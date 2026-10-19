import { createPublicKey } from "node:crypto";
import {
  canonicalChallenge,
  decodeHeader,
  fingerprint,
  randomId,
  signCompact,
  verifyAgentSignature,
  verifyCompact,
} from "./crypto.mjs";
import { ErrorCode, reject } from "./errors.mjs";
import { publicMetrics } from "./store.mjs";
import { publicTiers, tierFor } from "./tiers.mjs";

const normalizeMethod = (value) => {
  const method = String(value || "GET").toUpperCase();
  if (!/^[A-Z]+$/.test(method)) throw reject(ErrorCode.INVALID_METHOD, "Invalid HTTP method");
  return method;
};

// Canonicalize a resource so that cosmetically different paths map to one
// binding: collapse duplicate slashes, resolve `.`/`..`, and strip the query
// string and fragment. Rejects control characters and anything escaping root.
export function normalizeResource(value) {
  const raw = String(value ?? "/");
  if (raw.length > 512) throw reject(ErrorCode.INVALID_RESOURCE, "Invalid resource");
  if (/[\u0000-\u001f\u007f]/.test(raw)) throw reject(ErrorCode.INVALID_RESOURCE, "Invalid resource");
  const path = raw.split(/[?#]/, 1)[0];
  if (!path.startsWith("/")) throw reject(ErrorCode.INVALID_RESOURCE, "Invalid resource");
  const segments = [];
  for (const segment of path.split("/")) {
    if (segment === "" || segment === ".") continue;
    if (segment === "..") {
      if (segments.length === 0) throw reject(ErrorCode.INVALID_RESOURCE, "Invalid resource");
      segments.pop();
      continue;
    }
    segments.push(segment);
  }
  return `/${segments.join("/")}`;
}

// Normalize an optional exact-set scope into a sorted, de-duplicated list of
// "METHOD /resource" pairs. Rejects anything that is not an exact pair.
const MAX_SCOPE = 32;
export function normalizeScope(scope) {
  if (scope === undefined || scope === null) return [];
  if (!Array.isArray(scope)) throw reject(ErrorCode.INVALID_SCOPE, "scope must be an array of exact METHOD+resource pairs");
  if (scope.length > MAX_SCOPE) throw reject(ErrorCode.TOO_MANY_SCOPES, `scope is limited to ${MAX_SCOPE} entries`);
  const pairs = new Set();
  for (const entry of scope) {
    if (typeof entry !== "object" || entry === null) throw reject(ErrorCode.INVALID_SCOPE, "each scope entry must be an object with method and resource");
    const method = normalizeMethod(entry.method);
    const resource = normalizeResource(entry.resource);
    pairs.add(`${method} ${resource}`);
  }
  return [...pairs].sort();
}

// Build a verification keyring from either a legacy single key pair or an
// explicit rotation-aware array of keys. Exactly one key is `active` (used for
// signing); all keys can verify, so tokens minted before a rotation remain valid.
function buildKeyring({ privateKey, publicKey, keys }) {
  const list = [];
  if (Array.isArray(keys) && keys.length > 0) {
    for (const key of keys) list.push({ status: "active", createdAt: new Date(0).toISOString(), ...key, kid: key.kid ?? fingerprint(key.publicKey) });
  } else if (privateKey && publicKey) {
    list.push({ kid: fingerprint(publicKey), privateKey, publicKey, status: "active", createdAt: new Date(0).toISOString() });
  } else {
    throw new Error("ReverseCaptchaService requires either keys[] or a privateKey/publicKey pair");
  }
  const byKid = new Map(list.map((key) => [key.kid, key]));
  const active = list.filter((key) => key.status === "active").at(-1) ?? list.at(-1);
  return { keys: list, byKid, active };
}

export class ReverseCaptchaService {
  constructor({
    store,
    issuer,
    privateKey,
    publicKey,
    keys,
    challengeTtlSeconds = 30,
    tokenTtlSeconds = 300,
    leewaySeconds = 30,
    audience = "reverse-captcha-protected-service",
  }) {
    this.store = store;
    this.issuer = issuer;
    this.audience = audience;
    this.leewaySeconds = leewaySeconds;
    // Verification keyring: every key is publishable in JWKS and can verify.
    // `keys` (array of { kid, privateKey, publicKey, status, createdAt }) is the
    // rotation-aware form; a bare privateKey/publicKey pair becomes the active
    // key so existing single-key deployments keep working unchanged.
    this.keyring = buildKeyring({ privateKey, publicKey, keys });
    this.activeKey = this.keyring.active;
    this.privateKey = this.activeKey.privateKey;
    this.publicKey = this.activeKey.publicKey;
    this.keyId = this.activeKey.kid;
    this.challengeTtlSeconds = challengeTtlSeconds;
    this.tokenTtlSeconds = tokenTtlSeconds;
  }

  // Resolve the verification key for a token by its `kid`, falling back to the
  // active key for tokens minted before rotation was in use. A revoked key
  // resolves to null so its tokens are refused rather than silently re-verified
  // against the active key.
  keyFor(kid) {
    if (!kid) return this.activeKey;
    const key = this.keyring.byKid.get(kid);
    if (!key) return null;
    if (key.status === "revoked") return null;
    return key;
  }

  async registerAgent({ name, public_key, capabilities = [] }, now = new Date()) {
    const agentId = this.validateAgentRegistration({ name, public_key });
    const existing = this.store.state.agents[agentId];
    if (existing && existing.public_key !== public_key) throw reject(ErrorCode.IDENTITY_COLLISION, "Agent identity collision");
    const agent = {
      id: agentId,
      name: String(name),
      public_key,
      capabilities: Array.isArray(capabilities) ? capabilities.map(String).slice(0, 20) : [],
      tier: existing?.tier || "free",
      status: "active",
      created_at: existing?.created_at ?? now.toISOString(),
      updated_at: now.toISOString(),
    };
    this.store.state.agents[agentId] = agent;
    const passport = this.issuePassport(agent, now);
    await this.store.persist();
    return { agent: this.publicAgent(agent), passport };
  }

  validateAgentRegistration({ name, public_key }) {
    if (!name || String(name).length > 80) throw reject(ErrorCode.INVALID_NAME, "A name up to 80 characters is required");
    try {
      const key = createPublicKey(public_key);
      if (key.asymmetricKeyType !== "ed25519") throw new Error("Not an Ed25519 key");
    } catch (cause) {
      throw reject(ErrorCode.INVALID_PUBLIC_KEY, "public_key must be a valid PEM-encoded Ed25519 public key", { cause });
    }
    return `bot_${fingerprint(public_key)}`;
  }

  assertPaidRegistration(input) {
    const agentId = this.validateAgentRegistration(input);
    const existing = this.store.state.agents[agentId];
    if (existing && existing.tier !== "free") throw reject(ErrorCode.INVALID_TIER, "Agent is already registered on a paid tier");
    return agentId;
  }

  issuePassport(agent, now = new Date()) {
    const iat = Math.floor(now.getTime() / 1000);
    return signCompact({
      iss: this.issuer,
      sub: agent.id,
      typ: "bot-passport",
      name: agent.name,
      capabilities: agent.capabilities,
      status: agent.status,
      tier: agent.tier || "free",
      iat,
    }, this.privateKey, { typ: "bot-passport+jwt", kid: this.keyId });
  }

  publicAgent(agent) {
    return {
      id: agent.id,
      name: agent.name,
      capabilities: agent.capabilities,
      status: agent.status,
      tier: agent.tier || "free",
      created_at: agent.created_at,
    };
  }

  async createChallenge({ agent_id, method, resource, scope, delegation_id }, now = new Date()) {
    const agent = this.store.state.agents[String(agent_id)];
    if (!agent || agent.status !== "active") {
      this.store.increment("rejected", now);
      await this.store.persist();
      throw reject(agent ? ErrorCode.AGENT_INACTIVE : ErrorCode.UNKNOWN_AGENT, "Unknown or inactive agent");
    }
    const requestedScope = normalizeScope(scope);
    const tier = tierFor(agent.tier);
    if (requestedScope.length > tier.scope_limit) throw reject(ErrorCode.TOO_MANY_SCOPES, `${tier.id} tier is limited to ${tier.scope_limit} scope entries`);
    let delegation;
    if (delegation_id) {
      delegation = this.store.state.delegations[String(delegation_id)];
      if (!delegation || delegation.delegate_agent_id !== agent.id) throw reject(ErrorCode.UNKNOWN_DELEGATION, "Unknown delegation");
      if (delegation.revoked_at || Date.parse(delegation.expires_at) <= now.getTime()) throw reject(ErrorCode.DELEGATION_REVOKED, "Delegation is revoked or expired");
      const wanted = requestedScope.length ? requestedScope : [`${normalizeMethod(method)} ${normalizeResource(resource)}`];
      if (wanted.some((pair) => !delegation.scope.includes(pair))) throw reject(ErrorCode.DELEGATION_SCOPE_REJECTED, "Requested access exceeds delegated scope");
    }
    const challenge = {
      id: `ch_${randomId()}`,
      nonce: randomId(32),
      agent_id: agent.id,
      method: normalizeMethod(method),
      resource: normalizeResource(resource),
      // Optional exact-set scope. Empty when unused so the canonical string for
      // a plain single-resource challenge stays byte-for-byte identical to v0.1.
      scope: requestedScope,
      delegation_id: delegation?.id || null,
      created_at: now.toISOString(),
      expires_at: new Date(now.getTime() + this.challengeTtlSeconds * 1000).toISOString(),
      used_at: null,
    };
    this.store.state.challenges[challenge.id] = challenge;
    this.store.increment("challenges", now);
    this.store.prune(now.getTime());
    await this.store.persist();
    return { ...challenge, canonical: canonicalChallenge(challenge) };
  }

  async verifyChallenge({ challenge_id, signature }, now = new Date()) {
    const challenge = this.store.state.challenges[String(challenge_id)];
    const rejectProof = async (code, message) => {
      this.store.increment("rejected", now);
      await this.store.persist();
      throw reject(code, message);
    };
    if (!challenge) return rejectProof(ErrorCode.UNKNOWN_CHALLENGE, "Unknown challenge");
    if (challenge.used_at) return rejectProof(ErrorCode.CHALLENGE_ALREADY_USED, "Challenge already used");
    if (Date.parse(challenge.expires_at) < now.getTime()) return rejectProof(ErrorCode.CHALLENGE_EXPIRED, "Challenge expired");
    const agent = this.store.state.agents[challenge.agent_id];
    if (!agent || agent.status !== "active") return rejectProof(ErrorCode.AGENT_INACTIVE, "Agent is inactive");
    const delegation = challenge.delegation_id ? this.store.state.delegations[challenge.delegation_id] : null;
    if (challenge.delegation_id && (!delegation || delegation.revoked_at || Date.parse(delegation.expires_at) <= now.getTime())) {
      return rejectProof(ErrorCode.DELEGATION_REVOKED, "Delegation is revoked or expired");
    }
    let valid = false;
    try {
      valid = verifyAgentSignature(canonicalChallenge(challenge), signature, agent.public_key);
    } catch {
      valid = false;
    }
    if (!valid) return rejectProof(ErrorCode.SIGNATURE_REJECTED, "Signature rejected");
    challenge.used_at = now.toISOString();
    const iat = Math.floor(now.getTime() / 1000);
    const tier = tierFor(agent.tier);
    const delegationSeconds = delegation ? Math.max(1, Math.floor((Date.parse(delegation.expires_at) - now.getTime()) / 1000)) : Infinity;
    const expiresIn = Math.min(this.tokenTtlSeconds, tier.token_ttl_seconds, delegationSeconds);
    const token = signCompact({
      iss: this.issuer,
      sub: agent.id,
      aud: this.audience,
      method: challenge.method,
      resource: challenge.resource,
      // `scope` is the legacy OAuth-style marker when no extra resources are
      // requested; otherwise it becomes the exact-set of METHOD+resource pairs.
      ...(challenge.scope?.length
        ? { scope: challenge.scope, scope_type: "exact_set" }
        : { scope: "agent:access", scope_type: "single_resource" }),
      iat,
      exp: iat + expiresIn,
      jti: `at_${randomId(12)}`,
      tier: tier.id,
      ...(delegation ? { delegation_id: delegation.id, delegated_by: delegation.delegator_agent_id } : {}),
    }, this.activeKey.privateKey, { typ: "at+jwt", kid: this.activeKey.kid });
    this.store.increment("verified", now);
    this.store.increment("tokens_issued", now);
    await this.store.persist();
    return { access_token: token, token_type: "Bearer", expires_in: expiresIn };
  }

  inspectAccessToken(token, { method, resource, now = new Date() } = {}) {
    // Decode the header first (untrusted, signature not yet checked) to learn the
    // `kid`, then verify against exactly that key. This lets tokens minted before
    // a rotation stay valid while new ones use the active key. A revoked key
    // resolves to null and is refused outright.
    const header = decodeHeader(token);
    const key = this.keyFor(header?.kid);
    if (!key) throw reject(ErrorCode.TOKEN_ISSUER_REJECTED, "Token signing key is unknown or revoked");
    const { payload } = verifyCompact(token, key.publicKey);
    const nowSeconds = Math.floor(now.getTime() / 1000);
    // Enforce token type: an access token must be `at+jwt`. This blocks a BOT
    // PASSPORT (typ=bot-passport+jwt) from ever being replayed as an access token.
    if (header.typ !== "at+jwt") throw reject(ErrorCode.TOKEN_TYPE_REJECTED, "Token type rejected");
    if (payload.iss !== this.issuer) throw reject(ErrorCode.TOKEN_ISSUER_REJECTED, "Token issuer rejected");
    if (payload.aud !== this.audience) throw reject(ErrorCode.TOKEN_AUDIENCE_REJECTED, "Token audience rejected");
    // Leeway tolerates modest clock skew between issuer and resource server.
    if (!payload.exp || payload.exp + this.leewaySeconds <= nowSeconds) throw reject(ErrorCode.TOKEN_EXPIRED, "Token expired");
    if (method || resource) {
      const wantedMethod = normalizeMethod(method || payload.method);
      const wantedResource = normalizeResource(resource || payload.resource);
      const primary = payload.method === wantedMethod && payload.resource === wantedResource;
      const scoped = Array.isArray(payload.scope) && payload.scope.includes(`${wantedMethod} ${wantedResource}`);
      if (!primary && !scoped) {
        if (payload.resource === wantedResource) throw reject(ErrorCode.TOKEN_METHOD_MISMATCH, "Token method mismatch");
        throw reject(ErrorCode.TOKEN_RESOURCE_MISMATCH, "Token resource mismatch");
      }
    }
    const agent = this.store.state.agents[payload.sub];
    if (!agent || agent.status !== "active") throw reject(ErrorCode.AGENT_INACTIVE, "Agent is inactive");
    if (payload.delegation_id) {
      const delegation = this.store.state.delegations[payload.delegation_id];
      if (!delegation || delegation.revoked_at || Date.parse(delegation.expires_at) <= now.getTime()) throw reject(ErrorCode.DELEGATION_REVOKED, "Delegation is revoked or expired");
    }
    return payload;
  }

  async createDelegation(parentToken, { delegate_agent_id, scope, expires_in = 900 }, now = new Date()) {
    const parent = this.inspectAccessToken(parentToken, { now });
    const delegator = this.store.state.agents[parent.sub];
    const tier = tierFor(delegator.tier);
    if (!tier.active_delegation_limit) throw reject(ErrorCode.DELEGATION_NOT_ALLOWED, "Delegation requires a paid Agent or Pro tier");
    const delegate = this.store.state.agents[String(delegate_agent_id)];
    if (!delegate || delegate.status !== "active") throw reject(ErrorCode.UNKNOWN_AGENT, "Unknown or inactive delegate agent");
    const normalized = normalizeScope(scope);
    if (!normalized.length) throw reject(ErrorCode.INVALID_SCOPE, "Delegation requires at least one exact scope entry");
    const parentScope = new Set(Array.isArray(parent.scope) ? parent.scope : [`${parent.method} ${parent.resource}`]);
    if (normalized.some((pair) => !parentScope.has(pair))) throw reject(ErrorCode.DELEGATION_SCOPE_REJECTED, "Delegated scope must be a subset of the caller token");
    const active = Object.values(this.store.state.delegations).filter((item) => item.delegator_agent_id === parent.sub && !item.revoked_at && Date.parse(item.expires_at) > now.getTime());
    if (active.length >= tier.active_delegation_limit) throw reject(ErrorCode.DELEGATION_NOT_ALLOWED, `${tier.id} tier active delegation limit reached`);
    const seconds = Math.min(Math.max(60, Number(expires_in) || 900), 86_400, parent.exp - Math.floor(now.getTime() / 1000));
    if (seconds < 1) throw reject(ErrorCode.TOKEN_EXPIRED, "Parent token expires too soon to delegate");
    const delegation = {
      id: `dlg_${randomId(12)}`, delegator_agent_id: parent.sub, delegate_agent_id: delegate.id,
      scope: normalized, created_at: now.toISOString(), expires_at: new Date(now.getTime() + seconds * 1000).toISOString(), revoked_at: null,
    };
    this.store.state.delegations[delegation.id] = delegation;
    this.store.increment("delegations_created", now);
    await this.store.persist();
    return delegation;
  }

  async revokeDelegation(parentToken, delegationId, now = new Date()) {
    const parent = this.inspectAccessToken(parentToken, { now });
    const delegation = this.store.state.delegations[String(delegationId)];
    if (!delegation || delegation.delegator_agent_id !== parent.sub) throw reject(ErrorCode.UNKNOWN_DELEGATION, "Unknown delegation");
    delegation.revoked_at ||= now.toISOString();
    await this.store.persist();
    return { id: delegation.id, revoked_at: delegation.revoked_at };
  }

  async activateTier(agentId, tierId, payment, now = new Date()) {
    const agent = this.assertTierActivation(agentId, tierId);
    const tier = tierFor(tierId);
    agent.tier = tier.id;
    agent.updated_at = now.toISOString();
    const paymentId = `pay_${randomId(12)}`;
    this.store.state.payments[paymentId] = { id: paymentId, agent_id: agent.id, tier: tier.id, transaction: payment.transaction, network: payment.network, created_at: now.toISOString() };
    this.store.increment("paid_tier_activations", now);
    await this.store.persist();
    return { agent_id: agent.id, tier: tier.id, status: "active", passport: this.issuePassport(agent, now), payment: { transaction: payment.transaction, network: payment.network } };
  }

  assertTierActivation(agentId, tierId) {
    const tier = tierFor(tierId);
    if (!tier?.paid) throw reject(ErrorCode.INVALID_TIER, "Only Agent and Pro are paid tiers");
    const agent = this.store.state.agents[String(agentId)];
    if (!agent || agent.status !== "active") throw reject(ErrorCode.UNKNOWN_AGENT, "Unknown or inactive agent");
    const rank = { free: 0, agent: 1, pro: 2 };
    if (rank[agent.tier || "free"] >= rank[tier.id]) throw reject(ErrorCode.INVALID_TIER, `Agent already has ${agent.tier || "free"} tier or higher`);
    return agent;
  }

  metrics(now = new Date()) {
    return publicMetrics(this.store.state, now.getTime());
  }

  dashboard(now = new Date()) {
    const cutoff = now.getTime() - 24 * 3_600_000;
    const hourly = Object.entries(this.store.state.metrics)
      .filter(([hour]) => Date.parse(hour) >= cutoff)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([hour, counts]) => ({ hour, ...counts }));
    return {
      generated_at: now.toISOString(),
      summary: this.metrics(now),
      agents: Object.values(this.store.state.agents).map((agent) => this.publicAgent(agent)),
      active_delegations: Object.values(this.store.state.delegations).filter((item) => !item.revoked_at && Date.parse(item.expires_at) > now.getTime()).length,
      hourly,
      retained_data: ["agent identity records", "unexpired challenges", "hourly aggregate counters for 30 days"],
      excluded_data: ["IP addresses", "user agents", "request bodies", "raw signatures", "individual access logs"],
    };
  }

  discovery() {
    return {
      issuer: this.issuer,
      protocol: "reverse-captcha/v1",
      challenge_endpoint: `${this.issuer}/v1/challenges`,
      verification_endpoint: `${this.issuer}/v1/verify`,
      delegation_endpoint: `${this.issuer}/v1/delegations`,
      tiers_endpoint: `${this.issuer}/v1/tiers`,
      jwks_uri: `${this.issuer}/.well-known/jwks.json`,
      passport_type: "bot-passport+jwt",
      // Agent-discoverable timing and algorithm parameters. These were previously
      // only knowable by reading the source.
      challenge_ttl_seconds: this.challengeTtlSeconds,
      token_ttl_seconds: this.tokenTtlSeconds,
      clock_skew_leeway_seconds: this.leewaySeconds,
      algorithms_supported: ["EdDSA"],
      curves_supported: ["Ed25519"],
      access_token_typ: "at+jwt",
      passport_typ: "bot-passport+jwt",
      scope_supported: true,
      scope_mode: "exact",
      scope_limit: "Scopes are exact METHOD+resource pairs. Wildcards and path prefixes are not honored.",
      tiers: publicTiers(),
      registration_endpoint: `${this.issuer}/v1/admin/agents`,
      paid_registration_endpoint: `${this.issuer}/v1/paid/register`,
      registration_note: "Operator-approved registration uses the admin endpoint. Public self-registration is available through the x402-paid endpoint.",
      claim_limit: "Authorization proves control of a registered agent key. It does not prove the absence of human direction or control.",
    };
  }

  // Publish the whole keyring so verifiers can resolve any active or retiring
  // key by `kid`. Retired keys stay published because tokens they minted are
  // still valid until they expire; only revoked keys are withheld, and their
  // already-issued tokens are refused at inspection time.
  jwks() {
    const keys = this.keyring.keys
      .filter((key) => key.status !== "revoked")
      .map((key) => ({
        ...createPublicKey(key.publicKey).export({ format: "jwk" }),
        use: "sig",
        alg: "EdDSA",
        kid: key.kid,
        status: key.status,
      }));
    return { keys };
  }
}
