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
    if (!key) return this.activeKey;
    if (key.status === "revoked") return null;
    return key;
  }

  async registerAgent({ name, public_key, capabilities = [] }, now = new Date()) {
    if (!name || String(name).length > 80) throw reject(ErrorCode.INVALID_NAME, "A name up to 80 characters is required");
    try {
      createPublicKey(public_key);
    } catch (cause) {
      throw reject(ErrorCode.INVALID_PUBLIC_KEY, "public_key must be a valid PEM-encoded Ed25519 public key", { cause });
    }
    const agentId = `bot_${fingerprint(public_key)}`;
    const existing = this.store.state.agents[agentId];
    if (existing && existing.public_key !== public_key) throw reject(ErrorCode.IDENTITY_COLLISION, "Agent identity collision");
    const agent = {
      id: agentId,
      name: String(name),
      public_key,
      capabilities: Array.isArray(capabilities) ? capabilities.map(String).slice(0, 20) : [],
      status: "active",
      created_at: existing?.created_at ?? now.toISOString(),
      updated_at: now.toISOString(),
    };
    this.store.state.agents[agentId] = agent;
    const passport = this.issuePassport(agent, now);
    await this.store.persist();
    return { agent: this.publicAgent(agent), passport };
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
      iat,
    }, this.privateKey, { typ: "bot-passport+jwt", kid: this.keyId });
  }

  publicAgent(agent) {
    return {
      id: agent.id,
      name: agent.name,
      capabilities: agent.capabilities,
      status: agent.status,
      created_at: agent.created_at,
    };
  }

  async createChallenge({ agent_id, method, resource, scope }, now = new Date()) {
    const agent = this.store.state.agents[String(agent_id)];
    if (!agent || agent.status !== "active") {
      this.store.increment("rejected", now);
      await this.store.persist();
      throw reject(agent ? ErrorCode.AGENT_INACTIVE : ErrorCode.UNKNOWN_AGENT, "Unknown or inactive agent");
    }
    const challenge = {
      id: `ch_${randomId()}`,
      nonce: randomId(32),
      agent_id: agent.id,
      method: normalizeMethod(method),
      resource: normalizeResource(resource),
      // Optional exact-set scope. Empty when unused so the canonical string for
      // a plain single-resource challenge stays byte-for-byte identical to v0.1.
      scope: normalizeScope(scope),
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
    let valid = false;
    try {
      valid = verifyAgentSignature(canonicalChallenge(challenge), signature, agent.public_key);
    } catch {
      valid = false;
    }
    if (!valid) return rejectProof(ErrorCode.SIGNATURE_REJECTED, "Signature rejected");
    challenge.used_at = now.toISOString();
    const iat = Math.floor(now.getTime() / 1000);
    const expiresIn = this.tokenTtlSeconds;
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
    if (!key) throw reject(ErrorCode.TOKEN_ISSUER_REJECTED, "Token signing key has been revoked");
    const { payload } = verifyCompact(token, key.publicKey);
    const nowSeconds = Math.floor(now.getTime() / 1000);
    // Enforce token type: an access token must be `at+jwt`. This blocks a BOT
    // PASSPORT (typ=bot-passport+jwt) from ever being replayed as an access token.
    if (header.typ !== "at+jwt") throw reject(ErrorCode.TOKEN_TYPE_REJECTED, "Token type rejected");
    if (payload.iss !== this.issuer || payload.aud !== this.audience) throw reject(ErrorCode.TOKEN_ISSUER_REJECTED, "Token issuer or audience rejected");
    // Leeway tolerates modest clock skew between issuer and resource server.
    if (!payload.exp || payload.exp + this.leewaySeconds <= nowSeconds) throw reject(ErrorCode.TOKEN_EXPIRED, "Token expired");
    if (method && payload.method !== normalizeMethod(method)) throw reject(ErrorCode.TOKEN_METHOD_MISMATCH, "Token method mismatch");
    if (resource) {
      const wanted = normalizeResource(resource);
      const covered = Array.isArray(payload.scope) && payload.scope.includes(`${payload.method} ${wanted}`);
      if (payload.resource !== wanted && !covered) throw reject(ErrorCode.TOKEN_RESOURCE_MISMATCH, "Token resource mismatch");
    }
    const agent = this.store.state.agents[payload.sub];
    if (!agent || agent.status !== "active") throw reject(ErrorCode.AGENT_INACTIVE, "Agent is inactive");
    return payload;
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
      registration_endpoint: `${this.issuer}/v1/admin/agents`,
      registration_note: "Registration is operator-authorized: it requires the admin bearer token. Agents cannot self-register.",
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
