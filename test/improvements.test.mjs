import assert from "node:assert/strict";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { createSigningKeys, signCompact } from "../src/crypto.mjs";
import { ErrorCode } from "../src/errors.mjs";
import { ReverseCaptchaService } from "../src/service.mjs";
import { JsonStore } from "../src/store.mjs";
import { createAgentIdentity, signChallenge, verifyAccessToken } from "../sdk/index.mjs";

async function fixture(options = {}) {
  const directory = await mkdtemp(join(tmpdir(), "reverse-captcha-"));
  const store = await new JsonStore(join(directory, "state.json")).load();
  const keys = createSigningKeys();
  const service = new ReverseCaptchaService({
    store,
    issuer: "https://issuer.test",
    ...keys,
    challengeTtlSeconds: 10,
    tokenTtlSeconds: 60,
    ...options,
  });
  return { service, keys };
}

async function registeredAgent(service, name = "Agent") {
  const identity = createAgentIdentity();
  const { agent } = await service.registerAgent({ name, public_key: identity.publicKey });
  return { identity, agent };
}

test("discovery advertises timing, algorithms, and scope support so agents need not guess", async () => {
  const { service } = await fixture({ challengeTtlSeconds: 45, tokenTtlSeconds: 900, leewaySeconds: 15 });
  const doc = service.discovery();
  assert.equal(doc.challenge_ttl_seconds, 45);
  assert.equal(doc.token_ttl_seconds, 900);
  assert.equal(doc.clock_skew_leeway_seconds, 15);
  assert.deepEqual(doc.algorithms_supported, ["EdDSA"]);
  assert.equal(doc.access_token_typ, "at+jwt");
  assert.equal(doc.scope_supported, true);
  assert.match(doc.registration_endpoint, /\/v1\/admin\/agents$/);
});

test("protocol failures carry stable machine-readable codes", async () => {
  const { service } = await fixture();
  const err = await service.createChallenge({ agent_id: "bot_missing", method: "GET", resource: "/x" }).catch((e) => e);
  assert.equal(err.code, ErrorCode.UNKNOWN_AGENT);
  assert.equal(err.status, 403);
  const body = err.toJSON();
  assert.equal(body.error, "request_rejected");
  assert.equal(body.code, "unknown_agent");
  assert.equal(body.retryable, false);
});

test("invalid resources and scopes are rejected with explicit codes", async () => {
  const { service } = await fixture();
  const { agent } = await registeredAgent(service);
  await assert.rejects(
    service.createChallenge({ agent_id: agent.id, method: "GET", resource: "no-leading-slash" }),
    (e) => e.code === ErrorCode.INVALID_RESOURCE,
  );
  await assert.rejects(
    service.createChallenge({ agent_id: agent.id, method: "GET", resource: "/../escape" }),
    (e) => e.code === ErrorCode.INVALID_RESOURCE,
  );
  await assert.rejects(
    service.createChallenge({ agent_id: agent.id, method: "GET", resource: "/ok", scope: "not-an-array" }),
    (e) => e.code === ErrorCode.INVALID_SCOPE,
  );
});

test("equivalent resources normalize to the same binding", async () => {
  const { service } = await fixture();
  const { identity, agent } = await registeredAgent(service);
  // Canonicalize with messy input; verify against the tidy form.
  const challenge = await service.createChallenge({ agent_id: agent.id, method: "GET", resource: "/v1//demo/./agent-only?utm=x" });
  const proof = signChallenge(challenge.canonical, identity.privateKey);
  const access = await service.verifyChallenge({ challenge_id: challenge.id, signature: proof });
  const claims = service.inspectAccessToken(access.access_token, { method: "GET", resource: "/v1/demo/agent-only" });
  assert.equal(claims.resource, "/v1/demo/agent-only");
});

test("clock-skew leeway keeps a just-expired token valid, then rejects it", async () => {
  const { service } = await fixture({ tokenTtlSeconds: 60, leewaySeconds: 30 });
  const { identity, agent } = await registeredAgent(service);
  const challenge = await service.createChallenge({ agent_id: agent.id, method: "GET", resource: "/p" });
  const access = await service.verifyChallenge({ challenge_id: challenge.id, signature: signChallenge(challenge.canonical, identity.privateKey) });
  const expiredAt = new Date(Date.now() + 10_000); // 10s past exp, inside 30s leeway
  const claims = service.inspectAccessToken(access.access_token, { now: expiredAt });
  assert.equal(claims.sub, agent.id);
  assert.throws(
    () => service.inspectAccessToken(access.access_token, { now: new Date(Date.now() + 200_000) }),
    (e) => e.code === ErrorCode.TOKEN_EXPIRED,
  );
});

test("a BOT PASSPORT cannot be replayed as an access token (typ enforcement)", async () => {
  const { service, keys } = await fixture();
  const { agent } = await registeredAgent(service);
  const passport = signCompact(
    { iss: "https://issuer.test", sub: agent.id, typ: "bot-passport", iat: Math.floor(Date.now() / 1000), exp: Math.floor(Date.now() / 1000) + 600 },
    keys.privateKey,
    { typ: "bot-passport+jwt", kid: service.keyId },
  );
  assert.throws(() => service.inspectAccessToken(passport, { method: "GET", resource: "/p" }), (e) => e.code === ErrorCode.TOKEN_TYPE_REJECTED);
  assert.throws(() => verifyAccessToken(passport, keys.publicKey, { issuer: "https://issuer.test" }), (e) => e.code === "token_type_rejected");
});

test("scoped tokens authorize every named resource and nothing else", async () => {
  const { service } = await fixture();
  const { identity, agent } = await registeredAgent(service);
  await service.activateTier(agent.id, "agent", { transaction: "0xtest", network: "eip155:8453" });
  const challenge = await service.createChallenge({
    agent_id: agent.id,
    method: "GET",
    resource: "/v1/a",
    scope: [
      { method: "GET", resource: "/v1/a" },
      { method: "POST", resource: "/v1/b" },
      { method: "GET", resource: "/v1/a" }, // duplicate collapses
    ],
  });
  const access = await service.verifyChallenge({ challenge_id: challenge.id, signature: signChallenge(challenge.canonical, identity.privateKey) });
  service.inspectAccessToken(access.access_token, { method: "GET", resource: "/v1/a" });
  service.inspectAccessToken(access.access_token, { method: "POST", resource: "/v1/b" });
  assert.throws(() => service.inspectAccessToken(access.access_token, { method: "GET", resource: "/v1/c" }), (e) => e.code === ErrorCode.TOKEN_RESOURCE_MISMATCH);
});

test("key rotation: tokens minted by a retired key still verify via JWKS kid lookup", async () => {
  const directory = await mkdtemp(join(tmpdir(), "reverse-captcha-"));
  const store = await new JsonStore(join(directory, "state.json")).load();
  const oldKeys = createSigningKeys();
  const newKeys = createSigningKeys();
  const service = new ReverseCaptchaService({
    store,
    issuer: "https://issuer.test",
    keys: [
      { kid: "key-2024", ...oldKeys, status: "retired", createdAt: "2024-01-01T00:00:00Z" },
      { kid: "key-2025", ...newKeys, status: "active", createdAt: "2025-01-01T00:00:00Z" },
    ],
  });
  assert.equal(service.keyId, "key-2025");
  const jwks = service.jwks();
  assert.equal(jwks.keys.length, 2);
  assert.deepEqual(jwks.keys.map((k) => k.kid).sort(), ["key-2024", "key-2025"]);
  // New tokens are minted by the active key and inspect cleanly.
  const { identity, agent } = await registeredAgent(service);
  const challenge = await service.createChallenge({ agent_id: agent.id, method: "GET", resource: "/p" });
  const access = await service.verifyChallenge({ challenge_id: challenge.id, signature: signChallenge(challenge.canonical, identity.privateKey) });
  const headerKid = JSON.parse(Buffer.from(access.access_token.split(".")[0], "base64url").toString()).kid;
  assert.equal(headerKid, "key-2025");
  service.inspectAccessToken(access.access_token, { method: "GET", resource: "/p" });
  // A token minted under the retired key still verifies via kid lookup.
  const oldToken = signCompact(
    { iss: "https://issuer.test", sub: agent.id, aud: "reverse-captcha-protected-service", method: "GET", resource: "/p", scope: "agent:access", iat: Math.floor(Date.now() / 1000), exp: Math.floor(Date.now() / 1000) + 300 },
    oldKeys.privateKey,
    { typ: "at+jwt", kid: "key-2024" },
  );
  const oldClaims = service.inspectAccessToken(oldToken, { method: "GET", resource: "/p" });
  assert.equal(oldClaims.sub, agent.id);
});

test("key revocation: a revoked key's tokens are refused, not re-verified against the active key", async () => {
  const directory = await mkdtemp(join(tmpdir(), "reverse-captcha-"));
  const store = await new JsonStore(join(directory, "state.json")).load();
  const oldKeys = createSigningKeys();
  const newKeys = createSigningKeys();
  const service = new ReverseCaptchaService({
    store,
    issuer: "https://issuer.test",
    keys: [
      { kid: "compromised", ...oldKeys, status: "revoked", createdAt: "2024-01-01T00:00:00Z" },
      { kid: "current", ...newKeys, status: "active", createdAt: "2025-01-01T00:00:00Z" },
    ],
  });
  // The revoked key is withheld from JWKS.
  assert.deepEqual(service.jwks().keys.map((k) => k.kid), ["current"]);
  const { agent } = await registeredAgent(service);
  const revokedToken = signCompact(
    { iss: "https://issuer.test", sub: agent.id, aud: "reverse-captcha-protected-service", method: "GET", resource: "/p", scope: "agent:access", iat: Math.floor(Date.now() / 1000), exp: Math.floor(Date.now() / 1000) + 300 },
    oldKeys.privateKey,
    { typ: "at+jwt", kid: "compromised" },
  );
  assert.throws(() => service.inspectAccessToken(revokedToken, { method: "GET", resource: "/p" }), (e) => e.code === ErrorCode.TOKEN_ISSUER_REJECTED);
});

test("an unknown kid is rejected instead of silently falling back to the active key", async () => {
  const { service, keys } = await fixture();
  const { agent } = await registeredAgent(service);
  const token = signCompact(
    { iss: "https://issuer.test", sub: agent.id, aud: "reverse-captcha-protected-service", method: "GET", resource: "/p", scope: "agent:access", iat: Math.floor(Date.now() / 1000), exp: Math.floor(Date.now() / 1000) + 300 },
    keys.privateKey,
    { typ: "at+jwt", kid: "attacker-chosen-kid" },
  );
  assert.throws(() => service.inspectAccessToken(token), (error) => error.code === ErrorCode.TOKEN_ISSUER_REJECTED);
});

test("SDK surfaces structured error codes instead of bare status text", async () => {
  const { service } = await fixture();
  const fetchImpl = async () => ({ ok: false, status: 403, json: async () => ({ error: "request_rejected", code: "unknown_agent", message: "Unknown or inactive agent", retryable: false }) });
  const { requestAgentAccess } = await import("../sdk/index.mjs");
  await assert.rejects(
    requestAgentAccess({ origin: "https://issuer.test", agentId: "bot_x", privateKey: "unused", resource: "/p", fetchImpl }),
    (e) => e.name === "ReverseCaptchaError" && e.code === "unknown_agent" && e.status === 403 && e.retryable === false,
  );
  void service;
});
