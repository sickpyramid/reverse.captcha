import assert from "node:assert/strict";
import { mkdtemp, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { createSigningKeys } from "../src/crypto.mjs";
import { ReverseCaptchaService } from "../src/service.mjs";
import { JsonStore } from "../src/store.mjs";
import { createAgentIdentity, signChallenge, verifyAccessToken } from "../sdk/index.mjs";

async function fixture() {
  const directory = await mkdtemp(join(tmpdir(), "reverse-captcha-"));
  const store = await new JsonStore(join(directory, "state.json")).load();
  const keys = createSigningKeys();
  const service = new ReverseCaptchaService({ store, issuer: "https://issuer.test", ...keys, challengeTtlSeconds: 10, tokenTtlSeconds: 60 });
  return { service, keys };
}

test("registered agent completes challenge and receives resource-bound token", async () => {
  const { service, keys } = await fixture();
  const identity = createAgentIdentity();
  const registered = await service.registerAgent({ name: "Test Agent", public_key: identity.publicKey, capabilities: ["research"] });
  assert.match(registered.agent.id, /^bot_/);
  assert.equal(registered.passport.split(".").length, 3);
  const challenge = await service.createChallenge({ agent_id: registered.agent.id, method: "GET", resource: "/private" });
  const proof = signChallenge(challenge.canonical, identity.privateKey);
  const access = await service.verifyChallenge({ challenge_id: challenge.id, signature: proof });
  const claims = verifyAccessToken(access.access_token, keys.publicKey, { issuer: "https://issuer.test", method: "GET", resource: "/private" });
  assert.equal(claims.sub, registered.agent.id);
  assert.throws(() => service.inspectAccessToken(access.access_token, { method: "POST", resource: "/private" }), /method mismatch/i);
});

test("challenges are one-time and invalid signatures are rejected", async () => {
  const { service } = await fixture();
  const identity = createAgentIdentity();
  const stranger = createAgentIdentity();
  const { agent } = await service.registerAgent({ name: "One Shot", public_key: identity.publicKey });
  const challenge = await service.createChallenge({ agent_id: agent.id, method: "POST", resource: "/jobs" });
  await assert.rejects(service.verifyChallenge({ challenge_id: challenge.id, signature: signChallenge(challenge.canonical, stranger.privateKey) }), /rejected/i);
  await service.verifyChallenge({ challenge_id: challenge.id, signature: signChallenge(challenge.canonical, identity.privateKey) });
  await assert.rejects(service.verifyChallenge({ challenge_id: challenge.id, signature: signChallenge(challenge.canonical, identity.privateKey) }), /already used/i);
});

test("public metrics contain aggregates and an explicit privacy statement", async () => {
  const { service } = await fixture();
  const metrics = service.metrics();
  assert.deepEqual(Object.keys(metrics.totals), ["challenges", "verified", "rejected", "tokens_issued"]);
  assert.match(metrics.privacy, /No IP addresses/);
  assert.equal(JSON.stringify(metrics).includes("user_agent"), false);
});

test("public experience presents the reverse checkbox, real proof flow, and human fallback", async () => {
  const html = await readFile(new URL("../public/index.html", import.meta.url), "utf8");
  const script = await readFile(new URL("../public/app.js", import.meta.url), "utf8");
  assert.match(html, /I'm a BOT/);
  assert.match(html, /ED25519 SIGNATURE/);
  assert.match(html, /PROCEED IN HUMAN MODE/);
  assert.match(script, /\/v1\/challenges/);
  assert.match(script, /\/v1\/verify/);
  assert.match(script, /OPEN PUBLIC SITE ANYWAY/);
});
