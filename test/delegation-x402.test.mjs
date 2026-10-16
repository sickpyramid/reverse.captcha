import assert from "node:assert/strict";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { createSigningKeys } from "../src/crypto.mjs";
import { ReverseCaptchaService } from "../src/service.mjs";
import { JsonStore } from "../src/store.mjs";
import { X402Payments } from "../src/x402.mjs";
import { createAgentIdentity, signChallenge } from "../sdk/index.mjs";

async function setup() {
  const directory = await mkdtemp(join(tmpdir(), "reverse-captcha-delegation-"));
  const store = await new JsonStore(join(directory, "state.json")).load();
  const service = new ReverseCaptchaService({ store, issuer: "https://issuer.test", ...createSigningKeys(), tokenTtlSeconds: 900 });
  const parentIdentity = createAgentIdentity();
  const childIdentity = createAgentIdentity();
  const parent = (await service.registerAgent({ name: "Parent", public_key: parentIdentity.publicKey })).agent;
  const child = (await service.registerAgent({ name: "Child", public_key: childIdentity.publicKey })).agent;
  return { service, parentIdentity, childIdentity, parent, child };
}

test("a paid agent delegates only a subset and the delegate proves its own key", async () => {
  const { service, parentIdentity, childIdentity, parent, child } = await setup();
  await service.activateTier(parent.id, "agent", { transaction: "0xtest", network: "eip155:8453" });
  const parentChallenge = await service.createChallenge({ agent_id: parent.id, method: "GET", resource: "/jobs", scope: [{ method: "GET", resource: "/jobs" }, { method: "POST", resource: "/results" }] });
  const parentAccess = await service.verifyChallenge({ challenge_id: parentChallenge.id, signature: signChallenge(parentChallenge.canonical, parentIdentity.privateKey) });
  const grant = await service.createDelegation(parentAccess.access_token, { delegate_agent_id: child.id, scope: [{ method: "GET", resource: "/jobs" }] });
  const childChallenge = await service.createChallenge({ agent_id: child.id, method: "GET", resource: "/jobs", delegation_id: grant.id });
  const childAccess = await service.verifyChallenge({ challenge_id: childChallenge.id, signature: signChallenge(childChallenge.canonical, childIdentity.privateKey) });
  const claims = service.inspectAccessToken(childAccess.access_token, { method: "GET", resource: "/jobs" });
  assert.equal(claims.sub, child.id);
  assert.equal(claims.delegated_by, parent.id);
  await service.revokeDelegation(parentAccess.access_token, grant.id);
  assert.throws(() => service.inspectAccessToken(childAccess.access_token), (error) => error.code === "delegation_revoked");
});

test("free agents cannot delegate and a parent cannot expand authority", async () => {
  const { service, parentIdentity, parent, child } = await setup();
  const challenge = await service.createChallenge({ agent_id: parent.id, method: "GET", resource: "/one" });
  const access = await service.verifyChallenge({ challenge_id: challenge.id, signature: signChallenge(challenge.canonical, parentIdentity.privateKey) });
  await assert.rejects(service.createDelegation(access.access_token, { delegate_agent_id: child.id, scope: [{ method: "GET", resource: "/one" }] }), (error) => error.code === "delegation_not_allowed");
  await service.activateTier(parent.id, "agent", { transaction: "0xtest", network: "eip155:8453" });
  await assert.rejects(service.createDelegation(access.access_token, { delegate_agent_id: child.id, scope: [{ method: "POST", resource: "/two" }] }), (error) => error.code === "delegation_scope_rejected");
});

test("x402 v2 advertises Bazaar metadata and verifies then settles", async () => {
  const calls = [];
  const fetchImpl = async (url) => {
    calls.push(url);
    const settled = url.endsWith("/settle");
    return { ok: true, headers: { get: () => null }, json: async () => settled ? { success: true, transaction: "0xabc", network: "eip155:8453" } : { isValid: true, payer: "0xpayer" } };
  };
  const payments = new X402Payments({ enabled: true, facilitatorUrl: "https://facilitator.test", network: "eip155:8453", asset: "0xasset", payTo: "0xmerchant", prices: { agent: "10000" }, fetchImpl });
  const requirement = payments.requirement({ tier: "agent", url: "https://issuer.test/v1/paid/tiers/agent" });
  assert.equal(requirement.paymentRequired.x402Version, 2);
  assert.equal(requirement.paymentRequired.extensions.bazaar.info.input.type, "http");
  const payload = { x402Version: 2, accepted: requirement.paymentRequirements, payload: { signature: "0xproof" } };
  const result = await payments.authorize({ tier: "agent", url: "https://issuer.test/v1/paid/tiers/agent", paymentSignature: Buffer.from(JSON.stringify(payload)).toString("base64") });
  assert.equal(result.success, true);
  assert.deepEqual(calls, ["https://facilitator.test/verify", "https://facilitator.test/settle"]);
});
