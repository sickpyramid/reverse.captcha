import assert from "node:assert/strict";
import { createAgentIdentity, requestAgentAccess } from "../sdk/index.mjs";

const origin = process.env.PUBLIC_ORIGIN || "http://127.0.0.1:4408";
const adminToken = process.env.ADMIN_TOKEN;
if (!adminToken) throw new Error("ADMIN_TOKEN is required");

const healthResponse = await fetch(`${origin}/healthz`);
assert.equal(healthResponse.status, 200);

const identity = createAgentIdentity();
const registrationResponse = await fetch(`${origin}/v1/admin/agents`, {
  method: "POST",
  headers: { authorization: `Bearer ${adminToken}`, "content-type": "application/json" },
  body: JSON.stringify({ name: "Local Validation Agent", public_key: identity.publicKey, capabilities: ["self-test"] }),
});
assert.equal(registrationResponse.status, 201);
const registration = await registrationResponse.json();
assert.match(registration.agent.id, /^bot_/);
assert.equal(registration.passport.split(".").length, 3);

const access = await requestAgentAccess({
  origin,
  agentId: registration.agent.id,
  privateKey: identity.privateKey,
  method: "GET",
  resource: "/v1/demo/agent-only",
});
const protectedResponse = await fetch(`${origin}/v1/demo/agent-only`, {
  headers: { authorization: `Bearer ${access.access_token}` },
});
assert.equal(protectedResponse.status, 200);
const protectedBody = await protectedResponse.json();
assert.equal(protectedBody.access, "GRANTED");

const pageResponse = await fetch(origin);
assert.equal(pageResponse.status, 200);
const page = await pageResponse.text();
assert.match(page, /I'm a BOT/);
assert.match(page, /ED25519 SIGNATURE/);
assert.match(page, /PROCEED IN HUMAN MODE/);

const metricsResponse = await fetch(`${origin}/v1/metrics/public`);
const metrics = await metricsResponse.json();
assert.ok(metrics.totals.verified >= 1);

console.log(JSON.stringify({
  health: "ok",
  agent_id: registration.agent.id,
  passport: "signed",
  protected_access: protectedBody.access,
  privacy_metrics: metrics.privacy,
}, null, 2));
