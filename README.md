# BOT ONLY / Reverse CAPTCHA

A lightweight open protocol and optional hosted issuer for agent-only websites and APIs.

Reverse CAPTCHA verifies control of an approved Ed25519 agent credential. It does not and cannot prove that a human is absent from the control loop.

## MVP contents

- Ed25519 agent identities and signed BOT PASSPORTS
- One-time, short-lived challenge-response bound to HTTP method and resource
- Short-lived EdDSA access tokens with offline verification
- Dependency-free JavaScript client and Express-compatible middleware
- Issuer discovery and JWKS endpoints
- Public humorous reverse-CAPTCHA page with live aggregate metrics
- Visitor-facing Reverse CAPTCHA scan that demonstrates BOT PASSPORT failure, then allows entry to the public site in clearly labeled human mode
- Private developer console showing approved BOT PASSPORT identities, aggregate issuer activity, and the privacy contract
- Admin-authorized registration endpoint
- Privacy-safe hourly counters; no IP, user-agent, request-body, or raw-signature retention
- Hardened loopback-only Docker Compose deployment for a shared VPS

Token ownership is deliberately separate and optional. Wallets and balances are not part of authentication.

## Run locally

Requires Node.js 22 or newer.

```powershell
$env:ADMIN_TOKEN = "replace-with-a-long-random-development-secret"
$env:PUBLIC_ORIGIN = "http://127.0.0.1:4408"
node src/server.mjs
```

Then open `http://127.0.0.1:4408` and check `http://127.0.0.1:4408/healthz`.

## Register and call from an agent

Generate the key pair on the agent machine using `createAgentIdentity()` from `sdk/index.mjs`. Submit only its `publicKey` to the operator-protected registration endpoint:

```js
import { createAgentIdentity, requestAgentAccess } from "./sdk/index.mjs";

const identity = createAgentIdentity(); // store privateKey securely on the agent host

// Operator registers identity.publicKey once and returns agent.id.
const access = await requestAgentAccess({
  origin: "https://reversecaptcha.example.com",
  agentId: "bot_...",
  privateKey: identity.privateKey,
  method: "GET",
  resource: "/v1/demo/agent-only"
});

const response = await fetch("https://reversecaptcha.example.com/v1/demo/agent-only", {
  headers: { authorization: `Bearer ${access.access_token}` }
});
```

See `protocol/PROTOCOL.md` for the wire format and security boundary, and `protocol/openapi.yaml` for the HTTP surface.

## Safe Singapore VPS deployment

Do not deploy until the current host is audited. Re-check running containers, Compose projects, public listeners, available memory/disk, and the active Caddy configuration. Pick an unused loopback port and verify existing sites both before and after deployment.

The supplied Compose file expects `/opt/reverse-captcha` and binds only `127.0.0.1:4408`. Create `deploy/.env` from `.env.example` using a random admin token, create `deploy/data` owned by container UID 1000, then build and start only this Compose project.

Add a dedicated domain route based on `deploy/Caddyfile.example`, validate the complete active Caddy configuration with a disposable validator container, back up the active file, then reload without restarting unrelated containers. Confirm:

- container health and zero unexpected restarts;
- local `/healthz`, discovery, JWKS, and public metrics;
- public apex HTTPS, `www` redirect, security headers, and assets;
- every pre-existing production domain still returns its prior healthy response.

Issuer keys and state live only in `deploy/data`. Back that directory up with restrictive permissions. Never place agent private keys there.

## Current limitations before broader production use

- Registration is operator-controlled but has no multi-user dashboard or audit workflow yet.
- Issuer key rotation and revocation propagation need a versioned key lifecycle.
- Horizontal replicas need a transactional shared challenge store.
- Edge rate limiting must be configured in Caddy or an upstream service.
- Exact-resource binding is intentionally strict; wildcard policy should be designed explicitly, not inferred.
