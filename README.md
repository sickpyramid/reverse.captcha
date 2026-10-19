# reverse.captcha

> Humans spent decades asking computers to prove they were human. We reversed it.

**reverse.captcha** is an open authorization protocol and lightweight hosted service for agent-only websites and APIs. A visitor gets the fun **“I’m a BOT”** experience; a real integration uses Ed25519 keys, one-time challenges, exact permissions, short-lived access tokens, and revocable agent-to-agent delegation.

**Honest boundary:** reverse.captcha proves that a requester controls a registered agent credential. It cannot prove that the software has no human operator, prompt, owner, or override.

## Reverse Agent API

**Reverse Agent API by reverse.captcha** is the umbrella for pay-per-use security and web utilities designed for autonomous agents. The first production services accept USDC on Base through x402:

| Service | Endpoint | Live price | Result |
|---|---|---:|---|
| Agent Identity & Access | `POST /v1/paid/register` | $0.01 | Registered Ed25519 identity, Agent tier, and signed BOT PASSPORT |
| Web Evidence Snapshot | `POST /v1/paid/evidence` | $0.03 | Bounded HTTPS snapshot with SHA-256, metadata, redirects, and text excerpt |
| Source Freshness Check | `POST /v1/paid/freshness` | $0.01 | Fresh/stale/unknown assessment against a requested age, with observed date evidence |

Browse the machine-readable catalog at `GET /v1/services`, the x402 discovery document at `GET /.well-known/x402`, and the OpenAPI description at `GET /openapi.json`.

Payments grant access to the service; they do not prove autonomous operation, truth, authorship, or the absence of human control. Self-hosting remains open-source and does not require payment or token ownership.

## Why it has real utility

- Protect API routes for approved agents without shipping shared API secrets.
- Give each agent a stable public-key identity and signed BOT PASSPORT.
- Bind access to an exact HTTP method and normalized resource.
- Let one agent authorize another agent without sharing its private key or master token.
- Revoke a delegation and invalidate delegated tokens immediately at the issuer.
- Verify signed access tokens locally using the issuer JWKS.
- Offer optional paid hosted tiers through x402 v2 while keeping identity separate from payment.
- Publish aggregate service health without retaining visitor IPs, user agents, raw signatures, or access logs.

## Five-minute local demo

Requires Node.js 22 or newer. There are no runtime npm dependencies.

```powershell
git clone https://github.com/sickpyramid/reverse.captcha.git
cd reverse.captcha
Copy-Item .env.example .env
$env:ADMIN_TOKEN = "replace-with-a-long-random-development-secret"
$env:PUBLIC_ORIGIN = "http://127.0.0.1:4408"
npm test
npm start
```

Open `http://127.0.0.1:4408`. The homepage opens directly and embeds a live **I'm a BOT** Reverse CAPTCHA demo. Humans can explore every step, but the protected demo API only unlocks after a registered agent signs the one-time challenge.

## How agent authorization works

1. The agent generates an Ed25519 key pair locally.
2. An operator registers only its public key.
3. The agent requests a one-time challenge bound to a method and resource.
4. The agent signs the exact canonical challenge.
5. The issuer verifies the proof and returns a short-lived `at+jwt` access token.
6. The protected service validates the signature, issuer, audience, expiry, identity status, method, and resource.

```js
import { createAgentIdentity, requestAgentAccess } from "./sdk/index.mjs";

const identity = createAgentIdentity(); // keep privateKey on the agent host

// The operator registers identity.publicKey once and returns agent.id.
const access = await requestAgentAccess({
  origin: "https://reversecaptcha.example.com",
  agentId: "bot_...",
  privateKey: identity.privateKey,
  method: "GET",
  resource: "/v1/demo/agent-only",
});

const response = await fetch("https://reversecaptcha.example.com/v1/demo/agent-only", {
  headers: { authorization: `Bearer ${access.access_token}` },
});
```

See [Agent quickstart](docs/AGENT_QUICKSTART.md) for registration, delegation, revocation, and adaptation examples.

## Agent-to-agent delegation

A paid Agent or Pro identity can create a short-lived delegation whose exact scope is a subset of its own token. The delegate then signs a fresh challenge with the delegate’s own registered key. This preserves attribution and avoids handing a child agent the parent’s private key or bearer token.

```js
import { createDelegation, requestAgentAccess } from "./sdk/index.mjs";

const grant = await createDelegation({
  origin,
  accessToken: parentToken,
  delegateAgentId: "bot_child...",
  scope: [{ method: "GET", resource: "/jobs/42" }],
  expiresIn: 600,
});

const childAccess = await requestAgentAccess({
  origin,
  agentId: "bot_child...",
  privateKey: childPrivateKey,
  method: "GET",
  resource: "/jobs/42",
  delegationId: grant.id,
});
```

## Tiers and x402

| Tier | Exact scopes/token | Active delegations | Token TTL ceiling |
|---|---:|---:|---:|
| Free | 1 | 0 | 5 min |
| Agent | 8 | 5 | 15 min |
| Pro | 32 | 50 | 30 min |

Paid hosted tiers use x402 v2: HTTP 402, canonical `PAYMENT-REQUIRED`, client `PAYMENT-SIGNATURE`, facilitator verification and settlement, and Bazaar discovery metadata. Payment is disabled by default until the operator supplies a reviewed facilitator, CAIP-2 network, asset, receiving wallet, and atomic-unit prices. Self-hosting remains MIT licensed and is never token-gated.

The hosted deployment also exposes **Agent Identity & Access for $0.01** and **Web Evidence Snapshot for $0.03**. Prices are atomic USDC amounts in the live x402 discovery metadata. Marketplace visibility and successful settlement are operational checks separate from code readiness.

See [x402 configuration and readiness](docs/X402.md). The repository is code-ready for configuration, but a live Bazaar listing is **not** complete until real payment settings and an end-to-end settlement are verified.

## HTTP surface

| Endpoint | Purpose |
|---|---|
| `GET /.well-known/reverse-captcha` | Machine-readable protocol discovery |
| `GET /.well-known/x402` | x402 paid-resource discovery |
| `GET /v1/services` | Reverse Agent API service catalog |
| `GET /openapi.json` | Marketplace-ready OpenAPI description |
| `GET /.well-known/jwks.json` | Issuer verification keys |
| `POST /v1/admin/agents` | Operator-authorized public-key registration |
| `POST /v1/challenges` | Create a one-time agent proof challenge |
| `POST /v1/verify` | Verify proof and mint an access token |
| `POST /v1/delegations` | Create a narrowed, expiring delegation |
| `POST /v1/delegations/:id/revoke` | Revoke a delegation |
| `GET /v1/tiers` | Read tier limits and payment availability |
| `POST /v1/paid/tiers/:tier` | x402-paid hosted tier activation |
| `POST /v1/paid/register` | x402-paid identity registration and BOT PASSPORT |
| `POST /v1/paid/evidence` | x402-paid privacy-safe web evidence snapshot |
| `POST /v1/paid/freshness` | x402-paid source freshness assessment |
| `GET /v1/metrics/public` | Privacy-safe rolling aggregates |
| `GET /v1/admin/dashboard` | Private operator dashboard data |

The full wire contract is in [protocol/PROTOCOL.md](protocol/PROTOCOL.md) and [protocol/openapi.yaml](protocol/openapi.yaml).

## Self-hosting

Docker Compose is included. The service binds to `127.0.0.1:4408` by default and expects TLS from your reverse proxy. Copy `.env.example` to `.env`, set a strong `ADMIN_TOKEN` and `PUBLIC_ORIGIN`, then run `docker compose up -d --build` from `deploy/`.

Keep x402 disabled until its payment settings are verified. Never store agent private keys, wallet private keys, or seed phrases in this service.

## Privacy and security

The built-in rate limiter is process-wide and retains no IP address. Public metrics are hourly aggregates. The store retains agent public identities, short-lived challenges, revocable delegation grants, minimal settlement references, and 30 days of aggregate counters. See [SECURITY.md](SECURITY.md) for the boundary and reporting guidance.

## Development

```powershell
npm test
npm run check
```

CI runs both commands on Node 22. Contributions must preserve exact scope matching, one-time challenges, delegate key proof, immediate delegation revocation, and the separation between identity, human control, and payment.

## License

MIT. Use the hosted issuer, embed the SDK, or adapt and self-host the protocol.
