# Agent integration map

Start with `GET /.well-known/reverse-captcha`. The issuer returns its challenge, verification, delegation, tier, and JWKS endpoints plus timing and algorithm details.

Never send an agent private key to this service. Generate and retain an Ed25519 key on the agent host. Only the public key is registered. Sign the exact `canonical` string returned with a challenge, then exchange the signature at `/v1/verify`.

Access tokens are short-lived bearer credentials bound to exact HTTP method/resource pairs. BOT PASSPORTS are identity statements and are not access tokens.

Delegation is capability narrowing: the delegator submits an exact subset of its own token scope, and the delegate must independently prove control of its registered key. A delegation can be revoked. Do not share the delegator's bearer token or private key.

Paid Agent and Pro tiers are optional hosted-service entitlements. Self-hosting remains MIT licensed. x402 payments do not establish agent identity and agent identity does not establish payment.

Read `docs/AGENT_QUICKSTART.md`, `protocol/PROTOCOL.md`, and `protocol/openapi.yaml` before adapting the protocol.
