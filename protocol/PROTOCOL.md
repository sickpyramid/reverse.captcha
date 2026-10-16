# Reverse CAPTCHA Protocol v1

Reverse CAPTCHA is an open authorization protocol for agent-operated websites and APIs. It proves that a requester controls a private key belonging to an approved agent identity. It does **not** prove that the software is autonomous or that no human operates, directs, or supervises it.

## Objects

### Agent credential

An agent generates an Ed25519 key pair locally. The private key never goes to the issuer. An operator registers the public key and receives an opaque agent ID plus a signed BOT PASSPORT.

The BOT PASSPORT is a compact EdDSA JWS carrying `iss`, `sub`, `name`, `capabilities`, `status`, `iat`, and `typ=bot-passport`. It is an identity statement, not an access token.

### Challenge

The requester sends its agent ID, target HTTP method, and target resource. The issuer returns a random nonce, expiry, and the exact canonical value to sign:

```text
reverse-captcha/v1
<challenge_id>
<nonce>
<agent_id>
<HTTP_METHOD>
<resource>
<expires_at>
```

Challenges expire quickly and are single-use. Servers must compare the submitted proof with the registered Ed25519 public key.

### Access token

Successful proof returns a short-lived EdDSA JWS. The token is bound to the agent, issuer, audience, HTTP method, and exact resource. A protected service may verify it offline with the issuer public key.

## HTTP flow

1. `POST /v1/challenges` with `agent_id`, `method`, and `resource`.
2. Sign the returned `canonical` UTF-8 bytes using the agent private key.
3. `POST /v1/verify` with `challenge_id` and the base64url signature.
4. Send `Authorization: Bearer <access_token>` to the protected endpoint.

Discovery lives at `/.well-known/reverse-captcha`; issuer keys live at `/.well-known/jwks.json`.

### Discovery and timing

Agents should read the discovery document rather than hardcoding parameters. It advertises `challenge_ttl_seconds`, `token_ttl_seconds`, `clock_skew_leeway_seconds`, `algorithms_supported`, `access_token_typ`, `scope_supported`, and `registration_endpoint`.

Access tokens carry `typ=at+jwt` in the protected header. A BOT PASSPORT carries `typ=bot-passport+jwt` and is never accepted where an access token is expected; verifiers MUST check `typ` before trusting any claim.

### Resources and scopes

`resource` values are canonicalized before binding: duplicate slashes are collapsed, `.` and `..` segments are resolved, and query strings and fragments are stripped. Resources containing control characters, exceeding 512 characters, or escaping the root are rejected.

A challenge MAY request an optional `scope` array of `{ method, resource }` pairs. Scopes are an exact set — no wildcards or path prefixes. A scoped token authorizes every listed pair and nothing else. Without `scope`, the token binds a single method and resource exactly as before.

### Errors

Every refusal returns a machine-readable body:

```json
{ "error": "request_rejected", "code": "unknown_agent", "message": "Unknown or inactive agent", "retryable": false }
```

`code` is the stable reason (`unknown_agent`, `challenge_expired`, `signature_rejected`, `token_expired`, `token_type_rejected`, `rate_limited`, …). `error` is a coarse legacy bucket retained for older clients. `retryable` tells an agent whether the same call may succeed later; `429` responses also carry a `Retry-After` header. `401` responses carry a `WWW-Authenticate: Bearer` challenge that points back at the discovery document.

### Key rotation

The issuer may publish multiple signing keys in JWKS, each with a distinct `kid`. New tokens are minted by the active key; tokens signed by a retired but published key remain valid until expiry, so rotation does not invalidate in-flight tokens. A `revoked` key is withheld from JWKS and its tokens are refused at verification time.

### Rate limiting

`POST /v1/challenges` and `POST /v1/verify` are rate limited per client address. Exceeding the limit returns `429` with `code=rate_limited` and a `Retry-After` header.

## Security and privacy profile

- Use HTTPS in production.
- Keep agent private keys client-side; registration accepts public keys only.
- Require operator authorization for registration, status changes, and key rotation.
- Bind tokens to the exact HTTP method and resource; keep expiry short.
- Consume a challenge once even if a valid proof is replayed.
- Rotate issuer keys with overlapping `kid` publication in a later production release.
- This MVP stores only agent records, live challenges, and hourly aggregate counters. It intentionally does not retain IP addresses, user agents, request bodies, raw signatures, or individual access logs.
- Rate limiting should be enforced at the reverse proxy without persistent per-person analytics.
- Token ownership, wallets, and memecoin balances are outside the authorization protocol. A future token may support community features, but must never be required to authenticate an agent.

## Threat-model boundary

Reverse CAPTCHA can show that a request was signed by a key registered to an approved software identity. A human can run that software, instruct it, copy credentials from a compromised host, or operate an automated client. Therefore UI language must say **authorized agent identity verified**, never **human absence proven**.
