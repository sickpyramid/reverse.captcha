# Agent quickstart

## What this gives you

Reverse CAPTCHA lets a resource server answer one narrow question: **does this request control a registered Ed25519 agent key that has authority for this exact method and resource?** It does not determine whether a human instructed, operates, or can override the agent.

## Hosted issuer flow

1. Generate an Ed25519 identity locally with `createAgentIdentity()`.
2. Give only the public key to the issuer operator for registration.
3. Discover the issuer at `/.well-known/reverse-captcha`.
4. Request a one-time challenge for the target method and resource.
5. Sign the returned canonical string locally.
6. Exchange that proof for a short-lived access token.
7. Present the token to the protected API.

```js
import { createAgentIdentity, requestAgentAccess } from "./sdk/index.mjs";

const identity = createAgentIdentity();
// Persist identity.privateKey in your secret store. Register identity.publicKey.

const access = await requestAgentAccess({
  origin: "https://reversecaptcha.example.com",
  agentId: "bot_FROM_REGISTRATION",
  privateKey: identity.privateKey,
  method: "GET",
  resource: "/v1/demo/agent-only",
});

const response = await fetch("https://reversecaptcha.example.com/v1/demo/agent-only", {
  headers: { authorization: `Bearer ${access.access_token}` },
});
```

## Delegate to another agent

Delegation is available on Agent and Pro tiers. First obtain a parent token whose exact scope contains everything you intend to delegate. The delegate must already be registered.

```js
import { createDelegation, requestAgentAccess } from "./sdk/index.mjs";

const grant = await createDelegation({
  origin,
  accessToken: parentAccess.access_token,
  delegateAgentId: childAgentId,
  scope: [{ method: "GET", resource: "/jobs/42" }],
  expiresIn: 600,
});

const childAccess = await requestAgentAccess({
  origin,
  agentId: childAgentId,
  privateKey: childPrivateKey,
  method: "GET",
  resource: "/jobs/42",
  delegationId: grant.id,
});
```

The parent can call `revokeDelegation(...)`; all tokens carrying that delegation ID are then rejected by this issuer immediately.

## Adapting the code

The repository is MIT licensed. You can embed the SDK, use the hosted issuer, or self-host the whole service. Keep these invariants:

- private keys stay on agent hosts;
- challenges are short-lived and single use;
- access is bound to exact methods and normalized resources;
- delegated scope can only shrink;
- identity, payment, and human-control claims remain separate.
