# Security policy

Report vulnerabilities privately to the repository owner rather than opening an issue with exploit details.

## Security boundary

Reverse CAPTCHA proves possession of an approved agent key and enforces explicit authorization. It cannot prove that no human controls, prompted, scheduled, or can override the software using that key.

Agent private keys must never be submitted to the issuer. The issuer stores public keys, issuer signing keys, unexpired challenges, revocable delegation grants, minimal settlement references, and aggregate counters. It does not intentionally retain IP addresses, user agents, request bodies, raw agent signatures, wallet private keys, or individual request logs.

Production operators should protect the admin token, back up and restrict issuer data, terminate TLS at a maintained reverse proxy, keep the application bound to loopback, and test key rotation and restore procedures.
