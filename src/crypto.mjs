import {
  createHash,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  randomBytes,
  sign,
  timingSafeEqual,
  verify,
} from "node:crypto";

export const b64url = (value) => Buffer.from(value).toString("base64url");
export const fromB64url = (value) => Buffer.from(value, "base64url");

export function fingerprint(publicKeyPem) {
  const der = createPublicKey(publicKeyPem).export({ type: "spki", format: "der" });
  return createHash("sha256").update(der).digest("base64url").slice(0, 24);
}

export function createSigningKeys() {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  return {
    privateKey: privateKey.export({ type: "pkcs8", format: "pem" }),
    publicKey: publicKey.export({ type: "spki", format: "pem" }),
  };
}

export function signCompact(payload, privateKeyPem, header = {}) {
  const protectedHeader = b64url(JSON.stringify({ alg: "EdDSA", ...header }));
  const encodedPayload = b64url(JSON.stringify(payload));
  const input = `${protectedHeader}.${encodedPayload}`;
  const signature = sign(null, Buffer.from(input), createPrivateKey(privateKeyPem));
  return `${input}.${b64url(signature)}`;
}

// Decode only the protected header of a compact JWS WITHOUT verifying the
// signature. The result is untrusted input: callers must use it solely to select
// a verification key, then verify the full token before trusting any claim.
export function decodeHeader(token) {
  const [header] = String(token).split(".");
  if (!header) throw new Error("Malformed signed token");
  return JSON.parse(fromB64url(header).toString("utf8"));
}

export function verifyCompact(token, publicKeyPem) {
  const parts = String(token).split(".");
  if (parts.length !== 3) throw new Error("Malformed signed token");
  const [header, payload, signature] = parts;
  const ok = verify(
    null,
    Buffer.from(`${header}.${payload}`),
    createPublicKey(publicKeyPem),
    fromB64url(signature),
  );
  if (!ok) throw new Error("Invalid signed token");
  return {
    header: JSON.parse(fromB64url(header).toString("utf8")),
    payload: JSON.parse(fromB64url(payload).toString("utf8")),
  };
}

export function safeSecretEquals(left, right) {
  const a = Buffer.from(String(left ?? ""));
  const b = Buffer.from(String(right ?? ""));
  return a.length === b.length && timingSafeEqual(a, b);
}

export const randomId = (bytes = 18) => randomBytes(bytes).toString("base64url");

export function canonicalChallenge(challenge) {
  return [
    "reverse-captcha/v1",
    challenge.id,
    challenge.nonce,
    challenge.agent_id,
    challenge.method,
    challenge.resource,
    challenge.expires_at,
  ].join("\n");
}

export function verifyAgentSignature(message, signature, publicKeyPem) {
  return verify(
    null,
    Buffer.from(message),
    createPublicKey(publicKeyPem),
    fromB64url(signature),
  );
}
