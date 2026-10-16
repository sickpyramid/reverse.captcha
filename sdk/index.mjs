import { createPrivateKey, createPublicKey, generateKeyPairSync, sign, verify } from "node:crypto";

const b64url = (value) => Buffer.from(value).toString("base64url");
const fromB64url = (value) => Buffer.from(value, "base64url");

// Raised for any protocol refusal. Carries the machine-readable `code`, the
// HTTP `status`, and `retryable` so an agent can branch without parsing prose.
export class ReverseCaptchaError extends Error {
  constructor(message, { code = "unknown_error", status = 0, retryable = false, details } = {}) {
    super(message);
    this.name = "ReverseCaptchaError";
    this.code = code;
    this.status = status;
    this.retryable = retryable;
    this.details = details;
  }
}

// Turn a non-2xx protocol response into a typed error. Prefers the server's
// structured body over the generic status text.
async function toProtocolError(response, fallback) {
  let body;
  try {
    body = await response.json();
  } catch {
    body = undefined;
  }
  return new ReverseCaptchaError(body?.message || fallback, {
    code: body?.code || `http_${response.status}`,
    status: response.status,
    retryable: Boolean(body?.retryable),
    details: body?.details,
  });
}

export function createAgentIdentity() {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  return {
    privateKey: privateKey.export({ type: "pkcs8", format: "pem" }),
    publicKey: publicKey.export({ type: "spki", format: "pem" }),
  };
}

export function signChallenge(canonical, privateKeyPem) {
  return sign(null, Buffer.from(canonical), createPrivateKey(privateKeyPem)).toString("base64url");
}

export async function requestAgentAccess({ origin, agentId, privateKey, method = "GET", resource, scope, fetchImpl = fetch }) {
  const base = origin.replace(/\/$/, "");
  const challengeResponse = await fetchImpl(`${base}/v1/challenges`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ agent_id: agentId, method, resource, ...(scope ? { scope } : {}) }),
  });
  if (!challengeResponse.ok) throw await toProtocolError(challengeResponse, "Challenge rejected");
  const challenge = await challengeResponse.json();
  const verifyResponse = await fetchImpl(`${base}/v1/verify`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ challenge_id: challenge.id, signature: signChallenge(challenge.canonical, privateKey) }),
  });
  if (!verifyResponse.ok) throw await toProtocolError(verifyResponse, "Verification rejected");
  return verifyResponse.json();
}

// Fetch the issuer discovery document so timing, endpoints, and algorithms can
// be read from the server instead of hardcoded by the agent.
export async function discover(origin, fetchImpl = fetch) {
  const base = origin.replace(/\/$/, "");
  const response = await fetchImpl(`${base}/.well-known/reverse-captcha`);
  if (!response.ok) throw await toProtocolError(response, "Discovery failed");
  return response.json();
}

export function verifyAccessToken(token, publicKey, { issuer, audience, method, resource, now = Date.now(), leewaySeconds = 30 } = {}) {
  const [header, payload, signature] = String(token).split(".");
  if (!header || !payload || !signature) throw new ReverseCaptchaError("Malformed access token", { code: "malformed_token" });
  const decodedHeader = JSON.parse(fromB64url(header).toString("utf8"));
  // An access token must be typed `at+jwt`. A BOT PASSPORT (`bot-passport+jwt`)
  // is an identity statement and must never be accepted where an access token is
  // expected, so this check blocks passport-as-token replay by construction.
  if (decodedHeader.typ && decodedHeader.typ !== "at+jwt") throw new ReverseCaptchaError("Token type rejected", { code: "token_type_rejected" });
  const valid = verify(null, Buffer.from(`${header}.${payload}`), createPublicKey(publicKey), fromB64url(signature));
  if (!valid) throw new ReverseCaptchaError("Invalid access token signature", { code: "signature_rejected" });
  const claims = JSON.parse(fromB64url(payload).toString("utf8"));
  if (issuer && claims.iss !== issuer) throw new ReverseCaptchaError("Unexpected issuer", { code: "token_issuer_rejected" });
  if (audience && claims.aud !== audience) throw new ReverseCaptchaError("Unexpected audience", { code: "token_audience_rejected" });
  // Leeway tolerates modest clock skew between the issuer and this verifier.
  if (!claims.exp || claims.exp + leewaySeconds <= Math.floor(now / 1000)) throw new ReverseCaptchaError("Expired access token", { code: "token_expired" });
  if (method && claims.method !== String(method).toUpperCase()) throw new ReverseCaptchaError("Method not authorized", { code: "token_method_mismatch" });
  if (resource) {
    // Exact-set scope may authorize this resource even if it is not the primary.
    const wanted = String(resource);
    const covered = Array.isArray(claims.scope) && claims.scope.includes(`${String(method || claims.method).toUpperCase()} ${wanted}`);
    if (claims.resource !== wanted && !covered) throw new ReverseCaptchaError("Resource not authorized", { code: "token_resource_mismatch" });
  }
  return claims;
}

export function agentOnly({ publicKey, issuer, audience, leewaySeconds, resource = (request) => request.path || request.url }) {
  return (request, response, next) => {
    try {
      const authorization = request.headers.authorization || "";
      if (!authorization.startsWith("Bearer ")) throw new ReverseCaptchaError("Bearer token required", { code: "authorization_required" });
      request.agent = verifyAccessToken(authorization.slice(7), publicKey, {
        issuer,
        audience,
        leewaySeconds,
        method: request.method,
        resource: resource(request),
      });
      next();
    } catch (error) {
      // RFC 6750: bearer refusals carry a WWW-Authenticate challenge.
      if (typeof response.setHeader === "function") {
        response.setHeader("WWW-Authenticate", `Bearer realm="reverse-captcha", error="${error.code || "invalid_token"}"`);
      }
      response.status(401).json({
        error: "reverse_captcha_required",
        code: error.code || "invalid_token",
        message: error.message,
        retryable: Boolean(error.retryable),
      });
    }
  };
}

export { b64url };
