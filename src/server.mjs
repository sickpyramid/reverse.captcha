import { createServer } from "node:http";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { extname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { createSigningKeys, safeSecretEquals } from "./crypto.mjs";
import { ErrorCode, ProtocolError, isProtocolError, reject } from "./errors.mjs";
import { ReverseCaptchaService } from "./service.mjs";
import { JsonStore } from "./store.mjs";
import { publicTiers } from "./tiers.mjs";
import { X402Payments } from "./x402.mjs";
import { createUrlEvidence } from "./evidence.mjs";

const root = resolve(fileURLToPath(new URL("..", import.meta.url)));
const dataDir = resolve(process.env.DATA_DIR || join(root, "data"));
const port = Number(process.env.PORT || 4408);
const host = process.env.HOST || "127.0.0.1";
const issuer = String(process.env.PUBLIC_ORIGIN || `http://${host}:${port}`).replace(/\/$/, "");
const adminToken = process.env.ADMIN_TOKEN;
if (!adminToken || adminToken.length < 24) throw new Error("ADMIN_TOKEN must contain at least 24 characters");

await mkdir(dataDir, { recursive: true });
const keyPath = join(dataDir, "issuer-keys.json");
let keys;
try {
  keys = JSON.parse(await readFile(keyPath, "utf8"));
} catch (error) {
  if (error.code !== "ENOENT") throw error;
  keys = createSigningKeys();
  await writeFile(keyPath, `${JSON.stringify(keys)}\n`, { mode: 0o600, flag: "wx" });
}

const store = await new JsonStore(join(dataDir, "state.json")).load();
const service = new ReverseCaptchaService({
  store,
  issuer,
  ...keys,
  challengeTtlSeconds: Number(process.env.CHALLENGE_TTL_SECONDS || 30),
  tokenTtlSeconds: Number(process.env.TOKEN_TTL_SECONDS || 300),
  leewaySeconds: Number(process.env.CLOCK_SKEW_LEEWAY_SECONDS || 30),
  audience: process.env.TOKEN_AUDIENCE || "reverse-captcha-protected-service",
});
const x402 = new X402Payments({
  enabled: process.env.X402_ENABLED === "true",
  facilitatorUrl: process.env.X402_FACILITATOR_URL,
  network: process.env.X402_NETWORK,
  asset: process.env.X402_ASSET,
  payTo: process.env.X402_PAY_TO,
  prices: {
    agent: process.env.X402_AGENT_AMOUNT,
    pro: process.env.X402_PRO_AMOUNT,
    register: process.env.X402_REGISTER_AMOUNT,
    evidence: process.env.X402_EVIDENCE_AMOUNT,
  },
});
const mime = { ".html": "text/html; charset=utf-8", ".css": "text/css; charset=utf-8", ".js": "text/javascript; charset=utf-8", ".json": "application/json; charset=utf-8", ".svg": "image/svg+xml" };

// Privacy-safe process-wide limiter. It deliberately stores no IP address or
// fingerprint. Deployments needing per-client limits should add them at a
// trusted reverse proxy and disclose that proxy's retention policy.
const rateLimitPerMinute = Number(process.env.RATE_LIMIT_PER_MINUTE ?? 600);
const rateWindows = new Map();
function checkRate(key) {
  if (rateLimitPerMinute <= 0) return;
  const windowId = Math.floor(Date.now() / 60_000);
  const bucket = rateWindows.get(key);
  if (!bucket || bucket.windowId !== windowId) {
    rateWindows.set(key, { windowId, count: 1 });
    if (rateWindows.size > 10_000) {
      for (const [k, v] of rateWindows) if (v.windowId !== windowId) rateWindows.delete(k);
    }
    return;
  }
  bucket.count += 1;
  if (bucket.count > rateLimitPerMinute) {
    const retryAfter = 60 - Math.floor((Date.now() % 60_000) / 1000);
    throw reject(ErrorCode.RATE_LIMITED, "Too many requests; retry later", { retryAfter });
  }
}
const clientKey = () => "global";

function send(response, status, body, headers = {}) {
  const payload = typeof body === "string" ? body : JSON.stringify(body);
  response.writeHead(status, {
    "content-type": typeof body === "string" ? "text/plain; charset=utf-8" : "application/json; charset=utf-8",
    "cache-control": "no-store",
    "x-content-type-options": "nosniff",
    "referrer-policy": "no-referrer",
    "content-security-policy": "default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:; frame-ancestors 'none'",
    ...headers,
  });
  response.end(payload);
}

// RFC 6750 bearer challenge. Advertises the discovery document so a client can
// self-configure from a single 401 instead of hardcoding endpoints.
const bearerChallenge = (error) =>
  `Bearer realm="reverse-captcha", error="${error}", resource_metadata="${issuer}/.well-known/reverse-captcha"`;

function sendError(response, error) {
  if (isProtocolError(error)) {
    const headers = { ...error.headers() };
    if (error.status === 401) headers["www-authenticate"] = bearerChallenge(error.code);
    return send(response, error.status, error.toJSON(), headers);
  }
  // Unexpected faults are not leaked to the caller.
  console.error("[reverse-captcha] internal error:", error);
  const wrapped = new ProtocolError(ErrorCode.INTERNAL_ERROR, "Internal server error");
  return send(response, wrapped.status, wrapped.toJSON());
}

async function body(request) {
  const chunks = [];
  let size = 0;
  for await (const chunk of request) {
    size += chunk.length;
    if (size > 32_768) throw reject(ErrorCode.BODY_TOO_LARGE, "Request body too large");
    chunks.push(chunk);
  }
  const text = Buffer.concat(chunks).toString("utf8") || "{}";
  try {
    return JSON.parse(text);
  } catch (cause) {
    throw reject(ErrorCode.INVALID_JSON, "Request body must be valid JSON", { cause });
  }
}

const routes = new Map([
  ["GET /.well-known/reverse-captcha", async () => service.discovery()],
  ["GET /.well-known/jwks.json", async () => service.jwks()],
  ["GET /v1/metrics/public", async () => service.metrics()],
  ["GET /healthz", async () => ({ ok: true, protocol: "reverse-captcha/v1" })],
  ["GET /v1/tiers", async () => ({ payment_protocol: "x402-v2", payment_enabled: x402.enabled, tiers: publicTiers(x402.prices) })],
  ["GET /v1/services", async () => ({
    payment_protocol: "x402-v2",
    payment_enabled: x402.enabled,
    network: x402.network,
    receiver: x402.payTo,
    services: [
      { id: "agent-identity-access", name: "Agent Identity & Access", method: "POST", path: "/v1/paid/register", price_atomic: x402.prices.register || null, description: "Register an Ed25519 agent identity and activate the hosted Agent tier." },
      { id: "web-evidence-snapshot", name: "Web Evidence Snapshot", method: "POST", path: "/v1/paid/evidence", price_atomic: x402.prices.evidence || null, description: "Create a privacy-safe point-in-time URL and content evidence snapshot." },
    ],
    claim_limit: "Agent authorization proves control of a registered key, not absence of human direction.",
  })],
  ["GET /.well-known/x402", async () => ({
    version: 1,
    name: "Reverse Agent API by reverse.captcha",
    description: "Pay-per-use security and web utilities for autonomous agents.",
    openapi: `${issuer}/openapi.json`,
    payment_protocol: "x402-v2",
    network: x402.network,
    ownershipProofs: x402.payTo ? [x402.payTo] : [],
    resources: [`${issuer}/v1/paid/register`, `${issuer}/v1/paid/evidence`],
    resource_metadata: [
      { method: "POST", url: `${issuer}/v1/paid/register`, price: "$0.01", description: "Hosted Reverse CAPTCHA agent identity registration and Agent-tier activation." },
      { method: "POST", url: `${issuer}/v1/paid/evidence`, price: "$0.03", description: "Point-in-time HTTPS content evidence with hashes and provenance." },
    ],
  })],
]);

const registrationPayment = {
  description: "Register an Ed25519 agent identity and activate the reverse.captcha Agent tier",
  input: { name: "Example Agent", public_key: "-----BEGIN PUBLIC KEY-----\\n...\\n-----END PUBLIC KEY-----", capabilities: ["fetch", "summarize"] },
  inputSchema: { type: "object", properties: { name: { type: "string" }, public_key: { type: "string" }, capabilities: { type: "array", items: { type: "string" } } }, required: ["name", "public_key"] },
  outputExample: { agent: { id: "bot_...", tier: "agent" }, passport: "eyJ...", payment: { network: "eip155:8453", transaction: "0x..." } },
};

const evidencePayment = {
  description: "Create a privacy-safe point-in-time HTTPS content evidence snapshot",
  input: { url: "https://example.com/" },
  inputSchema: { type: "object", properties: { url: { type: "string", format: "uri", pattern: "^https://" } }, required: ["url"] },
  outputExample: { ok: true, final_url: "https://example.com/", status: 200, fetched_at: "2026-01-01T00:00:00.000Z", sha256: "...", title: "Example Domain" },
};

const bearer = (request) => {
  const authorization = request.headers.authorization || "";
  if (!authorization.startsWith("Bearer ")) throw reject(ErrorCode.AUTHORIZATION_REQUIRED, "Bearer access token required");
  return authorization.slice(7);
};

const server = createServer(async (request, response) => {
  const url = new URL(request.url, issuer);
  const method = request.method === "HEAD" ? "GET" : request.method;
  try {
    if (request.method === "OPTIONS") return send(response, 204, "", { allow: "GET, POST, OPTIONS" });
    if (method === "POST" && url.pathname === "/v1/admin/agents") {
      if (!safeSecretEquals(request.headers.authorization, `Bearer ${adminToken}`)) return send(response, 401, { error: "admin_authorization_required", code: ErrorCode.AUTHORIZATION_REQUIRED, message: "Admin authorization required", retryable: false }, { "www-authenticate": bearerChallenge(ErrorCode.AUTHORIZATION_REQUIRED) });
      return send(response, 201, await service.registerAgent(await body(request)));
    }
    if (method === "GET" && url.pathname === "/v1/admin/dashboard") {
      if (!safeSecretEquals(request.headers.authorization, `Bearer ${adminToken}`)) return send(response, 401, { error: "admin_authorization_required", code: ErrorCode.AUTHORIZATION_REQUIRED, message: "Admin authorization required", retryable: false }, { "www-authenticate": bearerChallenge(ErrorCode.AUTHORIZATION_REQUIRED) });
      return send(response, 200, service.dashboard());
    }
    if (method === "POST" && url.pathname === "/v1/challenges") {
      checkRate(clientKey(request));
      return send(response, 201, await service.createChallenge(await body(request)));
    }
    if (method === "POST" && url.pathname === "/v1/verify") {
      checkRate(clientKey(request));
      return send(response, 200, await service.verifyChallenge(await body(request)));
    }
    if (method === "POST" && url.pathname === "/v1/delegations") {
      return send(response, 201, await service.createDelegation(bearer(request), await body(request)));
    }
    const revokeMatch = url.pathname.match(/^\/v1\/delegations\/([^/]+)\/revoke$/);
    if (method === "POST" && revokeMatch) {
      return send(response, 200, await service.revokeDelegation(bearer(request), decodeURIComponent(revokeMatch[1])));
    }
    const tierMatch = url.pathname.match(/^\/v1\/paid\/tiers\/(agent|pro)$/);
    if (method === "POST" && tierMatch) {
      const tier = tierMatch[1];
      const target = await body(request);
      service.assertTierActivation(target.agent_id, tier);
      const payment = x402.requirement({ tier, url: `${issuer}${url.pathname}` });
      const paymentSignature = request.headers["payment-signature"];
      if (!paymentSignature) return send(response, 402, payment.paymentRequired, { "payment-required": payment.header });
      const settlement = await x402.authorize({ tier, url: `${issuer}${url.pathname}`, paymentSignature });
      const result = await service.activateTier(target.agent_id, tier, settlement);
      return send(response, 200, result, { "payment-response": Buffer.from(JSON.stringify(settlement)).toString("base64") });
    }
    if (method === "POST" && url.pathname === "/v1/paid/register") {
      checkRate(clientKey(request));
      const payment = x402.requirement({ product: "register", url: `${issuer}${url.pathname}`, ...registrationPayment });
      const paymentSignature = request.headers["payment-signature"];
      if (!paymentSignature) return send(response, 402, payment.paymentRequired, { "payment-required": payment.header });
      const target = await body(request);
      const agentId = service.assertPaidRegistration(target);
      const settlement = await x402.authorize({ product: "register", url: `${issuer}${url.pathname}`, paymentSignature, ...registrationPayment });
      const registered = await service.registerAgent(target);
      const activation = await service.activateTier(agentId, "agent", settlement);
      return send(response, 201, { ...registered, agent: { ...registered.agent, tier: "agent" }, passport: activation.passport, payment: activation.payment }, { "payment-response": Buffer.from(JSON.stringify(settlement)).toString("base64") });
    }
    if (method === "POST" && url.pathname === "/v1/paid/evidence") {
      checkRate(clientKey(request));
      const payment = x402.requirement({ product: "evidence", url: `${issuer}${url.pathname}`, ...evidencePayment });
      const paymentSignature = request.headers["payment-signature"];
      if (!paymentSignature) return send(response, 402, payment.paymentRequired, { "payment-required": payment.header });
      const target = await body(request);
      let parsed;
      try { parsed = new URL(String(target.url || "")); } catch { return send(response, 400, { error: "invalid_request", code: "invalid_url", message: "url must be a valid public HTTPS URL", retryable: false }); }
      if (parsed.protocol !== "https:" || parsed.username || parsed.password) return send(response, 400, { error: "invalid_request", code: "invalid_url", message: "Only public HTTPS URLs without credentials are accepted", retryable: false });
      const settlement = await x402.authorize({ product: "evidence", url: `${issuer}${url.pathname}`, paymentSignature, ...evidencePayment });
      const result = await createUrlEvidence(target);
      return send(response, 200, { ...result, payment: { transaction: settlement.transaction, network: settlement.network } }, { "payment-response": Buffer.from(JSON.stringify(settlement)).toString("base64") });
    }
    if (method === "GET" && url.pathname === "/v1/demo/agent-only") {
      const authorization = request.headers.authorization || "";
      if (!authorization.startsWith("Bearer ")) return send(response, 401, { error: "reverse_captcha_required", code: ErrorCode.AUTHORIZATION_REQUIRED, message: "reverse_captcha_required", challenge: `${issuer}/v1/challenges`, retryable: false }, { "www-authenticate": bearerChallenge("invalid_request") });
      const claims = service.inspectAccessToken(authorization.slice(7), { method: "GET", resource: "/v1/demo/agent-only" });
      return send(response, 200, { access: "GRANTED", message: "Welcome, machine.", agent_id: claims.sub });
    }
    const handler = routes.get(`${method} ${url.pathname}`);
    if (handler) return send(response, 200, await handler());
    if (method === "GET") {
      const requested = url.pathname === "/" ? "index.html" : url.pathname.slice(1);
      if (!/^[a-zA-Z0-9._-]+$/.test(requested)) return send(response, 404, { error: "not_found", code: "not_found", message: "Not found", retryable: false });
      try {
        const file = await readFile(join(root, "public", requested));
        response.writeHead(200, { "content-type": mime[extname(requested)] || "application/octet-stream", "cache-control": requested === "index.html" ? "no-cache" : "public, max-age=3600", "x-content-type-options": "nosniff", "content-security-policy": "default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:; frame-ancestors 'none'" });
        return response.end(file);
      } catch {}
    }
    return send(response, 404, { error: "not_found", code: "not_found", message: "Not found", retryable: false });
  } catch (error) {
    return sendError(response, error);
  }
});

server.listen(port, host, () => console.log(`Reverse CAPTCHA listening on ${host}:${port}`));

for (const signal of ["SIGINT", "SIGTERM"]) {
  process.on(signal, () => server.close(() => process.exit(0)));
}
