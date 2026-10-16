import { createServer } from "node:http";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { extname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { createSigningKeys, safeSecretEquals } from "./crypto.mjs";
import { ErrorCode, ProtocolError, isProtocolError, reject } from "./errors.mjs";
import { ReverseCaptchaService } from "./service.mjs";
import { JsonStore } from "./store.mjs";

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
const mime = { ".html": "text/html; charset=utf-8", ".css": "text/css; charset=utf-8", ".js": "text/javascript; charset=utf-8", ".svg": "image/svg+xml" };

// Edge rate limiter. Keyed by client IP with a fixed window. Only the two
// unauthenticated POST endpoints are limited, so a spammer cannot force disk
// writes or CPU verification. Disabled when RATE_LIMIT_PER_MINUTE is 0.
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
const clientKey = (request) => request.socket.remoteAddress || "unknown";

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
]);

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
