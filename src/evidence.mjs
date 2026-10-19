import { createHash } from "node:crypto";
import { lookup as dnsLookup } from "node:dns/promises";
import { request as httpsRequest } from "node:https";
import { isIP } from "node:net";

const MAX_BYTES = 256 * 1024;
const MAX_REDIRECTS = 4;
const TIMEOUT_MS = 8_000;

function blockedIpv4(address) {
  const parts = address.split(".").map(Number);
  if (parts.length !== 4 || parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) return true;
  const [a, b] = parts;
  return a === 0 || a === 10 || a === 127 || a >= 224 ||
    (a === 100 && b >= 64 && b <= 127) ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 0) ||
    (a === 192 && b === 168) ||
    (a === 198 && (b === 18 || b === 19));
}

function blockedIpv6(address) {
  const value = address.toLowerCase().split("%")[0];
  if (value === "::" || value === "::1") return true;
  if (value.startsWith("fc") || value.startsWith("fd") || value.startsWith("fe8") || value.startsWith("fe9") || value.startsWith("fea") || value.startsWith("feb")) return true;
  if (value.startsWith("::ffff:")) return blockedIpv4(value.slice(7));
  return false;
}

export function isPublicIp(address) {
  const family = isIP(address);
  return family === 4 ? !blockedIpv4(address) : family === 6 ? !blockedIpv6(address) : false;
}

async function publicLookup(hostname, options, callback) {
  try {
    const addresses = await dnsLookup(hostname, { all: true, verbatim: true });
    if (!addresses.length || addresses.some(({ address }) => !isPublicIp(address))) {
      return callback(new Error("Target resolves to a non-public address"));
    }
    const preferred = addresses.find(({ family }) => family === 4) || addresses[0];
    callback(null, preferred.address, preferred.family);
  } catch (error) {
    callback(error);
  }
}

function cleanText(value, max = 500) {
  return String(value || "").replace(/<[^>]*>/g, " ").replace(/\s+/g, " ").trim().slice(0, max);
}

function meta(html, name) {
  const escaped = name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const patterns = [
    new RegExp(`<meta[^>]+(?:name|property)=["']${escaped}["'][^>]+content=["']([^"']*)["'][^>]*>`, "i"),
    new RegExp(`<meta[^>]+content=["']([^"']*)["'][^>]+(?:name|property)=["']${escaped}["'][^>]*>`, "i"),
  ];
  for (const pattern of patterns) {
    const match = html.match(pattern);
    if (match) return cleanText(match[1], 300);
  }
  return null;
}

function parseDate(value) {
  if (!value) return null;
  const timestamp = Date.parse(String(value));
  return Number.isFinite(timestamp) ? new Date(timestamp).toISOString() : null;
}

function dateSignals(html) {
  const candidates = [
    ["meta:article:modified_time", meta(html, "article:modified_time")],
    ["meta:og:updated_time", meta(html, "og:updated_time")],
    ["meta:dateModified", meta(html, "dateModified")],
    ["meta:article:published_time", meta(html, "article:published_time")],
    ["meta:datePublished", meta(html, "datePublished")],
  ];
  for (const field of ["dateModified", "datePublished", "uploadDate"]) {
    const pattern = new RegExp(`['"]${field}['"]\\s*:\\s*['"]([^'"]+)['"]`, "i");
    candidates.push([`structured:${field}`, html.match(pattern)?.[1]]);
  }
  candidates.push(["html:time", html.match(/<time[^>]+datetime=["']([^"']+)["']/i)?.[1]]);
  return candidates.map(([source, value]) => ({ source, timestamp: parseDate(value) })).filter(({ timestamp }) => timestamp);
}

function pageFacts(text, contentType) {
  if (!/html|xml/i.test(contentType)) return { title: null, description: null, canonical_url: null, link_count: 0, text_excerpt: cleanText(text, 600), date_signals: [] };
  const title = cleanText(text.match(/<title[^>]*>([\s\S]*?)<\/title>/i)?.[1], 200) || null;
  const canonical = text.match(/<link[^>]+rel=["']canonical["'][^>]+href=["']([^"']+)["'][^>]*>/i)?.[1] || null;
  const withoutNoise = text.replace(/<(script|style|noscript|svg)[^>]*>[\s\S]*?<\/\1>/gi, " ");
  return {
    title,
    description: meta(text, "description") || meta(text, "og:description"),
    canonical_url: canonical,
    link_count: (text.match(/<a\b/gi) || []).length,
    text_excerpt: cleanText(withoutNoise, 600),
    date_signals: dateSignals(text),
  };
}

export function assessFreshness(evidence, input = {}, now = new Date()) {
  const requested = Number(input.max_age_seconds ?? 86_400);
  if (!Number.isInteger(requested) || requested < 60 || requested > 2_678_400) throw new Error("max_age_seconds must be an integer from 60 to 2678400");
  if (!evidence?.ok) return { ...evidence, max_age_seconds: requested, freshness: "unavailable", is_within_max_age: null, confidence: "none", evidence_timestamp: null, age_seconds: null, date_candidates: [] };
  const candidates = [];
  const lastModified = parseDate(evidence.headers?.last_modified);
  if (lastModified) candidates.push({ source: "http:last-modified", timestamp: lastModified, confidence: "medium" });
  for (const signal of evidence.date_signals || []) candidates.push({ ...signal, confidence: signal.source.includes("modified") || signal.source.includes("updated") ? "medium" : "low" });
  const nowMs = now.getTime();
  const plausible = candidates.filter(({ timestamp }) => {
    const value = Date.parse(timestamp);
    return Number.isFinite(value) && value <= nowMs + 300_000;
  }).sort((a, b) => Date.parse(b.timestamp) - Date.parse(a.timestamp));
  const selected = plausible[0] || null;
  const ageSeconds = selected ? Math.max(0, Math.floor((nowMs - Date.parse(selected.timestamp)) / 1000)) : null;
  return {
    ...evidence,
    max_age_seconds: requested,
    freshness: selected ? (ageSeconds <= requested ? "fresh" : "stale") : "unknown",
    is_within_max_age: selected ? ageSeconds <= requested : null,
    confidence: selected?.confidence || "none",
    evidence_timestamp: selected?.timestamp || null,
    evidence_source: selected?.source || null,
    age_seconds: ageSeconds,
    date_candidates: plausible,
    claim_limit: "Freshness is based on publisher- and server-declared timestamps observed at fetch time. It does not prove factual accuracy, authorship, or when the underlying event occurred.",
  };
}

async function get(url) {
  return new Promise((resolve, reject) => {
    const request = httpsRequest(url, {
      method: "GET",
      headers: { accept: "text/html,application/json,text/plain,application/xml;q=0.8", "user-agent": "reverse.captcha-evidence/1.0" },
      lookup: publicLookup,
      timeout: TIMEOUT_MS,
    }, (response) => {
      const chunks = [];
      let bytes = 0;
      response.on("data", (chunk) => {
        if (bytes >= MAX_BYTES) return;
        const slice = chunk.subarray(0, MAX_BYTES - bytes);
        chunks.push(slice);
        bytes += slice.length;
      });
      response.on("end", () => resolve({ status: response.statusCode || 0, headers: response.headers, body: Buffer.concat(chunks), truncated: Number(response.headers["content-length"] || 0) > bytes }));
    });
    request.on("timeout", () => request.destroy(new Error("Target timed out")));
    request.on("error", reject);
    request.end();
  });
}

export async function createUrlEvidence(input, now = new Date()) {
  const original = String(input?.url || "");
  let current;
  try { current = new URL(original); } catch { throw new Error("url must be a valid HTTPS URL"); }
  if (current.protocol !== "https:" || current.username || current.password) throw new Error("Only public HTTPS URLs without credentials are accepted");
  const redirects = [];
  try {
    for (let count = 0; count <= MAX_REDIRECTS; count += 1) {
      const response = await get(current);
      const location = response.headers.location;
      if (location && [301, 302, 303, 307, 308].includes(response.status)) {
        if (count === MAX_REDIRECTS) throw new Error("Too many redirects");
        const next = new URL(location, current);
        if (next.protocol !== "https:" || next.username || next.password) throw new Error("Redirected to a disallowed URL");
        redirects.push(next.href);
        current = next;
        continue;
      }
      const contentType = String(response.headers["content-type"] || "application/octet-stream").split(";", 1)[0];
      const text = response.body.toString("utf8");
      return {
        ok: true,
        requested_url: original,
        final_url: current.href,
        fetched_at: now.toISOString(),
        status: response.status,
        content_type: contentType,
        bytes_sampled: response.body.length,
        truncated: response.truncated || response.body.length === MAX_BYTES,
        sha256: createHash("sha256").update(response.body).digest("hex"),
        redirects,
        headers: {
          cache_control: response.headers["cache-control"] || null,
          etag: response.headers.etag || null,
          last_modified: response.headers["last-modified"] || null,
        },
        ...pageFacts(text, contentType),
        claim_limit: "This is a point-in-time transport and content snapshot, not a truth or authorship determination.",
      };
    }
  } catch (error) {
    return { ok: false, requested_url: original, final_url: current.href, fetched_at: now.toISOString(), error: String(error.message || error), redirects };
  }
}

export async function createFreshnessReport(input, now = new Date()) {
  return assessFreshness(await createUrlEvidence(input, now), input, now);
}
