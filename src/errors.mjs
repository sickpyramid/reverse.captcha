// Machine-readable protocol errors.
//
// Every failure the protocol can produce carries a stable `code` so an agent
// can branch on it programmatically instead of pattern-matching human text.
// The legacy `error` bucket is preserved so existing clients keep working.

export const ErrorCode = Object.freeze({
  // 400 — the request itself is malformed or unusable
  INVALID_REQUEST: "invalid_request",
  INVALID_JSON: "invalid_json",
  BODY_TOO_LARGE: "body_too_large",
  INVALID_RESOURCE: "invalid_resource",
  INVALID_METHOD: "invalid_method",
  INVALID_NAME: "invalid_name",
  INVALID_PUBLIC_KEY: "invalid_public_key",
  INVALID_SCOPE: "invalid_scope",
  TOO_MANY_SCOPES: "too_many_scopes",

  // 401 — authentication is required or the credential is not usable
  AUTHORIZATION_REQUIRED: "authorization_required",
  TOKEN_EXPIRED: "token_expired",
  TOKEN_TYPE_REJECTED: "token_type_rejected",

  // 403 — the caller is known but the proof/authorization is refused
  UNKNOWN_AGENT: "unknown_agent",
  AGENT_INACTIVE: "agent_inactive",
  UNKNOWN_CHALLENGE: "unknown_challenge",
  CHALLENGE_ALREADY_USED: "challenge_already_used",
  CHALLENGE_EXPIRED: "challenge_expired",
  SIGNATURE_REJECTED: "signature_rejected",
  TOKEN_ISSUER_REJECTED: "token_issuer_rejected",
  TOKEN_AUDIENCE_REJECTED: "token_audience_rejected",
  TOKEN_METHOD_MISMATCH: "token_method_mismatch",
  TOKEN_RESOURCE_MISMATCH: "token_resource_mismatch",
  IDENTITY_COLLISION: "identity_collision",

  // 409 — registration conflict
  AGENT_EXISTS: "agent_exists",

  // 429 — caller is throttled
  RATE_LIMITED: "rate_limited",

  // 500 — unexpected server fault
  INTERNAL_ERROR: "internal_error",
});

// Which coarse HTTP status each code maps to.
const STATUS_BY_CODE = new Map([
  [ErrorCode.INVALID_REQUEST, 400],
  [ErrorCode.INVALID_JSON, 400],
  [ErrorCode.BODY_TOO_LARGE, 413],
  [ErrorCode.INVALID_RESOURCE, 400],
  [ErrorCode.INVALID_METHOD, 400],
  [ErrorCode.INVALID_NAME, 400],
  [ErrorCode.INVALID_PUBLIC_KEY, 400],
  [ErrorCode.INVALID_SCOPE, 400],
  [ErrorCode.TOO_MANY_SCOPES, 400],
  [ErrorCode.AUTHORIZATION_REQUIRED, 401],
  [ErrorCode.TOKEN_EXPIRED, 401],
  [ErrorCode.TOKEN_TYPE_REJECTED, 401],
  [ErrorCode.UNKNOWN_AGENT, 403],
  [ErrorCode.AGENT_INACTIVE, 403],
  [ErrorCode.UNKNOWN_CHALLENGE, 403],
  [ErrorCode.CHALLENGE_ALREADY_USED, 403],
  [ErrorCode.CHALLENGE_EXPIRED, 403],
  [ErrorCode.SIGNATURE_REJECTED, 403],
  [ErrorCode.TOKEN_ISSUER_REJECTED, 403],
  [ErrorCode.TOKEN_AUDIENCE_REJECTED, 403],
  [ErrorCode.TOKEN_METHOD_MISMATCH, 403],
  [ErrorCode.TOKEN_RESOURCE_MISMATCH, 403],
  [ErrorCode.IDENTITY_COLLISION, 403],
  [ErrorCode.AGENT_EXISTS, 409],
  [ErrorCode.RATE_LIMITED, 429],
  [ErrorCode.INTERNAL_ERROR, 500],
]);

// Coarse buckets kept for backward compatibility with clients that only look
// at the `error` field (e.g. the public gate reads `message`, dashboards read
// `error`). Unknown specifics still resolve to a stable bucket.
const BUCKET_BY_STATUS = new Map([
  [400, "request_rejected"],
  [401, "reverse_captcha_required"],
  [403, "request_rejected"],
  [409, "request_rejected"],
  [413, "request_rejected"],
  [429, "rate_limited"],
  [500, "internal_error"],
]);

// Codes where a well-behaved agent may retry the same call later (after the
// advertised delay). Everything else is a permanent refusal for that payload.
const RETRYABLE = new Set([
  ErrorCode.RATE_LIMITED,
  ErrorCode.INTERNAL_ERROR,
]);

export class ProtocolError extends Error {
  constructor(code, message, { details, retryAfter, cause } = {}) {
    super(message, cause ? { cause } : undefined);
    this.name = "ProtocolError";
    this.code = STATUS_BY_CODE.has(code) ? code : ErrorCode.INTERNAL_ERROR;
    this.status = STATUS_BY_CODE.get(this.code);
    this.details = details;
    this.retryAfter = retryAfter;
    this.retryable = RETRYABLE.has(this.code);
  }

  // Wire shape. `error` stays the legacy bucket, `code` is the precise reason.
  toJSON() {
    const body = {
      error: BUCKET_BY_STATUS.get(this.status) ?? "request_rejected",
      code: this.code,
      message: this.message,
      retryable: this.retryable,
    };
    if (this.details !== undefined) body.details = this.details;
    return body;
  }

  headers() {
    const headers = {};
    if (this.status === 429) headers["retry-after"] = String(this.retryAfter ?? 60);
    return headers;
  }
}

export const isProtocolError = (error) => error instanceof ProtocolError;

// Convenience constructors for the most common failures.
export const reject = (code, message, options) => new ProtocolError(code, message, options);
