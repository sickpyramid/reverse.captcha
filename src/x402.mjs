import { ErrorCode, reject } from "./errors.mjs";

const encode = (value) => Buffer.from(JSON.stringify(value)).toString("base64");
const decode = (value) => JSON.parse(Buffer.from(String(value), "base64").toString("utf8"));

export class X402Payments {
  constructor({ enabled = false, facilitatorUrl, network, asset, payTo, prices = {}, fetchImpl = fetch } = {}) {
    this.enabled = enabled;
    this.facilitatorUrl = String(facilitatorUrl || "").replace(/\/$/, "");
    this.network = network;
    this.asset = asset;
    this.payTo = payTo;
    this.prices = prices;
    this.fetch = fetchImpl;
    if (enabled && (!this.facilitatorUrl || !network || !asset || !payTo)) {
      throw new Error("x402 requires X402_FACILITATOR_URL, X402_NETWORK, X402_ASSET, and X402_PAY_TO");
    }
  }

  requirement({ tier, url }) {
    const amount = this.prices[tier];
    if (!this.enabled || !amount) throw reject(ErrorCode.PAYMENT_NOT_CONFIGURED, "Paid tier activation is not configured");
    const paymentRequirements = {
      scheme: "exact", network: this.network, amount: String(amount), asset: this.asset,
      payTo: this.payTo, maxTimeoutSeconds: 60,
      extra: { paymentFlow: "authorization" },
    };
    const info = {
      input: { type: "http", method: "POST", bodyType: "json", body: { agent_id: "bot_..." } },
      output: { type: "json", example: { tier, status: "active", agent_id: "bot_..." } },
    };
    const schema = {
      $schema: "https://json-schema.org/draft/2020-12/schema", type: "object",
      properties: {
        input: { type: "object", properties: { type: { const: "http" }, method: { const: "POST" }, bodyType: { const: "json" }, body: { type: "object", properties: { agent_id: { type: "string" } }, required: ["agent_id"] } }, required: ["type", "method", "bodyType", "body"] },
        output: { type: "object", properties: { type: { type: "string" }, example: { type: "object" } }, required: ["type"] },
      }, required: ["input"],
    };
    const paymentRequired = {
      x402Version: 2,
      error: "PAYMENT-SIGNATURE header is required",
      resource: { url, description: `Activate the reverse.captcha ${tier} tier`, mimeType: "application/json", serviceName: "reverse.captcha", tags: ["agents", "authorization", "privacy"] },
      accepts: [paymentRequirements],
      extensions: { bazaar: { info, schema } },
    };
    return { paymentRequired, paymentRequirements, header: encode(paymentRequired) };
  }

  async callFacilitator(path, paymentPayload, paymentRequirements) {
    const response = await this.fetch(`${this.facilitatorUrl}${path}`, {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ x402Version: 2, paymentPayload, paymentRequirements }),
    });
    if (!response.ok) throw reject(ErrorCode.PAYMENT_REJECTED, `Facilitator ${path} failed`);
    return { body: await response.json(), extensions: response.headers?.get?.("extension-responses") || null };
  }

  async authorize({ tier, url, paymentSignature }) {
    const requirement = this.requirement({ tier, url });
    if (!paymentSignature) throw reject(ErrorCode.PAYMENT_REQUIRED, "Payment required", { details: requirement.paymentRequired });
    let paymentPayload;
    try { paymentPayload = decode(paymentSignature); } catch { throw reject(ErrorCode.PAYMENT_REJECTED, "Malformed PAYMENT-SIGNATURE header"); }
    const accepted = paymentPayload?.accepted || {};
    for (const key of ["scheme", "network", "amount", "asset", "payTo"]) {
      if (String(accepted[key]) !== String(requirement.paymentRequirements[key])) throw reject(ErrorCode.PAYMENT_REJECTED, `Payment ${key} does not match`);
    }
    const verified = await this.callFacilitator("/verify", paymentPayload, requirement.paymentRequirements);
    if (!verified.body.isValid) throw reject(ErrorCode.PAYMENT_REJECTED, verified.body.invalidReason || "Payment verification rejected");
    const settled = await this.callFacilitator("/settle", paymentPayload, requirement.paymentRequirements);
    if (!settled.body.success) throw reject(ErrorCode.PAYMENT_REJECTED, settled.body.errorReason || "Payment settlement failed");
    return { ...settled.body, extensionResponses: settled.extensions };
  }
}
