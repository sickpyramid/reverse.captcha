export const TIERS = Object.freeze({
  free: Object.freeze({ id: "free", scope_limit: 1, active_delegation_limit: 0, token_ttl_seconds: 300, paid: false }),
  agent: Object.freeze({ id: "agent", scope_limit: 8, active_delegation_limit: 5, token_ttl_seconds: 900, paid: true }),
  pro: Object.freeze({ id: "pro", scope_limit: 32, active_delegation_limit: 50, token_ttl_seconds: 1800, paid: true }),
});

export function tierFor(value) {
  return TIERS[String(value || "free")] || null;
}

export function publicTiers(prices = {}) {
  return Object.values(TIERS).map((tier) => ({ ...tier, price_atomic: prices[tier.id] || null }));
}
