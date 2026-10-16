import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { dirname } from "node:path";

const freshState = () => ({ agents: {}, challenges: {}, delegations: {}, payments: {}, metrics: {} });

export class JsonStore {
  constructor(path) {
    this.path = path;
    this.state = freshState();
    this.queue = Promise.resolve();
  }

  async load() {
    try {
      this.state = { ...freshState(), ...JSON.parse(await readFile(this.path, "utf8")) };
    } catch (error) {
      if (error.code !== "ENOENT") throw error;
      await this.persist();
    }
    return this;
  }

  async persist() {
    this.queue = this.queue.then(async () => {
      await mkdir(dirname(this.path), { recursive: true });
      const temporary = `${this.path}.tmp`;
      await writeFile(temporary, `${JSON.stringify(this.state, null, 2)}\n`, { mode: 0o600 });
      await rename(temporary, this.path);
    });
    return this.queue;
  }

  increment(metric, now = new Date()) {
    const hour = now.toISOString().slice(0, 13) + ":00:00Z";
    this.state.metrics[hour] ??= {};
    this.state.metrics[hour][metric] = (this.state.metrics[hour][metric] ?? 0) + 1;
  }

  prune(nowMs = Date.now()) {
    for (const [id, challenge] of Object.entries(this.state.challenges)) {
      const expired = Date.parse(challenge.expires_at) < nowMs;
      const oldUsed = challenge.used_at && Date.parse(challenge.used_at) < nowMs - 3_600_000;
      if (expired || oldUsed) delete this.state.challenges[id];
    }
    for (const [id, delegation] of Object.entries(this.state.delegations)) {
      if (Date.parse(delegation.expires_at) < nowMs - 86_400_000) delete this.state.delegations[id];
    }
    const cutoff = nowMs - 30 * 86_400_000;
    for (const hour of Object.keys(this.state.metrics)) {
      if (Date.parse(hour) < cutoff) delete this.state.metrics[hour];
    }
  }
}

export function publicMetrics(state, nowMs = Date.now()) {
  const totals = { challenges: 0, verified: 0, rejected: 0, tokens_issued: 0 };
  const cutoff = nowMs - 24 * 3_600_000;
  for (const [hour, bucket] of Object.entries(state.metrics)) {
    if (Date.parse(hour) < cutoff) continue;
    for (const key of Object.keys(totals)) totals[key] += bucket[key] ?? 0;
  }
  return {
    period: "rolling_24h",
    totals,
    registered_agents: Object.values(state.agents).filter((agent) => agent.status === "active").length,
    privacy: "Aggregate counters only. No IP addresses, user agents, request bodies, or raw signatures are retained.",
  };
}
