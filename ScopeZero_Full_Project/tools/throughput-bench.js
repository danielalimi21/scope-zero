// Persistence hot-path throughput benchmark — real SQLite Store, no mocks.
//
//   node tools/throughput-bench.js [iterations]
//
// On every tool call the runtime writes three pieces of state: the agent's
// behavior profile, the session risk, and decision metrics. Previously each of
// those reserialized the entire state blob (SQLite) or took a global advisory
// lock + full-state read-modify-write (Postgres) — capping the gateway to
// single-writer throughput. They now live in row-keyed tables with atomic
// upserts. This benchmark hammers that hot path and proves two things:
//   1. sustained writes/sec on the persistence layer
//   2. the full-state blob is NEVER rewritten on the hot path (0 rewrites)
//
// (Full evaluateToolCall throughput is bounded by ledger fsync and, under a
// synthetic single-agent flood, by the burst guard correctly escalating to
// approval — neither is the persistence-scaling property measured here.)

import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { Store } from "../src/store.js";
import policy from "../config/defaultPolicy.json" with { type: "json" };

const ITERATIONS = Number(process.argv[2] || 50000);
const FANOUT = 256; // distinct agents / sessions — the shape that parallelizes

function blobRevision(store) {
  return store.db.prepare("SELECT updated_at, body FROM scopezero_state WHERE id = 'primary'").get();
}

async function main() {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "scopezero-bench-"));
  const store = new Store(path.join(dir, "scopezero.db"), policy);
  await store.init();

  const profileFor = (agentId) => ({
    tenant_id: "tenant_contoso",
    agent_id: agentId,
    tools: { "drive.read": { total_calls: 1, hourly_dist: Array(24).fill(0), velocity_window: [], daily_counts: {} } }
  });

  // Warm up.
  for (let i = 0; i < 500; i++) {
    await store.recordToolCall("tenant_contoso", `agent-${i % FANOUT}`, "drive.read", profileFor(`agent-${i % FANOUT}`));
    await store.updateSessionRisk(`sess-${i % FANOUT}`, 1, "tenant_contoso");
    await store.recordDecision({ decision: "allow" });
  }

  const before = blobRevision(store);
  const t0 = process.hrtime.bigint();
  for (let i = 0; i < ITERATIONS; i++) {
    const agentId = `agent-${i % FANOUT}`;
    await store.recordToolCall("tenant_contoso", agentId, "drive.read", profileFor(agentId));
    await store.updateSessionRisk(`sess-${i % FANOUT}`, 2, "tenant_contoso");
    await store.recordDecision({ decision: i % 7 === 0 ? "block" : "allow" });
  }
  const t1 = process.hrtime.bigint();
  const after = blobRevision(store);

  const ms = Number(t1 - t0) / 1e6;
  const writes = ITERATIONS * 3;
  const blobUnchanged = before.updated_at === after.updated_at && before.body === after.body;
  const metrics = store.getMetrics();

  console.log("ScopeZero persistence hot-path throughput");
  console.log("─".repeat(52));
  console.log(`iterations              ${ITERATIONS.toLocaleString()}  (×3 row writes each)`);
  console.log(`distinct agents/sessions ${FANOUT}`);
  console.log(`elapsed                 ${ms.toFixed(1)} ms`);
  console.log(`hot-path writes/sec     ${Math.round((writes / ms) * 1000).toLocaleString()}`);
  console.log(`mean write latency      ${(ms / writes).toFixed(4)} ms`);
  console.log(`state-blob rewrites     ${blobUnchanged ? 0 : "MANY"}  (must be 0)`);
  console.log(`metrics.runtime_decisions ${metrics.runtime_decisions.toLocaleString()}`);
  console.log(`metrics.blocked_actions   ${metrics.blocked_actions.toLocaleString()}`);
  console.log("─".repeat(52));

  await fs.rm(dir, { recursive: true, force: true });

  if (!blobUnchanged) {
    console.error("REGRESSION: hot path rewrote the full-state blob.");
    process.exit(1);
  }
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
