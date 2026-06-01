// Concurrency benchmark — proves the hot-path counters are lossless under many
// simultaneous writers, and reports throughput.
//
//   node tools/concurrency-bench.js [iterations]                 # SQLite (single process)
//   SCOPEZERO_STORE=postgres DATABASE_URL=... node tools/concurrency-bench.js   # Postgres
//
// The test fires N recordDecision() calls concurrently (Promise.all) and then
// checks the metric counters advanced by EXACTLY N. A naive read-modify-write
// loses updates under real parallelism; the atomic SQL increments do not. On
// Postgres this exercises genuinely overlapping connections — the multi-writer
// path the scale work unlocked by taking the hot path off the global lock.

import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { Store } from "../src/store.js";
import { PostgresStore } from "../src/postgresStore.js";

const ITERATIONS = Number(process.argv[2] || 20000);
const usePostgres = process.env.SCOPEZERO_STORE === "postgres";

async function main() {
  const defaultPolicy = JSON.parse(await fs.readFile(new URL("../config/defaultPolicy.json", import.meta.url), "utf8"));

  let store;
  let cleanup = async () => {};
  if (usePostgres) {
    if (!process.env.DATABASE_URL) throw new Error("DATABASE_URL is required when SCOPEZERO_STORE=postgres.");
    store = new PostgresStore({ connectionString: process.env.DATABASE_URL, defaultPolicy });
    cleanup = async () => { await store.pool?.end?.(); };
  } else {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), "scopezero-conc-"));
    store = new Store(path.join(dir, "scopezero.db"), defaultPolicy);
    cleanup = async () => { await fs.rm(dir, { recursive: true, force: true }); };
  }
  await store.init();

  const before = await store.getMetrics();
  // Exact number of "block" decisions we will fire (i % 7 === 0 over [0, N)).
  const expectedBlocked = Math.floor((ITERATIONS - 1) / 7) + 1;

  const t0 = process.hrtime.bigint();
  await Promise.all(
    Array.from({ length: ITERATIONS }, (_, i) => store.recordDecision({ decision: i % 7 === 0 ? "block" : "allow" }))
  );
  const t1 = process.hrtime.bigint();

  const after = await store.getMetrics();
  const decisionsAdded = after.runtime_decisions - before.runtime_decisions;
  const blockedAdded = after.blocked_actions - before.blocked_actions;

  const ms = Number(t1 - t0) / 1e6;
  const lossless = decisionsAdded === ITERATIONS && blockedAdded === expectedBlocked;

  console.log("ScopeZero concurrency benchmark");
  console.log("─".repeat(52));
  console.log(`store                   ${usePostgres ? "postgres" : "sqlite"}`);
  console.log(`concurrent writes       ${ITERATIONS.toLocaleString()}`);
  console.log(`elapsed                 ${ms.toFixed(1)} ms`);
  console.log(`throughput              ${Math.round((ITERATIONS / ms) * 1000).toLocaleString()} decisions/sec`);
  console.log(`runtime_decisions delta ${decisionsAdded.toLocaleString()} (expected ${ITERATIONS.toLocaleString()})`);
  console.log(`blocked_actions delta   ${blockedAdded.toLocaleString()} (expected ${expectedBlocked.toLocaleString()})`);
  console.log(`lossless under load     ${lossless}`);
  console.log("─".repeat(52));

  await cleanup();

  if (!lossless) {
    console.error("REGRESSION: counters lost updates under concurrent writers.");
    process.exit(1);
  }
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
