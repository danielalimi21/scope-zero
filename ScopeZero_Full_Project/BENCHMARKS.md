# ScopeZero Benchmarks

Reproducible, no mocks. Run them yourself:

```bash
node tools/throughput-bench.js 20000     # persistence hot-path
node tools/concurrency-bench.js 20000    # lossless under concurrent writers
```

Both run a real SQLite `Store` + real hash-chained `Ledger`, driven through the
same code paths the gateway uses.

## What's measured

Every tool call writes three pieces of hot-path state — the agent behavior
profile, the session row (risk + ingest-taint), and decision metrics. These live
in row-keyed tables with atomic upserts, **not** in the full-state blob, so a call
never reserializes all state (and, in Postgres, never takes a global write lock).
The benches prove sustained throughput and that the blob is never rewritten on the
hot path.

## Reference numbers

Measured on a developer MacBook (Node v25, SQLite via `node:sqlite`). Indicative,
not a published SLA — re-run on your target hardware.

| Benchmark | Result |
|---|---|
| Hot-path writes/sec (`throughput-bench`, 20k, 256 agents) | ~23,600 writes/sec |
| Mean hot-path write latency | ~0.04 ms |
| State-blob rewrites on the hot path | **0** (hard invariant; CI gates on it) |
| Concurrent decisions/sec (`concurrency-bench`, 20k) | ~20,200 decisions/sec |
| Lossless under concurrent load | **true** (counters exactly match expected) |

## Honest scope

- These measure the **persistence + decision-accounting hot path**, not full
  `evaluateToolCall` end-to-end throughput. End-to-end is bounded by ledger fsync
  and, under a synthetic single-agent flood, by the burst guard correctly
  escalating to approval — neither is the persistence-scaling property here.
- **Multi-replica:** correctness-critical state (session risk, ingest-taint,
  metrics) is shared through the store — atomic upserts in SQLite, row-level
  atomic upserts under Postgres RLS — so concurrent replicas stay consistent. The
  in-process **decision cache is per-replica best-effort**: a cache miss simply
  re-evaluates the policy (no correctness impact), and the cache key includes
  classification, taint, and context so a stale entry is never reused across a
  changed input. A shared cache (Redis) can be wired via the cache seam if cross-
  replica cache hit-rate becomes the bottleneck; it is not required for
  correctness.
- Not yet measured in the open: sustained throughput against a managed Postgres,
  and end-to-end latency with a real OTLP exporter and external ledger anchor in
  the path. Those depend on the deployment and are pilot-stage measurements.

CI runs both benches on every push as a regression gate (`.github/workflows/scopezero-ci.yml`).
