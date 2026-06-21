# ScopeZero Benchmarks

Reproducible, no mocks. Run them yourself:

```bash
node tools/throughput-bench.js 20000     # persistence hot-path (in-process)
node tools/concurrency-bench.js 20000    # lossless under concurrent writers
node tools/load-test.js 10000 64         # end-to-end HTTP decisions under load
```

The first two run a real SQLite `Store` + real hash-chained `Ledger`, driven
through the same code paths the gateway uses. `load-test.js` boots the real
`server.js` and fires concurrent `POST /v1/action-authorizations` requests — the
exact call an embedded agent makes before each action — measuring end-to-end
throughput, latency distribution, and decision correctness under load.

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

## End-to-end HTTP load (`load-test.js`)

Real `server.js`, real HTTP, SQLite, 200 agents/missions, 10k requests at
concurrency 64 on the same MacBook:

| Metric | Result |
|---|---|
| Throughput | ~1,360 decisions/sec (over HTTP) |
| Latency p50 / p95 / p99 | ~46 / ~58 / ~66 ms |
| Errors under load | **0** |
| Dangerous (out-of-scope) actions allowed | **0** — the security invariant holds under load |
| Scaling | **linear** — throughput held at 5× the request count, no degradation |

### Fix: collection writes were O(n²)

The first end-to-end load run exposed a real bottleneck the in-process benches
hid: every write to a mirrored collection (agents/missions/**approvals**/policies)
went through a `save()` that re-serialized the entire state blob **and**
rebuilt the whole mirror table (DELETE-all + INSERT-all). Creating the *n*-th
approval cost O(n), so an approval-heavy workload degraded quadratically
(measured: ~4 decisions/sec, p50 ~7 s, climbing to 30 s). The hot-path counters
had already been moved off this path; the collection writes had not.

The fix: mirror tables are now authoritative and written one row per change
(`INSERT … ON CONFLICT DO UPDATE`); the blob carries only the small non-mirrored
singletons. Result above — **~340× throughput, ~150× lower p50**, and flat
latency across the run. (The Postgres store still carries the pre-fix write path;
applying the same incremental writes there is a tracked follow-up that needs a
live Postgres environment to verify multi-replica consistency.)

## Honest scope

- `throughput-bench` / `concurrency-bench` measure the **persistence +
  decision-accounting hot path** in-process; `load-test.js` measures the full
  **end-to-end** `evaluateToolCall` over HTTP (see the table above). End-to-end is
  bounded by ledger fsync and, under a synthetic single-agent flood, by the burst
  guard correctly escalating to approval — so the load test fans out across many
  agents (real traffic shape) and disables the per-IP DoS rate limiter to isolate
  decision throughput.
- **Multi-replica:** correctness-critical state (session risk, ingest-taint,
  metrics) is shared through the store — atomic upserts in SQLite, row-level
  atomic upserts under Postgres RLS — so concurrent replicas stay consistent. The
  in-process **decision cache is per-replica best-effort**: a cache miss simply
  re-evaluates the policy (no correctness impact), and the cache key includes
  classification, taint, and context so a stale entry is never reused across a
  changed input. A shared cache (Redis) can be wired via the cache seam if cross-
  replica cache hit-rate becomes the bottleneck; it is not required for
  correctness.
- Measured on a single host over loopback HTTP with SQLite — indicative on your
  hardware, not a published SLA or a datacenter result. Not yet measured in the
  open: sustained throughput against a managed Postgres (the Postgres store still
  has the pre-fix collection-write path), and end-to-end latency with a real OTLP
  exporter and external ledger anchor in the path. Those depend on the deployment
  and are pilot-stage measurements.

CI runs both benches on every push as a regression gate (`.github/workflows/scopezero-ci.yml`).
