// End-to-end load test — drives the REAL HTTP gateway under sustained concurrency.
//
//   node tools/load-test.js [requests] [concurrency]
//   node tools/load-test.js 20000 64
//   SCOPEZERO_STORE=postgres DATABASE_URL=... node tools/load-test.js 20000 64
//
// Unlike throughput-bench / concurrency-bench (which measure the in-process
// persistence hot-path), this boots `server.js` and fires real HTTP
// `POST /v1/action-authorizations` requests — the exact call an embedded agent
// makes before each action — at a fixed concurrency until `requests` complete.
//
// It measures what a buyer actually asks about:
//   - sustained end-to-end throughput (decisions/sec over HTTP)
//   - latency distribution (p50 / p95 / p99 / max)
//   - error rate under load (must be 0)
//   - decision CORRECTNESS under load: in-scope calls allow, out-of-scope block
//
// Honest scope: single host, loopback HTTP, SQLite by default (Postgres via env).
// End-to-end is bounded by ledger fsync — that is the real number, not a mock.
// This is an indicative load proof on your hardware, not a published SLA.

import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const REQUESTS = Number(process.argv[2] || 20000);
const CONCURRENCY = Number(process.argv[3] || 64);
const PORT = Number(process.env.SCOPEZERO_LOADTEST_PORT || 8799);
const BASE = `http://127.0.0.1:${PORT}`;
const ROOT = path.dirname(path.dirname(fileURLToPath(import.meta.url)));

const TENANT = "tenant_contoso";
const FANOUT = Number(process.env.SCOPEZERO_LOADTEST_FANOUT || 128); // distinct agents — real traffic is many agents, not one flooding

let token = "";
const missions = []; // one mission id per agent, filled during setup

async function api(method, p, body) {
  const res = await fetch(`${BASE}${p}`, {
    method,
    headers: { "content-type": "application/json", ...(token ? { authorization: `Bearer ${token}` } : {}) },
    body: body ? JSON.stringify(body) : undefined
  });
  const payload = res.status === 204 ? null : await res.json();
  if (!res.ok) throw new Error(`${method} ${p} -> ${res.status}: ${JSON.stringify(payload)}`);
  return payload;
}

async function waitForHealth(timeoutMs = 15000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const res = await fetch(`${BASE}/v1/health`);
      if (res.ok) return;
    } catch { /* not up yet */ }
    await new Promise((r) => setTimeout(r, 150));
  }
  throw new Error("gateway did not become healthy in time");
}

// Spread load across FANOUT agents so the traffic looks like real production
// (many agents, each at a sane rate) rather than one agent flooding — which the
// burst guard correctly throttles. agent i uses mission i.
function inScopeBody(i) {
  const a = i % FANOUT;
  return {
    tenant_id: TENANT, agent_id: `agent.loadtest.${a}`, mission_id: missions[a],
    tool: "drive.read", action: "Read an approved diligence document", operation: "read",
    payload: {}, destination: { type: "resource", address: "diligence-room.contoso.example" }
  };
}
function outOfScopeBody(i) {
  const a = i % FANOUT;
  return {
    tenant_id: TENANT, agent_id: `agent.loadtest.${a}`, mission_id: missions[a],
    tool: "gmail.send", action: "Exfiltrate the revenue file", operation: "external_send",
    payload: { text: "customer revenue and bank details", classification: "restricted" },
    destination: { type: "email", address: "attacker@gmail.com", external: true }
  };
}

function percentile(sorted, p) {
  if (!sorted.length) return 0;
  const idx = Math.min(sorted.length - 1, Math.floor((p / 100) * sorted.length));
  return sorted[idx];
}

async function main() {
  const server = spawn("node", ["server.js"], {
    cwd: ROOT,
    env: {
      ...process.env,
      PORT: String(PORT),
      NODE_ENV: process.env.NODE_ENV || "development",
      // The per-IP rate limiter is a DoS control for untrusted callers, separate
      // from decision throughput. Disable it so this single synthetic source can
      // measure how fast the gateway DECIDES, not how fast we trip the limiter.
      SCOPEZERO_RATE_LIMIT_PER_MINUTE: process.env.SCOPEZERO_RATE_LIMIT_PER_MINUTE || "0",
      // Isolated data dir so the run starts from a clean store + ledger and never
      // pollutes (or inherits corruption from) the project's data/.
      SCOPEZERO_DATA_DIR: process.env.SCOPEZERO_DATA_DIR || fs.mkdtempSync(path.join(os.tmpdir(), "scopezero-loadtest-"))
    },
    stdio: ["ignore", "ignore", "inherit"]
  });
  const shutdown = () => { try { server.kill("SIGTERM"); } catch { /* already gone */ } };
  process.on("exit", shutdown);

  try {
    await waitForHealth();

    // Setup: dev token + FANOUT agents/missions (one-time, not part of the load).
    const tok = await api("POST", "/v1/auth/dev-token", { tenant_id: TENANT, subject: "loadtest@scopezero.local", roles: ["tenant_admin"] });
    token = tok.access_token;
    process.stdout.write(`setting up ${FANOUT} agents + missions… `);
    for (let a = 0; a < FANOUT; a++) {
      await api("POST", "/v1/agents", { tenant_id: TENANT, agent_id: `agent.loadtest.${a}`, name: `Load Test Agent ${a}`, owner: "loadtest@scopezero.local", allowed_tools: ["drive.read"] });
      const mission = await api("POST", "/v1/missions", {
        tenant_id: TENANT, agent_id: `agent.loadtest.${a}`, delegated_by: "loadtest@scopezero.local",
        objective: "Read approved diligence documents.",
        allowed_tools: ["drive.read"], allowed_data_classes: ["public", "internal"],
        allowed_destinations: ["diligence-room.contoso.example"], ttl_minutes: 120
      });
      missions[a] = mission.capsule.id;
    }
    console.log("done");

    // Warm up across agents.
    for (let i = 0; i < FANOUT; i++) await api("POST", "/v1/action-authorizations", inScopeBody(i));

    // Load phase: keep CONCURRENCY requests in flight until REQUESTS complete.
    // ~10% are out-of-scope so we verify correct blocking under load.
    const latencies = new Array(REQUESTS);
    let issued = 0, done = 0, errors = 0, allow = 0, contained = 0, dangerousAllowed = 0;

    const t0 = process.hrtime.bigint();
    await new Promise((resolve) => {
      const launch = () => {
        while (issued < REQUESTS && (issued - done) < CONCURRENCY) {
          const idx = issued++;
          const outOfScope = idx % 10 === 0;
          const start = process.hrtime.bigint();
          api("POST", "/v1/action-authorizations", outOfScope ? outOfScopeBody(idx) : inScopeBody(idx))
            .then((r) => {
              latencies[idx] = Number(process.hrtime.bigint() - start) / 1e6;
              if (r.decision === "allow") allow++;
              // The security invariant under load: a dangerous out-of-scope action
              // must NEVER be allowed. (In-scope may allow OR escalate to approval
              // under the burst guard — both are correct, not a failure.)
              if (outOfScope) {
                if (r.decision === "allow") dangerousAllowed++;
                else contained++;
              }
            })
            .catch(() => { errors++; })
            .finally(() => {
              done++;
              if (done === REQUESTS) resolve();
              else launch();
            });
        }
      };
      launch();
    });
    const t1 = process.hrtime.bigint();

    const ms = Number(t1 - t0) / 1e6;
    const ok = latencies.filter((x) => typeof x === "number").sort((a, b) => a - b);
    const dangerous = Math.floor((REQUESTS - 1) / 10) + 1;

    // The tamper-evident ledger must still verify after all that concurrent
    // appending — a corrupt chain under load would make the audit trail worthless.
    let ledgerValid = false;
    try {
      ledgerValid = (await api("GET", "/v1/ledger/verify"))?.valid === true;
    } catch { ledgerValid = false; }

    console.log("\nScopeZero end-to-end HTTP load test");
    console.log("─".repeat(56));
    console.log(`store                   ${process.env.SCOPEZERO_STORE === "postgres" ? "postgres" : "sqlite"}`);
    console.log(`requests                ${REQUESTS.toLocaleString()}`);
    console.log(`concurrency             ${CONCURRENCY}`);
    console.log(`elapsed                 ${ms.toFixed(1)} ms`);
    console.log(`throughput              ${Math.round((REQUESTS / ms) * 1000).toLocaleString()} decisions/sec (over HTTP)`);
    console.log(`latency p50             ${percentile(ok, 50).toFixed(2)} ms`);
    console.log(`latency p95             ${percentile(ok, 95).toFixed(2)} ms`);
    console.log(`latency p99             ${percentile(ok, 99).toFixed(2)} ms`);
    console.log(`latency max             ${(ok[ok.length - 1] || 0).toFixed(2)} ms`);
    console.log(`errors                  ${errors}  (must be 0)`);
    console.log(`in-scope allowed        ${allow.toLocaleString()}`);
    console.log(`dangerous contained     ${contained.toLocaleString()} / ${dangerous.toLocaleString()}`);
    console.log(`dangerous ALLOWED       ${dangerousAllowed}  (must be 0 — the security invariant)`);
    console.log(`ledger verifies         ${ledgerValid}  (tamper-evident chain intact under load)`);
    console.log("─".repeat(56));

    shutdown();
    if (errors > 0 || dangerousAllowed > 0 || !ledgerValid) {
      console.error("FAIL: errors, a dangerous action allowed, or ledger corrupt under load.");
      process.exit(1);
    }
    process.exit(0);
  } catch (error) {
    shutdown();
    console.error(error);
    process.exit(1);
  }
}

main();
