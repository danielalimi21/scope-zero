import test from "node:test";
import assert from "node:assert/strict";
import { McpRefreshScheduler, createMcpRefreshSchedulerFromEnv } from "../src/mcpRefreshScheduler.js";
import { ScopeZeroRuntime } from "../src/runtime.js";

test("refreshAllMcpServers only refreshes servers with a package_name", async () => {
  const refreshed = [];
  const servers = [
    { server_id: "with-pkg", tenant_id: null, package_name: "@scope/pkg", package_ecosystem: "npm" },
    { server_id: "no-pkg", tenant_id: null, package_name: null },
    { server_id: "tenant-pkg", tenant_id: "tenant_contoso", package_name: "@scope/other", package_ecosystem: "npm" }
  ];

  // Fake fetch returns one CVE so we can confirm fetchFn is threaded through.
  const fetchFn = async () => ({
    ok: true,
    json: async () => ({ vulns: [{ id: "GHSA-xxxx", summary: "test" }] })
  });

  const runtime = new ScopeZeroRuntime({
    signingSecret: "s",
    ledger: { async append(record) { return { id: "e", hash: "h", record }; } },
    store: {
      listAllMcpServers() {
        return servers;
      },
      getMcpServer(id, tenantId) {
        return servers.find((s) => s.server_id === id && (s.tenant_id ?? null) === (tenantId ?? null));
      },
      async upsertMcpServer(server) {
        refreshed.push(server.server_id);
        return server;
      }
    }
  });

  const summary = await runtime.refreshAllMcpServers({ fetchFn });

  assert.equal(summary.candidates, 2, "only the two package_name servers are candidates");
  assert.deepEqual(refreshed.sort(), ["tenant-pkg", "with-pkg"]);
  assert.ok(summary.results.every((r) => r.signal_summary === "cve_found"));
});

test("scheduler is disabled when interval hours is 0", () => {
  const scheduler = new McpRefreshScheduler({ runtime: {}, intervalHours: 0 });
  assert.equal(scheduler.enabled, false);
  assert.equal(scheduler.start(), false);
});

test("scheduler runs refreshAllMcpServers on its interval", async () => {
  let registeredMs = null;
  let capturedCallback = null;
  const calls = [];

  const runtime = {
    async refreshAllMcpServers(opts) {
      calls.push(opts);
      return { candidates: 3, results: [] };
    }
  };

  const scheduler = new McpRefreshScheduler({
    runtime,
    intervalHours: 6,
    fetchFn: "fetch-sentinel",
    setIntervalFn: (cb, ms) => {
      capturedCallback = cb;
      registeredMs = ms;
      return { unref() {} };
    },
    clearIntervalFn: () => {}
  });

  assert.equal(scheduler.enabled, true);
  assert.equal(scheduler.start(), true);
  assert.equal(registeredMs, 6 * 60 * 60 * 1000, "interval derived from hours");

  // Fire the timer callback as the runtime would, then let runOnce settle.
  capturedCallback();
  await new Promise((resolve) => setImmediate(resolve));

  assert.equal(calls.length, 1);
  assert.equal(calls[0].fetchFn, "fetch-sentinel", "fetchFn threaded into refresh");
});

test("createMcpRefreshSchedulerFromEnv reads SCOPEZERO_MCP_REFRESH_INTERVAL_HOURS", () => {
  const enabled = createMcpRefreshSchedulerFromEnv({}, { SCOPEZERO_MCP_REFRESH_INTERVAL_HOURS: "12" });
  assert.equal(enabled.enabled, true);
  assert.equal(enabled.intervalMs, 12 * 60 * 60 * 1000);

  const disabled = createMcpRefreshSchedulerFromEnv({}, {});
  assert.equal(disabled.enabled, false);
});
