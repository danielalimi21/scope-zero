// Background scheduler that periodically refreshes MCP server trust signals
// (OSV CVE lookups + time-based decay). Without this the registry only updates
// when an operator manually POSTs /v1/mcp/servers/:id/refresh, so a newly
// disclosed CVE in a trusted server would go unnoticed.
//
// Interval is configured via SCOPEZERO_MCP_REFRESH_INTERVAL_HOURS. Unset or 0
// disables the scheduler (refresh stays manual).

const MS_PER_HOUR = 60 * 60 * 1000;

export class McpRefreshScheduler {
  constructor({
    runtime,
    intervalHours = 0,
    fetchFn = undefined,
    logger = () => {},
    setIntervalFn = setInterval,
    clearIntervalFn = clearInterval
  }) {
    this.runtime = runtime;
    this.intervalMs = Math.max(0, Number(intervalHours || 0)) * MS_PER_HOUR;
    this.fetchFn = fetchFn;
    this.logger = logger;
    this.setIntervalFn = setIntervalFn;
    this.clearIntervalFn = clearIntervalFn;
    this.timer = null;
    this.running = false;
  }

  get enabled() {
    return this.intervalMs > 0;
  }

  start() {
    if (!this.enabled || this.timer) {
      return false;
    }
    this.timer = this.setIntervalFn(() => {
      this.runOnce().catch((error) => this.logger(`mcp_refresh_failed: ${error.message}`));
    }, this.intervalMs);
    // Don't keep the process alive solely for the refresh timer.
    this.timer?.unref?.();
    return true;
  }

  stop() {
    if (this.timer) {
      this.clearIntervalFn(this.timer);
      this.timer = null;
    }
  }

  // Guarded so a slow OSV refresh can't overlap with the next tick.
  async runOnce() {
    if (this.running) {
      return { skipped: "already_running" };
    }
    this.running = true;
    try {
      const summary = await this.runtime.refreshAllMcpServers({ fetchFn: this.fetchFn });
      this.logger(`mcp_refresh_complete: ${summary.candidates} server(s) refreshed`);
      return summary;
    } finally {
      this.running = false;
    }
  }
}

export function createMcpRefreshSchedulerFromEnv(runtime, env = process.env, overrides = {}) {
  return new McpRefreshScheduler({
    runtime,
    intervalHours: Number(env.SCOPEZERO_MCP_REFRESH_INTERVAL_HOURS || 0),
    ...overrides
  });
}
