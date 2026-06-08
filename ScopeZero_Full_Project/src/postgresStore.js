import { Store } from "./store.js";

export class PostgresStore extends Store {
  constructor({ connectionString, defaultPolicy }) {
    super("postgres://scopezero", defaultPolicy);
    this.connectionString = connectionString;
    this.pool = null;
    this.transactionDepth = 0;
  }

  async init() {
    if (!this.connectionString) {
      throw new Error("DATABASE_URL is required when SCOPEZERO_STORE=postgres.");
    }
    const { Pool } = await import("pg");
    this.pool = new Pool({
      connectionString: this.connectionString,
      ssl: process.env.PGSSLMODE === "disable" ? false : { rejectUnauthorized: process.env.PGSSL_REJECT_UNAUTHORIZED === "true" }
    });
    await this.migrate();
    const result = await this.pool.query("SELECT body FROM scopezero_state WHERE id = $1", ["primary"]);
    this.state = result.rows[0]?.body || createEmptyState(this.defaultPolicy);
    await this.migrateHotPathState();
    await this.save();
  }

  // Lift any legacy blob-resident hot-path state into the dedicated tables, then
  // drop it from the blob so it is not re-persisted. Mirrors the SQLite store.
  async migrateHotPathState() {
    for (const profile of Object.values(this.state.behavior_profiles || {})) {
      if (profile?.tenant_id && profile?.agent_id) {
        await this.recordToolCall(profile.tenant_id, profile.agent_id, null, profile);
      }
    }
    for (const session of Object.values(this.state.sessions || {})) {
      if (session?.tenant_id && session?.session_id) {
        await this.withTenant(session.tenant_id, (client) =>
          client.query(
            `INSERT INTO sessions (tenant_id, session_id, risk_consumed, updated_at)
             VALUES ($1, $2, $3, now())
             ON CONFLICT (tenant_id, session_id) DO UPDATE SET risk_consumed = excluded.risk_consumed, updated_at = now()`,
            [session.tenant_id, session.session_id, Number(session.risk_consumed || 0)]
          )
        );
      }
    }
    for (const [name, value] of Object.entries(this.state.metrics || {})) {
      await this.pool.query(
        `INSERT INTO metrics (name, value) VALUES ($1, $2)
         ON CONFLICT (name) DO UPDATE SET value = excluded.value`,
        [name, Number(value) || 0]
      );
    }
    delete this.state.behavior_profiles;
    delete this.state.sessions;
    delete this.state.metrics;
  }

  // ── Hot path: per-row, off the global write lock ────────────────────────────
  // Behavior profiles and session risk are written on every tool call. Routing
  // them through withWriteLock (full-state read-modify-write under one advisory
  // lock) would cap the whole gateway to single-writer throughput. These are
  // per-agent / per-session independent rows, so atomic upserts let concurrent
  // evaluations proceed in parallel. Each runs in its own short transaction that
  // sets the tenant GUC so row-level security stays enforced (FORCE RLS) — no
  // global lock, just a per-row write scoped to the caller's tenant.

  async withTenant(tenantId, fn) {
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      await client.query("SELECT set_config('scopezero.tenant_id', $1, true)", [String(tenantId ?? "*")]);
      const result = await fn(client);
      await client.query("COMMIT");
      return result;
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally {
      client.release();
    }
  }

  async getBehaviorProfile(tenantId, agentId) {
    return this.withTenant(tenantId, async (client) => {
      const result = await client.query(
        "SELECT body FROM behavior_profiles WHERE tenant_id = $1 AND agent_id = $2",
        [tenantId, agentId]
      );
      return result.rows[0]?.body || null;
    });
  }

  async recordToolCall(tenantId, agentId, toolKey, profile) {
    return this.withTenant(tenantId, (client) =>
      client.query(
        `INSERT INTO behavior_profiles (tenant_id, agent_id, body, updated_at)
         VALUES ($1, $2, $3::jsonb, now())
         ON CONFLICT (tenant_id, agent_id) DO UPDATE SET body = excluded.body, updated_at = now()`,
        [tenantId, agentId, JSON.stringify(profile)]
      )
    );
  }

  async getSessionRisk(sessionId, tenantId = "tenant_contoso") {
    return this.withTenant(tenantId, async (client) => {
      const result = await client.query(
        "SELECT risk_consumed FROM sessions WHERE tenant_id = $1 AND session_id = $2",
        [tenantId, sessionId]
      );
      return result.rows[0]?.risk_consumed || 0;
    });
  }

  async updateSessionRisk(sessionId, contribution, tenantId = "tenant_contoso") {
    const delta = Number(contribution || 0);
    return this.withTenant(tenantId, async (client) => {
      const result = await client.query(
        `INSERT INTO sessions (tenant_id, session_id, risk_consumed, updated_at)
         VALUES ($1, $2, LEAST(100, $3), now())
         ON CONFLICT (tenant_id, session_id)
         DO UPDATE SET risk_consumed = LEAST(100, sessions.risk_consumed + $4), updated_at = now()
         RETURNING risk_consumed`,
        [tenantId, sessionId, Math.min(100, delta), delta]
      );
      return result.rows[0].risk_consumed;
    });
  }

  async getSessionIngestedClass(sessionId, tenantId = "tenant_contoso") {
    return this.withTenant(tenantId, async (client) => {
      const result = await client.query(
        "SELECT ingested_class_rank FROM sessions WHERE tenant_id = $1 AND session_id = $2",
        [tenantId, sessionId]
      );
      return result.rows[0]?.ingested_class_rank || 0;
    });
  }

  async updateSessionIngestedClass(sessionId, classRank, tenantId = "tenant_contoso") {
    const rank = Number(classRank || 0);
    return this.withTenant(tenantId, async (client) => {
      const result = await client.query(
        `INSERT INTO sessions (tenant_id, session_id, ingested_class_rank, updated_at)
         VALUES ($1, $2, $3, now())
         ON CONFLICT (tenant_id, session_id)
         DO UPDATE SET ingested_class_rank = GREATEST(sessions.ingested_class_rank, $3), updated_at = now()
         RETURNING ingested_class_rank`,
        [tenantId, sessionId, rank]
      );
      return result.rows[0].ingested_class_rank;
    });
  }

  async getAllSessions() {
    return this.withTenant("*", async (client) => {
      const result = await client.query("SELECT tenant_id, session_id, risk_consumed, ingested_class_rank FROM sessions");
      return Object.fromEntries(
        result.rows.map((row) => [
          `${row.tenant_id}:${row.session_id}`,
          { tenant_id: row.tenant_id, session_id: row.session_id, risk_consumed: row.risk_consumed, ingested_class_rank: row.ingested_class_rank }
        ])
      );
    });
  }

  async getAllBehaviorProfiles() {
    return this.withTenant("*", async (client) => {
      const result = await client.query("SELECT body FROM behavior_profiles");
      return Object.fromEntries(result.rows.map((row) => [`${row.body.tenant_id}:${row.body.agent_id}`, row.body]));
    });
  }

  async recordDecision(verdict) {
    const counters = ["runtime_decisions", "evidence_capsules"];
    if (verdict.decision === "block") counters.push("blocked_actions");
    else if (verdict.decision === "approval") counters.push("approvals_required");
    else if (verdict.decision === "redact") counters.push("redactions");
    else if (verdict.decision === "quarantine_context") counters.push("quarantined_contexts");
    for (const name of counters) {
      await this.pool.query(
        "INSERT INTO metrics (name, value) VALUES ($1, 1) ON CONFLICT (name) DO UPDATE SET value = metrics.value + 1",
        [name]
      );
    }
  }

  async getMetrics() {
    const metrics = { runtime_decisions: 0, blocked_actions: 0, approvals_required: 0, redactions: 0, quarantined_contexts: 0, evidence_capsules: 0 };
    const result = await this.pool.query("SELECT name, value FROM metrics");
    for (const row of result.rows) metrics[row.name] = Number(row.value);
    return metrics;
  }

  async migrate() {
    await this.pool.query(`
      CREATE TABLE IF NOT EXISTS tenants (
        tenant_id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        plan TEXT NOT NULL,
        body JSONB NOT NULL,
        updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
      );
      CREATE TABLE IF NOT EXISTS agents (
        tenant_id TEXT NOT NULL REFERENCES tenants(tenant_id),
        agent_id TEXT NOT NULL,
        owner TEXT NOT NULL,
        status TEXT NOT NULL,
        body JSONB NOT NULL,
        updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        PRIMARY KEY (tenant_id, agent_id)
      );
      CREATE TABLE IF NOT EXISTS missions (
        id TEXT PRIMARY KEY,
        tenant_id TEXT NOT NULL REFERENCES tenants(tenant_id),
        agent_id TEXT NOT NULL,
        status TEXT NOT NULL,
        body JSONB NOT NULL,
        updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
      );
      CREATE TABLE IF NOT EXISTS approvals (
        id TEXT PRIMARY KEY,
        tenant_id TEXT NOT NULL REFERENCES tenants(tenant_id),
        agent_id TEXT NOT NULL,
        status TEXT NOT NULL,
        body JSONB NOT NULL,
        updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
      );
      CREATE TABLE IF NOT EXISTS policies (
        tenant_id TEXT PRIMARY KEY REFERENCES tenants(tenant_id),
        body JSONB NOT NULL,
        updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
      );
      CREATE TABLE IF NOT EXISTS policy_versions (
        id TEXT PRIMARY KEY,
        tenant_id TEXT NOT NULL REFERENCES tenants(tenant_id),
        version INTEGER NOT NULL,
        status TEXT NOT NULL,
        body JSONB NOT NULL,
        created_at TIMESTAMPTZ NOT NULL,
        approved_at TIMESTAMPTZ
      );
      CREATE TABLE IF NOT EXISTS scopezero_state (
        id TEXT PRIMARY KEY,
        body JSONB NOT NULL,
        updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
      );
      CREATE TABLE IF NOT EXISTS behavior_profiles (
        tenant_id TEXT NOT NULL,
        agent_id TEXT NOT NULL,
        body JSONB NOT NULL,
        updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        PRIMARY KEY (tenant_id, agent_id)
      );
      CREATE TABLE IF NOT EXISTS sessions (
        tenant_id TEXT NOT NULL,
        session_id TEXT NOT NULL,
        risk_consumed DOUBLE PRECISION NOT NULL DEFAULT 0,
        ingested_class_rank DOUBLE PRECISION NOT NULL DEFAULT 0,
        updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        PRIMARY KEY (tenant_id, session_id)
      );
      ALTER TABLE sessions ADD COLUMN IF NOT EXISTS ingested_class_rank DOUBLE PRECISION NOT NULL DEFAULT 0;
      CREATE TABLE IF NOT EXISTS metrics (
        name TEXT PRIMARY KEY,
        value BIGINT NOT NULL DEFAULT 0
      );
      CREATE TABLE IF NOT EXISTS scopezero_write_locks (
        id TEXT PRIMARY KEY,
        updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
      );
      CREATE TABLE IF NOT EXISTS evidence_ledger (
        id TEXT PRIMARY KEY,
        time TIMESTAMPTZ NOT NULL,
        tenant_id TEXT,
        event_type TEXT NOT NULL,
        previous_hash TEXT NOT NULL,
        hash TEXT NOT NULL,
        record JSONB NOT NULL
      );
      CREATE INDEX IF NOT EXISTS evidence_ledger_tenant_time_idx ON evidence_ledger (tenant_id, time DESC);
      CREATE INDEX IF NOT EXISTS missions_tenant_agent_idx ON missions (tenant_id, agent_id);
      CREATE INDEX IF NOT EXISTS approvals_tenant_status_idx ON approvals (tenant_id, status);
      CREATE INDEX IF NOT EXISTS policy_versions_tenant_version_idx ON policy_versions (tenant_id, version DESC);
      INSERT INTO scopezero_write_locks (id) VALUES ('primary')
      ON CONFLICT (id) DO NOTHING;
    `);
    await this.enableTenantRls();
  }

  async refresh() {
    const result = await this.pool.query("SELECT body FROM scopezero_state WHERE id = $1", ["primary"]);
    this.state = result.rows[0]?.body || this.state || createEmptyState(this.defaultPolicy);
    return this.state;
  }

  async save() {
    if (this.transactionDepth > 0) {
      return;
    }
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      await this.writeState(client);
      await this.syncRelationalTables(client);
      await client.query("COMMIT");
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally {
      client.release();
    }
  }

  async withWriteLock(fn) {
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      this.transactionDepth += 1;
      await client.query("SELECT id FROM scopezero_write_locks WHERE id = $1 FOR UPDATE", ["primary"]);
      const result = await client.query("SELECT body FROM scopezero_state WHERE id = $1", ["primary"]);
      this.state = result.rows[0]?.body || createEmptyState(this.defaultPolicy);
      const value = await fn();
      await this.writeState(client);
      await this.syncRelationalTables(client);
      await client.query("COMMIT");
      return value;
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally {
      this.transactionDepth = Math.max(0, this.transactionDepth - 1);
      client.release();
    }
  }

  async setPolicy(tenantId, policyPatch) {
    return this.withWriteLock(() => super.setPolicy(tenantId, policyPatch));
  }

  async proposePolicy(tenantId, policyPatch, proposedBy) {
    return this.withWriteLock(() => super.proposePolicy(tenantId, policyPatch, proposedBy));
  }

  async reviewPolicyProposal(proposalId, decision, reviewer, tenantId = null) {
    return this.withWriteLock(() => super.reviewPolicyProposal(proposalId, decision, reviewer, tenantId));
  }

  async upsertAgent(agent) {
    return this.withWriteLock(() => super.upsertAgent(agent));
  }

  async addMission(capsule) {
    return this.withWriteLock(() => super.addMission(capsule));
  }

  async addApproval(approval) {
    return this.withWriteLock(() => super.addApproval(approval));
  }

  async updateApproval(approvalId, patch, tenantId = null) {
    return this.withWriteLock(() => super.updateApproval(approvalId, patch, tenantId));
  }

  async enableTenantRls() {
    await this.pool.query(`
      ALTER TABLE tenants ENABLE ROW LEVEL SECURITY;
      ALTER TABLE tenants FORCE ROW LEVEL SECURITY;
      ALTER TABLE agents ENABLE ROW LEVEL SECURITY;
      ALTER TABLE agents FORCE ROW LEVEL SECURITY;
      ALTER TABLE missions ENABLE ROW LEVEL SECURITY;
      ALTER TABLE missions FORCE ROW LEVEL SECURITY;
      ALTER TABLE approvals ENABLE ROW LEVEL SECURITY;
      ALTER TABLE approvals FORCE ROW LEVEL SECURITY;
      ALTER TABLE policies ENABLE ROW LEVEL SECURITY;
      ALTER TABLE policies FORCE ROW LEVEL SECURITY;
      ALTER TABLE policy_versions ENABLE ROW LEVEL SECURITY;
      ALTER TABLE policy_versions FORCE ROW LEVEL SECURITY;
      ALTER TABLE behavior_profiles ENABLE ROW LEVEL SECURITY;
      ALTER TABLE behavior_profiles FORCE ROW LEVEL SECURITY;
      ALTER TABLE sessions ENABLE ROW LEVEL SECURITY;
      ALTER TABLE sessions FORCE ROW LEVEL SECURITY;
      ALTER TABLE evidence_ledger ENABLE ROW LEVEL SECURITY;
      ALTER TABLE evidence_ledger FORCE ROW LEVEL SECURITY;
    `);
    for (const table of ["tenants", "agents", "missions", "approvals", "policies", "policy_versions", "behavior_profiles", "sessions"]) {
      await this.pool.query(`
        DROP POLICY IF EXISTS ${table}_scopezero_tenant_isolation ON ${table};
        CREATE POLICY ${table}_scopezero_tenant_isolation ON ${table}
          USING (tenant_id = current_setting('scopezero.tenant_id', true) OR current_setting('scopezero.tenant_id', true) = '*')
          WITH CHECK (tenant_id = current_setting('scopezero.tenant_id', true) OR current_setting('scopezero.tenant_id', true) = '*');
      `);
    }
    await this.pool.query(`
      DROP POLICY IF EXISTS evidence_ledger_scopezero_tenant_isolation ON evidence_ledger;
      CREATE POLICY evidence_ledger_scopezero_tenant_isolation ON evidence_ledger
        USING (tenant_id = current_setting('scopezero.tenant_id', true) OR current_setting('scopezero.tenant_id', true) = '*' OR tenant_id IS NULL)
        WITH CHECK (tenant_id = current_setting('scopezero.tenant_id', true) OR current_setting('scopezero.tenant_id', true) = '*' OR tenant_id IS NULL);
    `);
  }

  async writeState(client) {
    await client.query(
      `INSERT INTO scopezero_state (id, body, updated_at)
       VALUES ($1, $2::jsonb, now())
       ON CONFLICT (id) DO UPDATE SET body = excluded.body, updated_at = now()`,
      ["primary", JSON.stringify(this.state || createEmptyState(this.defaultPolicy))]
    );
  }

  async syncRelationalTables(client) {
    const state = this.state || createEmptyState(this.defaultPolicy);
    await client.query("SET LOCAL scopezero.tenant_id = '*'");
    await client.query("DELETE FROM policy_versions");
    await client.query("DELETE FROM approvals");
    await client.query("DELETE FROM missions");
    await client.query("DELETE FROM agents");
    await client.query("DELETE FROM policies");
    await client.query("DELETE FROM tenants");

    for (const tenant of state.tenants || []) {
      await client.query(
        `INSERT INTO tenants (tenant_id, name, plan, body, updated_at)
         VALUES ($1, $2, $3, $4::jsonb, now())`,
        [tenant.tenant_id, tenant.name, tenant.plan, JSON.stringify(tenant)]
      );
    }
    for (const agent of state.agents || []) {
      await client.query(
        `INSERT INTO agents (tenant_id, agent_id, owner, status, body, updated_at)
         VALUES ($1, $2, $3, $4, $5::jsonb, now())`,
        [agent.tenant_id, agent.agent_id, agent.owner, agent.status, JSON.stringify(agent)]
      );
    }
    for (const mission of state.missions || []) {
      await client.query(
        `INSERT INTO missions (id, tenant_id, agent_id, status, body, updated_at)
         VALUES ($1, $2, $3, $4, $5::jsonb, now())`,
        [mission.id, mission.tenant_id, mission.agent_id, mission.status, JSON.stringify(mission)]
      );
    }
    for (const approval of state.approvals || []) {
      await client.query(
        `INSERT INTO approvals (id, tenant_id, agent_id, status, body, updated_at)
         VALUES ($1, $2, $3, $4, $5::jsonb, now())`,
        [approval.id, approval.tenant_id, approval.agent_id, approval.status, JSON.stringify(approval)]
      );
    }
    for (const [tenantId, policy] of Object.entries(state.policies || {})) {
      await client.query(
        `INSERT INTO policies (tenant_id, body, updated_at)
         VALUES ($1, $2::jsonb, now())`,
        [tenantId, JSON.stringify(policy)]
      );
    }
    for (const version of state.policy_versions || []) {
      await client.query(
        `INSERT INTO policy_versions (id, tenant_id, version, status, body, created_at, approved_at)
         VALUES ($1, $2, $3, $4, $5::jsonb, $6, $7)`,
        [
          version.id,
          version.tenant_id,
          Number(version.version || 0),
          version.status,
          JSON.stringify(version),
          version.created_at,
          version.approved_at || version.reviewed_at || null
        ]
      );
    }
  }
}

function createEmptyState(defaultPolicy) {
  return {
    tenants: [{ tenant_id: "tenant_contoso", name: "Contoso Holdings", plan: "enterprise" }],
    agents: [],
    missions: [],
    approvals: [],
    policy_versions: [],
    sessions: {},
    policies: { tenant_contoso: defaultPolicy },
    metrics: {
      runtime_decisions: 0,
      blocked_actions: 0,
      approvals_required: 0,
      redactions: 0,
      quarantined_contexts: 0,
      evidence_capsules: 0
    }
  };
}
