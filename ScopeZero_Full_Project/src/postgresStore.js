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
    await this.save();
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

  async recordDecision(verdict) {
    return this.withWriteLock(() => super.recordDecision(verdict));
  }

  async updateSessionRisk(sessionId, contribution, tenantId = "tenant_contoso") {
    return this.withWriteLock(() => super.updateSessionRisk(sessionId, contribution, tenantId));
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
      ALTER TABLE evidence_ledger ENABLE ROW LEVEL SECURITY;
      ALTER TABLE evidence_ledger FORCE ROW LEVEL SECURITY;
    `);
    for (const table of ["tenants", "agents", "missions", "approvals", "policies", "policy_versions"]) {
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
