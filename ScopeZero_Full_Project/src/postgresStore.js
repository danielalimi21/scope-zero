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
      CREATE TABLE IF NOT EXISTS scopezero_state (
        id TEXT PRIMARY KEY,
        body JSONB NOT NULL,
        updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
      );
      CREATE TABLE IF NOT EXISTS scopezero_write_locks (
        id TEXT PRIMARY KEY,
        updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
      );
      INSERT INTO scopezero_write_locks (id) VALUES ('primary')
      ON CONFLICT (id) DO NOTHING;
    `);
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
    await this.pool.query(
      `INSERT INTO scopezero_state (id, body, updated_at)
       VALUES ($1, $2::jsonb, now())
       ON CONFLICT (id) DO UPDATE SET body = excluded.body, updated_at = now()`,
      ["primary", JSON.stringify(this.state || createEmptyState(this.defaultPolicy))]
    );
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
      await client.query(
        `INSERT INTO scopezero_state (id, body, updated_at)
         VALUES ($1, $2::jsonb, now())
         ON CONFLICT (id) DO UPDATE SET body = excluded.body, updated_at = now()`,
        ["primary", JSON.stringify(this.state)]
      );
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
