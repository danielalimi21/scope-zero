import fs from "node:fs/promises";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { createId, nowIso, sha256, stableStringify } from "./crypto.js";
import { buildMcpServerRecord, WELL_KNOWN_MCP_SERVERS } from "./mcpTrustRegistry.js";

// Top-level state collections that are mirrored into queryable relational
// tables. Everything else (behavior_profiles, sessions, mcp_servers,
// agent_certs, metrics) is read by the app from the in-memory state blob and is
// never queried via SQL, so it is not mirrored.
const MIRRORED_TABLES = ["tenants", "agents", "missions", "approvals", "policies", "policy_versions"];

export class Store {
  constructor(dbPath, defaultPolicy) {
    this.dbPath = dbPath;
    this.defaultPolicy = defaultPolicy;
    this.state = null;
    this.db = null;
    // Tracks which mirrored tables changed since the last persist so save()
    // only rebuilds those, instead of DELETE+INSERTing all six on every write.
    this.dirtyTables = new Set();
  }

  markDirty(...tables) {
    for (const table of tables) {
      this.dirtyTables.add(table);
    }
  }

  async init() {
    await fs.mkdir(path.dirname(this.dbPath), { recursive: true });
    this.db = new DatabaseSync(this.dbPath);
    this.migrate();
    this.state = this.loadState() || (await this.loadLegacyJsonState()) || createSeedState(this.defaultPolicy);
    // Hot-path collections (behavior profiles, session risk) are written on
    // every tool call. They live in their own row-keyed tables, not the
    // full-state blob, so a single call no longer reserializes all state — and
    // (in Postgres) no longer takes the global write lock.
    this.migrateHotPathState();
    // First persist rebuilds every mirror table from loaded/seed state.
    this.markDirty(...MIRRORED_TABLES);
    await this.save();
  }

  // One-time lift of any legacy blob-resident behavior_profiles/sessions into
  // their dedicated tables, then drop them from the in-memory state object so
  // the blob no longer carries (or re-persists) them.
  migrateHotPathState() {
    for (const profile of Object.values(this.state.behavior_profiles || {})) {
      if (profile?.tenant_id && profile?.agent_id) {
        this.writeBehaviorProfile(profile.tenant_id, profile.agent_id, profile);
      }
    }
    for (const session of Object.values(this.state.sessions || {})) {
      if (session?.tenant_id && session?.session_id) {
        this.db
          .prepare(
            `INSERT INTO sessions (tenant_id, session_id, risk_consumed, updated_at)
             VALUES (?, ?, ?, CURRENT_TIMESTAMP)
             ON CONFLICT(tenant_id, session_id) DO UPDATE SET risk_consumed = excluded.risk_consumed, updated_at = CURRENT_TIMESTAMP`
          )
          .run(session.tenant_id, session.session_id, Number(session.risk_consumed || 0));
      }
    }
    for (const [name, value] of Object.entries(this.state.metrics || {})) {
      this.db
        .prepare(
          `INSERT INTO metrics (name, value) VALUES (?, ?)
           ON CONFLICT(name) DO UPDATE SET value = excluded.value`
        )
        .run(name, Number(value) || 0);
    }
    delete this.state.behavior_profiles;
    delete this.state.sessions;
    delete this.state.metrics;
  }

  writeBehaviorProfile(tenantId, agentId, profile) {
    this.db
      .prepare(
        `INSERT INTO behavior_profiles (tenant_id, agent_id, body, updated_at)
         VALUES (?, ?, ?, CURRENT_TIMESTAMP)
         ON CONFLICT(tenant_id, agent_id) DO UPDATE SET body = excluded.body, updated_at = CURRENT_TIMESTAMP`
      )
      .run(tenantId, agentId, JSON.stringify(profile));
  }

  migrate() {
    this.db.exec(`
      PRAGMA journal_mode = WAL;
      PRAGMA foreign_keys = ON;
      CREATE TABLE IF NOT EXISTS scopezero_meta (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL,
        updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
      );
      CREATE TABLE IF NOT EXISTS scopezero_state (
        id TEXT PRIMARY KEY,
        body TEXT NOT NULL,
        updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
      );
      CREATE TABLE IF NOT EXISTS tenants (
        tenant_id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        plan TEXT NOT NULL,
        body TEXT NOT NULL,
        updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
      );
      CREATE TABLE IF NOT EXISTS agents (
        tenant_id TEXT NOT NULL,
        agent_id TEXT NOT NULL,
        owner TEXT NOT NULL,
        status TEXT NOT NULL,
        body TEXT NOT NULL,
        updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (tenant_id, agent_id)
      );
      CREATE TABLE IF NOT EXISTS missions (
        id TEXT PRIMARY KEY,
        tenant_id TEXT NOT NULL,
        agent_id TEXT NOT NULL,
        status TEXT NOT NULL,
        body TEXT NOT NULL,
        updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
      );
      CREATE TABLE IF NOT EXISTS approvals (
        id TEXT PRIMARY KEY,
        tenant_id TEXT NOT NULL,
        agent_id TEXT NOT NULL,
        status TEXT NOT NULL,
        body TEXT NOT NULL,
        updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
      );
      CREATE TABLE IF NOT EXISTS policies (
        tenant_id TEXT PRIMARY KEY,
        body TEXT NOT NULL,
        updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
      );
      CREATE TABLE IF NOT EXISTS policy_versions (
        id TEXT PRIMARY KEY,
        tenant_id TEXT NOT NULL,
        version INTEGER NOT NULL,
        status TEXT NOT NULL,
        body TEXT NOT NULL,
        created_at TEXT NOT NULL,
        approved_at TEXT
      );
      CREATE TABLE IF NOT EXISTS behavior_profiles (
        tenant_id TEXT NOT NULL,
        agent_id TEXT NOT NULL,
        body TEXT NOT NULL,
        updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (tenant_id, agent_id)
      );
      CREATE TABLE IF NOT EXISTS sessions (
        tenant_id TEXT NOT NULL,
        session_id TEXT NOT NULL,
        risk_consumed REAL NOT NULL DEFAULT 0,
        updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (tenant_id, session_id)
      );
      CREATE TABLE IF NOT EXISTS metrics (
        name TEXT PRIMARY KEY,
        value INTEGER NOT NULL DEFAULT 0
      );
      INSERT OR REPLACE INTO scopezero_meta (key, value, updated_at)
      VALUES ('schema_version', '4', CURRENT_TIMESTAMP);
    `);
  }

  loadState() {
    const row = this.db.prepare("SELECT body FROM scopezero_state WHERE id = ?").get("primary");
    return row ? JSON.parse(row.body) : null;
  }

  async loadLegacyJsonState() {
    const legacyPath = this.dbPath.replace(/\.db$/i, ".json");
    try {
      return JSON.parse(await fs.readFile(legacyPath, "utf8"));
    } catch {
      return null;
    }
  }

  async save() {
    const body = JSON.stringify(this.state);
    this.db
      .prepare(
        `INSERT INTO scopezero_state (id, body, updated_at)
         VALUES (?, ?, CURRENT_TIMESTAMP)
         ON CONFLICT(id) DO UPDATE SET body = excluded.body, updated_at = CURRENT_TIMESTAMP`
      )
      .run("primary", body);
    if (this.dirtyTables.size > 0) {
      this.syncRelationalTables(this.dirtyTables);
      this.dirtyTables.clear();
    }
  }

  // Rebuilds only the mirror tables flagged dirty since the last save. A
  // per-tool-call write (behavior/session/metrics) touches no mirrored
  // collection and so skips the relational rebuild entirely.
  syncRelationalTables(tables = new Set(MIRRORED_TABLES)) {
    const syncers = {
      tenants: () => {
        this.db.exec("DELETE FROM tenants");
        const insert = this.db.prepare("INSERT INTO tenants (tenant_id, name, plan, body) VALUES (?, ?, ?, ?)");
        for (const tenant of this.state.tenants) {
          insert.run(tenant.tenant_id, tenant.name, tenant.plan, JSON.stringify(tenant));
        }
      },
      agents: () => {
        this.db.exec("DELETE FROM agents");
        const insert = this.db.prepare("INSERT INTO agents (tenant_id, agent_id, owner, status, body) VALUES (?, ?, ?, ?, ?)");
        for (const agent of this.state.agents) {
          insert.run(agent.tenant_id, agent.agent_id, agent.owner, agent.status, JSON.stringify(agent));
        }
      },
      missions: () => {
        this.db.exec("DELETE FROM missions");
        const insert = this.db.prepare("INSERT INTO missions (id, tenant_id, agent_id, status, body) VALUES (?, ?, ?, ?, ?)");
        for (const mission of this.state.missions) {
          insert.run(mission.id, mission.tenant_id, mission.agent_id, mission.status, JSON.stringify(mission));
        }
      },
      approvals: () => {
        this.db.exec("DELETE FROM approvals");
        const insert = this.db.prepare("INSERT INTO approvals (id, tenant_id, agent_id, status, body) VALUES (?, ?, ?, ?, ?)");
        for (const approval of this.state.approvals) {
          insert.run(approval.id, approval.tenant_id, approval.agent_id, approval.status, JSON.stringify(approval));
        }
      },
      policies: () => {
        this.db.exec("DELETE FROM policies");
        const insert = this.db.prepare("INSERT INTO policies (tenant_id, body) VALUES (?, ?)");
        for (const [tenantId, policy] of Object.entries(this.state.policies)) {
          insert.run(tenantId, JSON.stringify(policy));
        }
      },
      policy_versions: () => {
        this.db.exec("DELETE FROM policy_versions");
        const insert = this.db.prepare("INSERT INTO policy_versions (id, tenant_id, version, status, body, created_at, approved_at) VALUES (?, ?, ?, ?, ?, ?, ?)");
        for (const version of this.state.policy_versions || []) {
          insert.run(version.id, version.tenant_id, version.version, version.status, JSON.stringify(version), version.created_at, version.approved_at || null);
        }
      }
    };

    this.db.exec("BEGIN IMMEDIATE TRANSACTION");
    try {
      for (const table of tables) {
        syncers[table]?.();
      }
      this.db.exec("COMMIT");
    } catch (error) {
      this.db.exec("ROLLBACK");
      throw error;
    }
  }

  listTenants() {
    return this.state.tenants;
  }

  getTenant(tenantId) {
    return this.state.tenants.find((tenant) => tenant.tenant_id === tenantId);
  }

  getPolicy(tenantId) {
    return {
      ...this.defaultPolicy,
      ...(this.state.policies[tenantId] || {})
    };
  }

  async setPolicy(tenantId, policyPatch) {
    this.assertTenant(tenantId);
    const activeVersion = this.nextPolicyVersion(tenantId);
    this.state.policies[tenantId] = {
      ...this.getPolicy(tenantId),
      ...policyPatch,
      policy_version: activeVersion,
      policy_hash: sha256(stableStringify({ ...this.getPolicy(tenantId), ...policyPatch }))
    };
    this.state.policy_versions ||= [];
    this.markDirty("policies", "policy_versions");
    this.state.policy_versions.push({
      id: createId("policyver", `${tenantId}:${activeVersion}`),
      tenant_id: tenantId,
      version: activeVersion,
      status: "active",
      proposed_by: "direct-write",
      approved_by: "direct-write",
      created_at: nowIso(),
      approved_at: nowIso(),
      policy: this.state.policies[tenantId],
      policy_hash: this.state.policies[tenantId].policy_hash
    });
    await this.save();
    return this.state.policies[tenantId];
  }

  listPolicyVersions(tenantId) {
    return (this.state.policy_versions || [])
      .filter((version) => version.tenant_id === tenantId)
      .sort((a, b) => Number(b.version) - Number(a.version));
  }

  async proposePolicy(tenantId, policyPatch, proposedBy = "unknown") {
    this.assertTenant(tenantId);
    this.state.policy_versions ||= [];
    const version = this.nextPolicyVersion(tenantId);
    const policy = {
      ...this.getPolicy(tenantId),
      ...policyPatch,
      policy_version: version
    };
    const proposal = {
      id: createId("policyprop", `${tenantId}:${version}:${proposedBy}`),
      tenant_id: tenantId,
      version,
      status: "pending_approval",
      proposed_by: proposedBy,
      created_at: nowIso(),
      policy,
      policy_hash: sha256(stableStringify(policy))
    };
    this.state.policy_versions.push(proposal);
    this.markDirty("policy_versions");
    await this.save();
    return proposal;
  }

  async reviewPolicyProposal(proposalId, decision, reviewer, tenantId = null) {
    this.state.policy_versions ||= [];
    const proposal = this.state.policy_versions.find((item) => item.id === proposalId && (!tenantId || item.tenant_id === tenantId));
    if (!proposal) {
      return null;
    }
    proposal.status = decision === "approve" ? "active" : "rejected";
    proposal.reviewed_by = reviewer;
    proposal.reviewed_at = nowIso();
    if (proposal.status === "active") {
      proposal.approved_by = reviewer;
      proposal.approved_at = proposal.reviewed_at;
      proposal.policy.policy_hash = proposal.policy_hash;
      this.state.policies[proposal.tenant_id] = proposal.policy;
    }
    this.markDirty("policies", "policy_versions");
    await this.save();
    return proposal;
  }

  nextPolicyVersion(tenantId) {
    const versions = this.listPolicyVersions(tenantId).map((version) => Number(version.version || 0));
    return Math.max(0, ...versions) + 1;
  }

  async upsertAgent(agent) {
    this.assertTenant(agent.tenant_id);
    const existing = this.state.agents.findIndex((item) => item.agent_id === agent.agent_id && item.tenant_id === agent.tenant_id);
    if (existing >= 0) {
      this.state.agents[existing] = { ...this.state.agents[existing], ...agent };
    } else {
      this.state.agents.push(agent);
    }
    this.markDirty("agents");
    await this.save();
    return agent;
  }

  getAgent(tenantId, agentId) {
    return this.state.agents.find((agent) => agent.tenant_id === tenantId && agent.agent_id === agentId);
  }

  async addMission(capsule) {
    this.assertTenant(capsule.tenant_id);
    this.state.missions.push(capsule);
    this.markDirty("missions");
    await this.save();
    return capsule;
  }

  getMission(missionId, tenantId = null) {
    const mission = this.state.missions.find((item) => item.id === missionId);
    if (!mission || (tenantId && mission.tenant_id !== tenantId)) {
      return null;
    }
    return mission;
  }

  async addApproval(approval) {
    this.assertTenant(approval.tenant_id);
    this.state.approvals.push(approval);
    this.markDirty("approvals");
    await this.save();
    return approval;
  }

  async updateApproval(approvalId, patch, tenantId = null) {
    const approval = this.state.approvals.find((item) => item.id === approvalId && (!tenantId || item.tenant_id === tenantId));
    if (!approval) {
      return null;
    }
    Object.assign(approval, patch);
    this.markDirty("approvals");
    await this.save();
    return approval;
  }

  // Atomic counter increments — no full-state read-modify-write. Fires on every
  // tool call, so it stays off the blob.
  async recordDecision(verdict) {
    const counters = ["runtime_decisions", "evidence_capsules"];
    if (verdict.decision === "block") counters.push("blocked_actions");
    else if (verdict.decision === "approval") counters.push("approvals_required");
    else if (verdict.decision === "redact") counters.push("redactions");
    else if (verdict.decision === "quarantine_context") counters.push("quarantined_contexts");
    const inc = this.db.prepare("INSERT INTO metrics (name, value) VALUES (?, 1) ON CONFLICT(name) DO UPDATE SET value = value + 1");
    this.db.exec("BEGIN IMMEDIATE TRANSACTION");
    try {
      for (const name of counters) inc.run(name);
      this.db.exec("COMMIT");
    } catch (error) {
      this.db.exec("ROLLBACK");
      throw error;
    }
  }

  getMetrics() {
    const metrics = { runtime_decisions: 0, blocked_actions: 0, approvals_required: 0, redactions: 0, quarantined_contexts: 0, evidence_capsules: 0 };
    for (const row of this.db.prepare("SELECT name, value FROM metrics").all()) {
      metrics[row.name] = row.value;
    }
    return metrics;
  }

  // Atomic per-row increment — correct under concurrent writers, no full-state
  // read-modify-write. Caps at 100.
  async updateSessionRisk(sessionId, contribution, tenantId = "tenant_contoso") {
    const delta = Number(contribution || 0);
    this.db
      .prepare(
        `INSERT INTO sessions (tenant_id, session_id, risk_consumed, updated_at)
         VALUES (?, ?, ?, CURRENT_TIMESTAMP)
         ON CONFLICT(tenant_id, session_id)
         DO UPDATE SET risk_consumed = MIN(100, sessions.risk_consumed + ?), updated_at = CURRENT_TIMESTAMP`
      )
      .run(tenantId, sessionId, Math.min(100, delta), delta);
    return this.getSessionRisk(sessionId, tenantId);
  }

  getSessionRisk(sessionId, tenantId = "tenant_contoso") {
    const row = this.db.prepare("SELECT risk_consumed FROM sessions WHERE tenant_id = ? AND session_id = ?").get(tenantId, sessionId);
    return row?.risk_consumed || 0;
  }

  getBehaviorProfile(tenantId, agentId) {
    const row = this.db.prepare("SELECT body FROM behavior_profiles WHERE tenant_id = ? AND agent_id = ?").get(tenantId, agentId);
    return row ? JSON.parse(row.body) : null;
  }

  async recordToolCall(tenantId, agentId, toolKey, profile) {
    this.writeBehaviorProfile(tenantId, agentId, profile);
  }

  // Surfaced for /v1/state and compliance views, which expect the legacy
  // `tenant:key` map shape. These are reporting reads, not the hot path.
  getAllSessions() {
    return Object.fromEntries(
      this.db.prepare("SELECT tenant_id, session_id, risk_consumed FROM sessions").all().map((row) => [
        `${row.tenant_id}:${row.session_id}`,
        { tenant_id: row.tenant_id, session_id: row.session_id, risk_consumed: row.risk_consumed }
      ])
    );
  }

  getAllBehaviorProfiles() {
    return Object.fromEntries(
      this.db.prepare("SELECT body FROM behavior_profiles").all().map((row) => {
        const profile = JSON.parse(row.body);
        return [`${profile.tenant_id}:${profile.agent_id}`, profile];
      })
    );
  }

  getMcpServer(serverId, tenantId = null) {
    const all = this.state.mcp_servers || [];
    // tenant-specific first, then global
    return (
      all.find(s => s.server_id === serverId && s.tenant_id === tenantId) ||
      all.find(s => s.server_id === serverId && s.tenant_id === null) ||
      null
    );
  }

  listAllMcpServers() {
    return this.state.mcp_servers || [];
  }

  listMcpServers({ tenantId = null, trustLevel = null } = {}) {
    const all = this.state.mcp_servers || [];
    return all.filter(s => {
      const tenantMatch = s.tenant_id === null || s.tenant_id === tenantId;
      const levelMatch = !trustLevel || s.trust_level === trustLevel;
      return tenantMatch && levelMatch;
    });
  }

  async upsertMcpServer(server) {
    this.state.mcp_servers ||= [];
    const idx = this.state.mcp_servers.findIndex(
      s => s.server_id === server.server_id && s.tenant_id === server.tenant_id
    );
    if (idx >= 0) {
      this.state.mcp_servers[idx] = { ...this.state.mcp_servers[idx], ...server };
    } else {
      this.state.mcp_servers.push(server);
    }
    await this.save();
    return this.state.mcp_servers[idx >= 0 ? idx : this.state.mcp_servers.length - 1];
  }

  getAgentCert(certId) {
    return (this.state.agent_certs || []).find(c => c.cert_id === certId) || null;
  }

  listAgentCerts(tenantId, agentId) {
    return (this.state.agent_certs || []).filter(
      c => c.tenant_id === tenantId && (!agentId || c.agent_id === agentId)
    );
  }

  async addAgentCert(cert) {
    this.state.agent_certs ||= [];
    this.state.agent_certs.push(cert);
    await this.save();
    return cert;
  }

  async revokeCert(certId, { revoked_by, reason, tenant_id = null }) {
    const cert = (this.state.agent_certs || []).find(
      c => c.cert_id === certId && (!tenant_id || c.tenant_id === tenant_id)
    );
    if (!cert) return null;
    cert.status = "revoked";
    cert.revoked_at = nowIso();
    cert.revoked_by = revoked_by || "security.operator@scopezero.local";
    cert.revocation_reason = reason || "unspecified";
    await this.save();
    return cert;
  }

  assertTenant(tenantId) {
    if (!this.getTenant(tenantId)) {
      throw new Error(`Unknown tenant: ${tenantId}`);
    }
  }
}

function createSeedState(defaultPolicy) {
  return {
    tenants: [
      {
        tenant_id: "tenant_contoso",
        name: "Contoso Holdings",
        plan: "enterprise"
      }
    ],
    agents: [
      {
        tenant_id: "tenant_contoso",
        agent_id: "agent.ma-diligence.72f1",
        name: "M&A Diligence Agent",
        owner: "vp.strategy@contoso.example",
        environment: "production",
        status: "active",
        allowed_tools: ["drive.search", "drive.read", "slack.draft"]
      }
    ],
    missions: [],
    approvals: [],
    policy_versions: [
      {
        id: "policyver_tenant_contoso_1",
        tenant_id: "tenant_contoso",
        version: 1,
        status: "active",
        proposed_by: "seed",
        approved_by: "seed",
        created_at: nowIso(),
        approved_at: nowIso(),
        policy: {
          ...defaultPolicy,
          policy_version: 1,
          policy_hash: sha256(stableStringify(defaultPolicy))
        },
        policy_hash: sha256(stableStringify(defaultPolicy))
      }
    ],
    sessions: {},
    behavior_profiles: {},
    mcp_servers: WELL_KNOWN_MCP_SERVERS.map(s => buildMcpServerRecord(s)),
    agent_certs: [],
    policies: {
      tenant_contoso: defaultPolicy
    },
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
