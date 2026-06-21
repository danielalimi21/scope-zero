import fs from "node:fs/promises";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { createId, nowIso, sha256, stableStringify } from "./crypto.js";
import { buildMcpServerRecord, WELL_KNOWN_MCP_SERVERS } from "./mcpTrustRegistry.js";

// Top-level state collections that are durable in their own row tables, written
// one row per change and treated as authoritative on load: tenants, agents,
// missions, approvals, policies, policy_versions. Everything else
// (behavior_profiles, sessions, metrics in their own tables; mcp_servers and
// agent_certs in the state blob) is handled separately.

export class Store {
  constructor(dbPath, defaultPolicy) {
    this.dbPath = dbPath;
    this.defaultPolicy = defaultPolicy;
    this.state = null;
    this.db = null;
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
    // Mirrored collections (tenants/agents/missions/approvals/policies/
    // policy_versions) live in their own row tables, written one row per change
    // (not a full-table rebuild). On load the tables are authoritative: hydrate
    // state from them, or — on a fresh/legacy/pre-migration db where a table is
    // empty — seed the table once from the loaded state.
    this.reconcileMirrored();
    // The blob now carries ONLY non-mirrored singletons (mcp_servers,
    // agent_certs); mirrored collections are durable in their tables, so a write
    // to one of them no longer reserializes all state.
    await this.saveBlob();
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
        ingested_class_rank REAL NOT NULL DEFAULT 0,
        updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (tenant_id, session_id)
      );
      CREATE TABLE IF NOT EXISTS metrics (
        name TEXT PRIMARY KEY,
        value INTEGER NOT NULL DEFAULT 0
      );
      INSERT OR REPLACE INTO scopezero_meta (key, value, updated_at)
      VALUES ('schema_version', '5', CURRENT_TIMESTAMP);
    `);
    // Additive column for session ingest-taint tracking. CREATE TABLE IF NOT
    // EXISTS won't add it to a pre-existing sessions table, so add it idempotently.
    this.ensureColumn("sessions", "ingested_class_rank", "REAL NOT NULL DEFAULT 0");
  }

  ensureColumn(table, column, definition) {
    const columns = this.db.prepare(`PRAGMA table_info(${table})`).all();
    if (!columns.some((col) => col.name === column)) {
      this.db.exec(`ALTER TABLE ${table} ADD COLUMN ${column} ${definition}`);
    }
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

  // Persist only the non-mirrored singletons (mcp_servers, agent_certs, …) to the
  // state blob. Mirrored collections are durable in their own row tables, written
  // incrementally, so they are stripped from the blob here — a write to one of
  // them no longer reserializes all state.
  saveBlob() {
    const { tenants, agents, missions, approvals, policies, policy_versions, ...rest } = this.state;
    const body = JSON.stringify(rest);
    this.db
      .prepare(
        `INSERT INTO scopezero_state (id, body, updated_at)
         VALUES (?, ?, CURRENT_TIMESTAMP)
         ON CONFLICT(id) DO UPDATE SET body = excluded.body, updated_at = CURRENT_TIMESTAMP`
      )
      .run("primary", body);
  }

  // ── Incremental mirror-table row writes (one row per change, O(1)) ──────────
  writeTenantRow(tenant) {
    this.db
      .prepare(
        `INSERT INTO tenants (tenant_id, name, plan, body) VALUES (?, ?, ?, ?)
         ON CONFLICT(tenant_id) DO UPDATE SET name = excluded.name, plan = excluded.plan, body = excluded.body, updated_at = CURRENT_TIMESTAMP`
      )
      .run(tenant.tenant_id, tenant.name || tenant.tenant_id, tenant.plan || "enterprise", JSON.stringify(tenant));
  }

  writeAgentRow(agent) {
    this.db
      .prepare(
        `INSERT INTO agents (tenant_id, agent_id, owner, status, body) VALUES (?, ?, ?, ?, ?)
         ON CONFLICT(tenant_id, agent_id) DO UPDATE SET owner = excluded.owner, status = excluded.status, body = excluded.body, updated_at = CURRENT_TIMESTAMP`
      )
      .run(agent.tenant_id, agent.agent_id, agent.owner || "", agent.status || "active", JSON.stringify(agent));
  }

  writeMissionRow(mission) {
    this.db
      .prepare(
        `INSERT INTO missions (id, tenant_id, agent_id, status, body) VALUES (?, ?, ?, ?, ?)
         ON CONFLICT(id) DO UPDATE SET tenant_id = excluded.tenant_id, agent_id = excluded.agent_id, status = excluded.status, body = excluded.body, updated_at = CURRENT_TIMESTAMP`
      )
      .run(mission.id, mission.tenant_id, mission.agent_id, mission.status || "active", JSON.stringify(mission));
  }

  writeApprovalRow(approval) {
    this.db
      .prepare(
        `INSERT INTO approvals (id, tenant_id, agent_id, status, body) VALUES (?, ?, ?, ?, ?)
         ON CONFLICT(id) DO UPDATE SET tenant_id = excluded.tenant_id, agent_id = excluded.agent_id, status = excluded.status, body = excluded.body, updated_at = CURRENT_TIMESTAMP`
      )
      .run(approval.id, approval.tenant_id, approval.agent_id, approval.status || "pending", JSON.stringify(approval));
  }

  writePolicyRow(tenantId, policy) {
    this.db
      .prepare(
        `INSERT INTO policies (tenant_id, body) VALUES (?, ?)
         ON CONFLICT(tenant_id) DO UPDATE SET body = excluded.body, updated_at = CURRENT_TIMESTAMP`
      )
      .run(tenantId, JSON.stringify(policy));
  }

  writePolicyVersionRow(version) {
    this.db
      .prepare(
        `INSERT INTO policy_versions (id, tenant_id, version, status, body, created_at, approved_at) VALUES (?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(id) DO UPDATE SET tenant_id = excluded.tenant_id, version = excluded.version, status = excluded.status, body = excluded.body, created_at = excluded.created_at, approved_at = excluded.approved_at`
      )
      .run(version.id, version.tenant_id, version.version, version.status, JSON.stringify(version), version.created_at, version.approved_at || null);
  }

  rowWriterFor(table) {
    return {
      tenants: (r) => this.writeTenantRow(r),
      agents: (r) => this.writeAgentRow(r),
      missions: (r) => this.writeMissionRow(r),
      approvals: (r) => this.writeApprovalRow(r),
      policy_versions: (r) => this.writePolicyVersionRow(r)
    }[table];
  }

  // On load the mirror tables are the source of truth for the six collections.
  // If a table has rows, hydrate state from it. If it is empty (fresh seed,
  // legacy JSON, or a pre-migration blob that still carried these collections),
  // seed the table once from the state we just loaded so the two are consistent
  // going forward. State collections are always left as proper containers so the
  // in-memory readers never see `undefined`.
  reconcileMirrored() {
    const has = (table) => this.db.prepare(`SELECT 1 FROM ${table} LIMIT 1`).get() !== undefined;
    const readAll = (table) => this.db.prepare(`SELECT body FROM ${table}`).all().map((r) => JSON.parse(r.body));

    for (const table of ["tenants", "agents", "missions", "approvals", "policy_versions"]) {
      if (has(table)) {
        this.state[table] = readAll(table);
      } else {
        this.state[table] = this.state[table] || [];
        for (const record of this.state[table]) this.rowWriterFor(table)(record);
      }
    }

    // policies is a { tenant_id: policy } map, not an array.
    if (has("policies")) {
      this.state.policies = Object.fromEntries(
        this.db.prepare("SELECT tenant_id, body FROM policies").all().map((r) => [r.tenant_id, JSON.parse(r.body)])
      );
    } else {
      this.state.policies = this.state.policies || {};
      for (const [tenantId, policy] of Object.entries(this.state.policies)) this.writePolicyRow(tenantId, policy);
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
    const versionRecord = {
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
    };
    this.state.policy_versions.push(versionRecord);
    this.writePolicyRow(tenantId, this.state.policies[tenantId]);
    this.writePolicyVersionRow(versionRecord);
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
    this.writePolicyVersionRow(proposal);
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
      this.writePolicyRow(proposal.tenant_id, proposal.policy);
    }
    this.writePolicyVersionRow(proposal);
    return proposal;
  }

  nextPolicyVersion(tenantId) {
    const versions = this.listPolicyVersions(tenantId).map((version) => Number(version.version || 0));
    return Math.max(0, ...versions) + 1;
  }

  async upsertAgent(agent) {
    this.assertTenant(agent.tenant_id);
    const existing = this.state.agents.findIndex((item) => item.agent_id === agent.agent_id && item.tenant_id === agent.tenant_id);
    let stored;
    if (existing >= 0) {
      this.state.agents[existing] = { ...this.state.agents[existing], ...agent };
      stored = this.state.agents[existing];
    } else {
      this.state.agents.push(agent);
      stored = agent;
    }
    this.writeAgentRow(stored);
    return stored;
  }

  getAgent(tenantId, agentId) {
    return this.state.agents.find((agent) => agent.tenant_id === tenantId && agent.agent_id === agentId);
  }

  async addMission(capsule) {
    this.assertTenant(capsule.tenant_id);
    this.state.missions.push(capsule);
    this.writeMissionRow(capsule);
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
    this.writeApprovalRow(approval);
    return approval;
  }

  async updateApproval(approvalId, patch, tenantId = null) {
    const approval = this.state.approvals.find((item) => item.id === approvalId && (!tenantId || item.tenant_id === tenantId));
    if (!approval) {
      return null;
    }
    Object.assign(approval, patch);
    this.writeApprovalRow(approval);
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

  // Monotonic per-session high-water mark of the most sensitive data class the
  // session has been exposed to (payload or context). Drives the laundering guard:
  // egress is judged against what the session has TOUCHED, not just the outbound
  // bytes, because laundered content leaves looking benign.
  async updateSessionIngestedClass(sessionId, classRank, tenantId = "tenant_contoso") {
    const rank = Number(classRank || 0);
    this.db
      .prepare(
        `INSERT INTO sessions (tenant_id, session_id, ingested_class_rank, updated_at)
         VALUES (?, ?, ?, CURRENT_TIMESTAMP)
         ON CONFLICT(tenant_id, session_id)
         DO UPDATE SET ingested_class_rank = MAX(sessions.ingested_class_rank, ?), updated_at = CURRENT_TIMESTAMP`
      )
      .run(tenantId, sessionId, rank, rank);
    return this.getSessionIngestedClass(sessionId, tenantId);
  }

  getSessionIngestedClass(sessionId, tenantId = "tenant_contoso") {
    const row = this.db.prepare("SELECT ingested_class_rank FROM sessions WHERE tenant_id = ? AND session_id = ?").get(tenantId, sessionId);
    return row?.ingested_class_rank || 0;
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
      this.db.prepare("SELECT tenant_id, session_id, risk_consumed, ingested_class_rank FROM sessions").all().map((row) => [
        `${row.tenant_id}:${row.session_id}`,
        { tenant_id: row.tenant_id, session_id: row.session_id, risk_consumed: row.risk_consumed, ingested_class_rank: row.ingested_class_rank }
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
    await this.saveBlob();
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
    await this.saveBlob();
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
    await this.saveBlob();
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
