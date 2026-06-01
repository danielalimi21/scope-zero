import fs from "node:fs/promises";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { createId, nowIso, sha256, stableStringify } from "./crypto.js";
import { buildMcpServerRecord, WELL_KNOWN_MCP_SERVERS } from "./mcpTrustRegistry.js";

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
    await this.save();
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
      INSERT OR REPLACE INTO scopezero_meta (key, value, updated_at)
      VALUES ('schema_version', '3', CURRENT_TIMESTAMP);
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
    this.syncRelationalTables();
  }

  syncRelationalTables() {
    this.db.exec("BEGIN IMMEDIATE TRANSACTION");
    try {
      this.db.exec("DELETE FROM tenants; DELETE FROM agents; DELETE FROM missions; DELETE FROM approvals; DELETE FROM policies; DELETE FROM policy_versions;");
      const insertTenant = this.db.prepare("INSERT INTO tenants (tenant_id, name, plan, body) VALUES (?, ?, ?, ?)");
      const insertAgent = this.db.prepare("INSERT INTO agents (tenant_id, agent_id, owner, status, body) VALUES (?, ?, ?, ?, ?)");
      const insertMission = this.db.prepare("INSERT INTO missions (id, tenant_id, agent_id, status, body) VALUES (?, ?, ?, ?, ?)");
      const insertApproval = this.db.prepare("INSERT INTO approvals (id, tenant_id, agent_id, status, body) VALUES (?, ?, ?, ?, ?)");
      const insertPolicy = this.db.prepare("INSERT INTO policies (tenant_id, body) VALUES (?, ?)");
      const insertPolicyVersion = this.db.prepare("INSERT INTO policy_versions (id, tenant_id, version, status, body, created_at, approved_at) VALUES (?, ?, ?, ?, ?, ?, ?)");

      for (const tenant of this.state.tenants) {
        insertTenant.run(tenant.tenant_id, tenant.name, tenant.plan, JSON.stringify(tenant));
      }
      for (const agent of this.state.agents) {
        insertAgent.run(agent.tenant_id, agent.agent_id, agent.owner, agent.status, JSON.stringify(agent));
      }
      for (const mission of this.state.missions) {
        insertMission.run(mission.id, mission.tenant_id, mission.agent_id, mission.status, JSON.stringify(mission));
      }
      for (const approval of this.state.approvals) {
        insertApproval.run(approval.id, approval.tenant_id, approval.agent_id, approval.status, JSON.stringify(approval));
      }
      for (const [tenantId, policy] of Object.entries(this.state.policies)) {
        insertPolicy.run(tenantId, JSON.stringify(policy));
      }
      for (const version of this.state.policy_versions || []) {
        insertPolicyVersion.run(version.id, version.tenant_id, version.version, version.status, JSON.stringify(version), version.created_at, version.approved_at || null);
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
    await this.save();
    return agent;
  }

  getAgent(tenantId, agentId) {
    return this.state.agents.find((agent) => agent.tenant_id === tenantId && agent.agent_id === agentId);
  }

  async addMission(capsule) {
    this.assertTenant(capsule.tenant_id);
    this.state.missions.push(capsule);
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
    await this.save();
    return approval;
  }

  async updateApproval(approvalId, patch, tenantId = null) {
    const approval = this.state.approvals.find((item) => item.id === approvalId && (!tenantId || item.tenant_id === tenantId));
    if (!approval) {
      return null;
    }
    Object.assign(approval, patch);
    await this.save();
    return approval;
  }

  async recordDecision(verdict) {
    this.state.metrics.runtime_decisions += 1;
    if (verdict.decision === "block") {
      this.state.metrics.blocked_actions += 1;
    }
    if (verdict.decision === "approval") {
      this.state.metrics.approvals_required += 1;
    }
    if (verdict.decision === "redact") {
      this.state.metrics.redactions += 1;
    }
    if (verdict.decision === "quarantine_context") {
      this.state.metrics.quarantined_contexts += 1;
    }
    this.state.metrics.evidence_capsules += 1;
    await this.save();
  }

  async updateSessionRisk(sessionId, contribution, tenantId = "tenant_contoso") {
    const key = `${tenantId}:${sessionId}`;
    const current = this.state.sessions[key] || { tenant_id: tenantId, session_id: sessionId, risk_consumed: 0 };
    current.risk_consumed = Math.min(100, Number(current.risk_consumed || 0) + Number(contribution || 0));
    this.state.sessions[key] = current;
    await this.save();
    return current.risk_consumed;
  }

  getSessionRisk(sessionId, tenantId = "tenant_contoso") {
    return this.state.sessions[`${tenantId}:${sessionId}`]?.risk_consumed || 0;
  }

  getBehaviorProfile(tenantId, agentId) {
    const key = `${tenantId}:${agentId}`;
    return this.state.behavior_profiles[key] || null;
  }

  async recordToolCall(tenantId, agentId, toolKey, profile) {
    const key = `${tenantId}:${agentId}`;
    this.state.behavior_profiles[key] = profile;
    await this.save();
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
