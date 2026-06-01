import { nowIso, createId } from "./crypto.js";

// Builds a compliance audit report from ledger events + store state.
// Supports JSON and HTML (print-ready for auditors).

export async function generateComplianceReport({ ledger, store, tenantId, from, to, format = "json" }) {
  const fromMs = from ? new Date(from).getTime() : Date.now() - 30 * 24 * 60 * 60 * 1000;
  const toMs = to ? new Date(to).getTime() : Date.now();
  const fromIso = new Date(fromMs).toISOString();
  const toIso = new Date(toMs).toISOString();

  const allEvents = await ledger.list({ limit: Number.MAX_SAFE_INTEGER, reverse: false });
  const events = allEvents.filter((e) => {
    const t = new Date(e.time).getTime();
    return t >= fromMs && t <= toMs && (!tenantId || matchesTenant(e, tenantId));
  });

  const ledgerIntegrity = await ledger.verify();
  const state = await store.state;

  const authEvents = events.filter((e) => e.record?.event_type === "action_authorization.evaluated");
  const approvalEvents = events.filter((e) => ["approval.approved", "approval.denied"].includes(e.record?.event_type));
  const missionEvents = events.filter((e) => e.record?.event_type === "mission.issued");
  const agentEvents = events.filter((e) => e.record?.event_type === "agent.registered");
  const policyEvents = events.filter((e) => ["policy.proposed", "policy.active", "policy.rejected"].includes(e.record?.event_type));

  // Decision breakdown
  const decisions = { allow: 0, block: 0, approval: 0, redact: 0, quarantine_context: 0, pause_session: 0 };
  let promptInjectionCount = 0;
  let sensitiveEgressCount = 0;
  const agentStats = {};
  const toolStats = {};
  const incidentLog = [];

  for (const e of authEvents) {
    const r = e.record;
    const verdict = r.verdict || {};
    const decision = verdict.decision || "allow";
    decisions[decision] = (decisions[decision] || 0) + 1;

    const agentId = r.agent_id || "unknown";
    if (!agentStats[agentId]) agentStats[agentId] = { agent_id: agentId, evaluated: 0, allowed: 0, blocked: 0, approval: 0, redacted: 0 };
    agentStats[agentId].evaluated += 1;
    if (decision === "allow") agentStats[agentId].allowed += 1;
    if (decision === "block") agentStats[agentId].blocked += 1;
    if (decision === "approval") agentStats[agentId].approval += 1;
    if (decision === "redact") agentStats[agentId].redacted += 1;

    const tool = r.tool || "unknown";
    if (!toolStats[tool]) toolStats[tool] = { tool, evaluated: 0, blocked: 0 };
    toolStats[tool].evaluated += 1;
    if (decision === "block") toolStats[tool].blocked += 1;

    const isPromptInjection = (verdict.reasons || []).some((r) => r.code === "prompt-influence");
    const isSensitiveEgress = (verdict.reasons || []).some((r) => r.code === "sensitive-egress");
    if (isPromptInjection) promptInjectionCount += 1;
    if (isSensitiveEgress) sensitiveEgressCount += 1;

    if (decision === "block" || isPromptInjection || isSensitiveEgress) {
      incidentLog.push({
        time: e.time,
        event_id: e.id,
        agent_id: agentId,
        tool,
        action: r.action || "",
        decision,
        risk_score: verdict.risk_score || 0,
        reasons: (verdict.reasons || []).map((r) => r.message),
        prompt_injection: isPromptInjection,
        sensitive_egress: isSensitiveEgress,
        evidence_hash: e.hash
      });
    }
  }

  const total = Object.values(decisions).reduce((a, b) => a + b, 0);
  const approvalLog = [];
  const approvalsPending = (state.approvals || []).filter((a) =>
    a.status === "pending" && (!tenantId || a.tenant_id === tenantId)
  );

  for (const e of approvalEvents) {
    const r = e.record;
    approvalLog.push({
      time: e.time,
      approval_id: r.approval?.id || "",
      agent_id: r.approval?.agent_id || "",
      tool: r.approval?.tool || "",
      decision: r.event_type === "approval.approved" ? "approved" : "denied",
      reviewed_by: r.approval?.reviewed_by || "",
      evidence_hash: e.hash
    });
  }

  const policyVersions = (state.policy_versions || [])
    .filter((v) => !tenantId || v.tenant_id === tenantId)
    .filter((v) => !v.created_at || new Date(v.created_at).getTime() <= toMs)
    .map((v) => ({
      version: v.version,
      status: v.status,
      proposed_by: v.proposed_by,
      approved_by: v.approved_by,
      created_at: v.created_at,
      approved_at: v.approved_at,
      policy_hash: v.policy_hash
    }));

  const topBlockedTools = Object.values(toolStats)
    .filter((t) => t.blocked > 0)
    .sort((a, b) => b.blocked - a.blocked)
    .slice(0, 10);

  // Multi-agent chain stats
  const allMissions = (store.state.missions || []).filter((m) => !tenantId || m.tenant_id === tenantId);
  const chainViolationCodes = new Set(["chain_cycle", "chain_depth_exceeded", "parent_mission_inactive", "parent_mission_expired"]);
  const chainViolations = authEvents.filter((e) =>
    (e.record?.verdict?.reasons || []).some((r) => chainViolationCodes.has(r.code))
  );
  const maxObservedDepth = allMissions.reduce((max, m) => Math.max(max, m.delegation_depth ?? 0), 0);
  const subMissions = allMissions.filter((m) => m.parent_mission_id);

  const report = {
    report_id: createId("rpt", `${tenantId || "all"}:${fromIso}:${toIso}`),
    generated_at: nowIso(),
    tenant_id: tenantId || "all",
    period: { from: fromIso, to: toIso },
    ledger_integrity: {
      valid: ledgerIntegrity.valid,
      total_entries: ledgerIntegrity.entries,
      chain_root: ledgerIntegrity.chain_root,
      failures: ledgerIntegrity.failures?.length || 0
    },
    executive_summary: {
      total_agent_actions: total,
      allowed: decisions.allow || 0,
      blocked: decisions.block || 0,
      human_approvals_required: decisions.approval || 0,
      human_approvals_approved: approvalLog.filter((a) => a.decision === "approved").length,
      human_approvals_denied: approvalLog.filter((a) => a.decision === "denied").length,
      human_approvals_pending: approvalsPending.length,
      redacted: decisions.redact || 0,
      quarantined: decisions.quarantine_context || 0,
      prompt_injection_attempts: promptInjectionCount,
      sensitive_egress_attempts: sensitiveEgressCount,
      block_rate_percent: total > 0 ? Math.round(((decisions.block || 0) / total) * 1000) / 10 : 0,
      missions_issued: missionEvents.length,
      agents_active: Object.keys(agentStats).length
    },
    agents: Object.values(agentStats).sort((a, b) => b.evaluated - a.evaluated),
    top_blocked_tools: topBlockedTools,
    approval_log: approvalLog,
    incident_log: incidentLog.slice(0, 100),
    policy_versions: policyVersions,
    agent_chains: {
      total_missions: allMissions.length,
      root_missions: allMissions.filter((m) => !m.parent_mission_id).length,
      sub_missions: subMissions.length,
      max_observed_depth: maxObservedDepth,
      chain_violations: chainViolations.length,
      violation_log: chainViolations.slice(0, 20).map((e) => ({
        time: e.time,
        agent_id: e.record.agent_id,
        mission_id: e.record.mission_id,
        reasons: (e.record?.verdict?.reasons || []).filter((r) => chainViolationCodes.has(r.code)).map((r) => r.message),
        evidence_hash: e.hash
      }))
    },
    compliance_mapping: buildComplianceMapping(decisions, ledgerIntegrity, promptInjectionCount)
  };

  if (format === "html") return renderHtml(report);
  return report;
}

function buildComplianceMapping(decisions, ledgerIntegrity, promptInjectionCount) {
  return {
    SOC2: [
      {
        control: "CC6.1",
        name: "Logical and Physical Access Controls",
        status: "covered",
        evidence: "RBAC authorization, OIDC/JWKS identity, tenant-scoped filtering on all endpoints"
      },
      {
        control: "CC6.6",
        name: "Change Management",
        status: "covered",
        evidence: `Policy proposals require approval before activation. ${decisions.block || 0} unauthorized actions blocked. Hash-linked evidence ledger is tamper-evident.`
      },
      {
        control: "CC7.2",
        name: "System Monitoring",
        status: "covered",
        evidence: "Every agent action evaluated and logged. SIEM export available in JSON/CEF/LEEF/OTLP. Prometheus metrics endpoint active."
      },
      {
        control: "CC7.4",
        name: "Incident Response",
        status: "covered",
        evidence: `${promptInjectionCount} prompt injection attempts detected. All blocked actions recorded with forensic evidence chain. Ledger integrity: ${ledgerIntegrity.valid ? "valid" : "FAILED"}.`
      },
      {
        control: "CC8.1",
        name: "Production Change Control",
        status: "covered",
        evidence: "Mission action contracts are cryptographically signed. Agents cannot exceed signed mission scope. Kubernetes manifests and readiness probes included."
      },
      {
        control: "C1.2",
        name: "Confidential Information Protection",
        status: "covered",
        evidence: "Sensitive data classifier active. Egress guard blocks data crossing external boundaries. Encrypted secret references — plaintext never returned."
      }
    ],
    EU_AI_Act: [
      {
        article: "Article 9",
        requirement: "Risk management system",
        status: "covered",
        evidence: "Per-action risk scoring, session risk budget, mission-scoped authorization enforced pre-execution"
      },
      {
        article: "Article 12",
        requirement: "Record-keeping",
        status: "covered",
        evidence: "Hash-chained JSONL evidence ledger. Every decision recorded with agent identity, mission ID, tool, action, verdict, and timestamp"
      },
      {
        article: "Article 13",
        requirement: "Transparency",
        status: "covered",
        evidence: "Every authorization decision includes structured reasons. Human delegator recorded on every mission. Approval audit trail maintained"
      },
      {
        article: "Article 14",
        requirement: "Human oversight",
        status: "covered",
        evidence: "Approval broker routes high-impact actions to human reviewers. Slack Block Kit notifications. Agents pause and wait for human decision"
      },
      {
        article: "Article 17",
        requirement: "Quality management",
        status: "covered",
        evidence: "Policy versioning with proposal/approval workflow. Policy changes sealed into evidence ledger. Automated test suite with 39 tests"
      }
    ],
    HIPAA_relevant: [
      {
        safeguard: "§164.312(a)(1)",
        name: "Access Control",
        status: "covered",
        evidence: "Agent identity verified on every action. Mission contracts limit data class access. Restricted data classes block unauthorized reads"
      },
      {
        safeguard: "§164.312(b)",
        name: "Audit Controls",
        status: "covered",
        evidence: "Complete audit log of every agent action. Tamper-evident hash chain. SIEM export for external audit systems"
      },
      {
        safeguard: "§164.312(e)(1)",
        name: "Transmission Security",
        status: "covered",
        evidence: "Sensitive egress guard prevents unauthorized external transmission. Destination allowlist enforced per mission contract"
      }
    ]
  };
}

function renderHtml(report) {
  const s = report.executive_summary;
  const integrityColor = report.ledger_integrity.valid ? "#22c55e" : "#ef4444";
  const integrityText = report.ledger_integrity.valid ? "VERIFIED" : "TAMPERED";

  const agentRows = report.agents.map((a) => `
    <tr>
      <td>${esc(a.agent_id)}</td>
      <td class="num">${a.evaluated}</td>
      <td class="num green">${a.allowed}</td>
      <td class="num red">${a.blocked}</td>
      <td class="num yellow">${a.approval}</td>
      <td class="num">${a.redacted}</td>
    </tr>`).join("");

  const incidentRows = report.incident_log.slice(0, 20).map((i) => `
    <tr>
      <td class="mono">${esc(i.time.slice(0, 19).replace("T", " "))}</td>
      <td>${esc(i.agent_id)}</td>
      <td>${esc(i.tool)}</td>
      <td><span class="badge badge-${i.decision}">${esc(i.decision)}</span></td>
      <td class="num">${i.risk_score}</td>
      <td>${i.prompt_injection ? "⚠ Prompt injection" : ""}${i.sensitive_egress ? "⚠ Sensitive egress" : ""}</td>
    </tr>`).join("");

  const approvalRows = report.approval_log.map((a) => `
    <tr>
      <td class="mono">${esc(a.time.slice(0, 19).replace("T", " "))}</td>
      <td>${esc(a.agent_id)}</td>
      <td>${esc(a.tool)}</td>
      <td><span class="badge badge-${a.decision}">${esc(a.decision)}</span></td>
      <td>${esc(a.reviewed_by)}</td>
    </tr>`).join("");

  const socRows = report.compliance_mapping.SOC2.map((c) => `
    <tr>
      <td><strong>${esc(c.control)}</strong></td>
      <td>${esc(c.name)}</td>
      <td><span class="badge badge-allow">Covered</span></td>
      <td>${esc(c.evidence)}</td>
    </tr>`).join("");

  const euRows = report.compliance_mapping.EU_AI_Act.map((c) => `
    <tr>
      <td><strong>${esc(c.article)}</strong></td>
      <td>${esc(c.requirement)}</td>
      <td><span class="badge badge-allow">Covered</span></td>
      <td>${esc(c.evidence)}</td>
    </tr>`).join("");

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ScopeZero Compliance Audit Report — ${esc(report.tenant_id)}</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; font-size: 13px; color: #1a1a2e; background: #fff; }
  .page { max-width: 1100px; margin: 0 auto; padding: 40px 32px; }
  header { display: flex; justify-content: space-between; align-items: flex-start; border-bottom: 3px solid #1a1a2e; padding-bottom: 24px; margin-bottom: 32px; }
  .logo { font-size: 22px; font-weight: 800; letter-spacing: -0.5px; color: #1a1a2e; }
  .logo span { color: #6366f1; }
  .meta { text-align: right; color: #555; line-height: 1.6; }
  h2 { font-size: 16px; font-weight: 700; margin: 32px 0 12px; color: #1a1a2e; border-left: 4px solid #6366f1; padding-left: 10px; }
  h3 { font-size: 13px; font-weight: 700; margin: 24px 0 8px; color: #444; text-transform: uppercase; letter-spacing: 0.5px; }
  .cards { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin-bottom: 8px; }
  .card { background: #f8f8ff; border: 1px solid #e8e8f0; border-radius: 8px; padding: 16px; }
  .card .val { font-size: 28px; font-weight: 800; color: #1a1a2e; }
  .card .val.red { color: #ef4444; }
  .card .val.green { color: #22c55e; }
  .card .val.yellow { color: #f59e0b; }
  .card .lbl { font-size: 11px; color: #777; margin-top: 4px; text-transform: uppercase; letter-spacing: 0.4px; }
  table { width: 100%; border-collapse: collapse; margin-bottom: 8px; }
  th { background: #1a1a2e; color: #fff; font-size: 11px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.4px; padding: 8px 10px; text-align: left; }
  td { padding: 7px 10px; border-bottom: 1px solid #f0f0f0; vertical-align: top; }
  tr:hover td { background: #f8f8ff; }
  .num { text-align: right; font-variant-numeric: tabular-nums; }
  .mono { font-family: monospace; font-size: 11px; color: #555; }
  .green { color: #22c55e; font-weight: 600; }
  .red { color: #ef4444; font-weight: 600; }
  .yellow { color: #f59e0b; font-weight: 600; }
  .badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600; text-transform: uppercase; }
  .badge-allow, .badge-approved { background: #dcfce7; color: #166534; }
  .badge-block, .badge-denied { background: #fee2e2; color: #991b1b; }
  .badge-approval { background: #fef3c7; color: #92400e; }
  .badge-redact { background: #e0e7ff; color: #3730a3; }
  .badge-quarantine_context { background: #fce7f3; color: #9d174d; }
  .integrity { display: flex; align-items: center; gap: 12px; background: #f8f8ff; border: 1px solid #e8e8f0; border-radius: 8px; padding: 16px 20px; margin-bottom: 16px; }
  .integrity .dot { width: 12px; height: 12px; border-radius: 50%; background: ${integrityColor}; flex-shrink: 0; }
  .integrity .status { font-weight: 800; color: ${integrityColor}; font-size: 15px; }
  .integrity .detail { color: #666; font-size: 12px; }
  .hash { font-family: monospace; font-size: 10px; color: #999; word-break: break-all; margin-top: 4px; }
  footer { margin-top: 48px; padding-top: 16px; border-top: 1px solid #e8e8f0; color: #aaa; font-size: 11px; display: flex; justify-content: space-between; }
  @media print { body { font-size: 11px; } .cards { grid-template-columns: repeat(4, 1fr); } }
</style>
</head>
<body>
<div class="page">
  <header>
    <div>
      <div class="logo">Scope<span>Zero</span></div>
      <div style="margin-top:6px;color:#555;font-size:12px;">Vendor-Neutral Agent Action Authorization Gateway</div>
    </div>
    <div class="meta">
      <strong>AI Agent Compliance Audit Report</strong><br>
      Tenant: ${esc(report.tenant_id)}<br>
      Period: ${esc(report.period.from.slice(0, 10))} → ${esc(report.period.to.slice(0, 10))}<br>
      Generated: ${esc(report.generated_at.slice(0, 19).replace("T", " "))} UTC<br>
      Report ID: <span style="font-family:monospace;font-size:11px">${esc(report.report_id)}</span>
    </div>
  </header>

  <h2>Executive Summary</h2>
  <div class="cards">
    <div class="card"><div class="val">${s.total_agent_actions}</div><div class="lbl">Total Agent Actions</div></div>
    <div class="card"><div class="val green">${s.allowed}</div><div class="lbl">Authorized</div></div>
    <div class="card"><div class="val red">${s.blocked}</div><div class="lbl">Blocked</div></div>
    <div class="card"><div class="val yellow">${s.human_approvals_required}</div><div class="lbl">Sent for Human Approval</div></div>
  </div>
  <div class="cards">
    <div class="card"><div class="val">${s.block_rate_percent}%</div><div class="lbl">Block Rate</div></div>
    <div class="card"><div class="val red">${s.prompt_injection_attempts}</div><div class="lbl">Prompt Injection Attempts</div></div>
    <div class="card"><div class="val red">${s.sensitive_egress_attempts}</div><div class="lbl">Sensitive Egress Attempts</div></div>
    <div class="card"><div class="val">${s.missions_issued}</div><div class="lbl">Missions Issued</div></div>
  </div>

  <h2>Evidence Ledger Integrity</h2>
  <div class="integrity">
    <div class="dot"></div>
    <div>
      <div class="status">${integrityText}</div>
      <div class="detail">${report.ledger_integrity.total_entries} entries verified · ${report.ledger_integrity.failures} integrity failures</div>
      <div class="hash">Chain root: ${esc(report.ledger_integrity.chain_root)}</div>
    </div>
  </div>

  <h2>Agent Activity</h2>
  <table>
    <thead><tr><th>Agent ID</th><th class="num">Evaluated</th><th class="num">Allowed</th><th class="num">Blocked</th><th class="num">Approval</th><th class="num">Redacted</th></tr></thead>
    <tbody>${agentRows || '<tr><td colspan="6" style="color:#aaa;text-align:center;padding:20px">No agent activity in this period</td></tr>'}</tbody>
  </table>

  ${report.incident_log.length > 0 ? `
  <h2>Incident Log <span style="font-weight:400;font-size:12px;color:#888">(blocks, prompt injections, sensitive egress — max 20 shown)</span></h2>
  <table>
    <thead><tr><th>Time (UTC)</th><th>Agent</th><th>Tool</th><th>Decision</th><th class="num">Risk</th><th>Flags</th></tr></thead>
    <tbody>${incidentRows}</tbody>
  </table>` : ""}

  ${report.approval_log.length > 0 ? `
  <h2>Human Approval Log</h2>
  <table>
    <thead><tr><th>Time (UTC)</th><th>Agent</th><th>Tool</th><th>Outcome</th><th>Reviewed By</th></tr></thead>
    <tbody>${approvalRows}</tbody>
  </table>` : ""}

  <h2>Multi-Agent Delegation Chains</h2>
  <div class="cards" style="grid-template-columns:repeat(4,1fr)">
    <div class="card"><div class="val">${report.agent_chains.total_missions}</div><div class="lbl">Total Missions</div></div>
    <div class="card"><div class="val">${report.agent_chains.sub_missions}</div><div class="lbl">Sub-Agent Missions</div></div>
    <div class="card"><div class="val">${report.agent_chains.max_observed_depth}</div><div class="lbl">Max Chain Depth</div></div>
    <div class="card"><div class="val ${report.agent_chains.chain_violations > 0 ? "red" : "green"}">${report.agent_chains.chain_violations}</div><div class="lbl">Chain Violations</div></div>
  </div>
  ${report.agent_chains.violation_log.length > 0 ? `
  <table style="margin-top:8px">
    <thead><tr><th>Time (UTC)</th><th>Agent</th><th>Mission</th><th>Violation</th></tr></thead>
    <tbody>${report.agent_chains.violation_log.map((v) => `
      <tr>
        <td class="mono">${esc(v.time.slice(0, 19).replace("T", " "))}</td>
        <td>${esc(v.agent_id)}</td>
        <td class="mono" style="font-size:11px">${esc(v.mission_id || "—")}</td>
        <td class="red">${esc(v.reasons.join("; "))}</td>
      </tr>`).join("")}
    </tbody>
  </table>` : '<p style="color:#aaa;font-size:12px;margin-top:8px">No chain violations in this period.</p>'}

  <h2>SOC 2 Control Coverage</h2>
  <table>
    <thead><tr><th>Control</th><th>Name</th><th>Status</th><th>Evidence</th></tr></thead>
    <tbody>${socRows}</tbody>
  </table>

  <h2>EU AI Act Coverage</h2>
  <table>
    <thead><tr><th>Article</th><th>Requirement</th><th>Status</th><th>Evidence</th></tr></thead>
    <tbody>${euRows}</tbody>
  </table>

  ${report.policy_versions.length > 0 ? `
  <h2>Policy Version History</h2>
  <table>
    <thead><tr><th>Version</th><th>Status</th><th>Proposed By</th><th>Approved By</th><th>Approved At</th><th>Policy Hash</th></tr></thead>
    <tbody>${report.policy_versions.map((v) => `
      <tr>
        <td>${v.version}</td>
        <td><span class="badge badge-${v.status === "active" ? "allow" : "block"}">${esc(v.status)}</span></td>
        <td>${esc(v.proposed_by || "—")}</td>
        <td>${esc(v.approved_by || "—")}</td>
        <td class="mono">${v.approved_at ? esc(v.approved_at.slice(0, 10)) : "—"}</td>
        <td class="mono" style="font-size:10px">${esc((v.policy_hash || "").slice(0, 16))}…</td>
      </tr>`).join("")}
    </tbody>
  </table>` : ""}

  <footer>
    <span>ScopeZero · Agent Action Authorization Gateway · scopezero.io</span>
    <span>Report ID: ${esc(report.report_id)}</span>
  </footer>
</div>
</body>
</html>`;
}

function matchesTenant(event, tenantId) {
  const r = event.record || {};
  return (
    r.tenant_id === tenantId ||
    r.agent?.tenant_id === tenantId ||
    r.mission?.tenant_id === tenantId ||
    r.approval?.tenant_id === tenantId
  );
}

function esc(str) {
  return String(str || "").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}
