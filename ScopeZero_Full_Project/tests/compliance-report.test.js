import test from "node:test";
import assert from "node:assert/strict";
import { generateComplianceReport } from "../src/complianceReport.js";

function makeLedger(events = []) {
  return {
    async list() { return events; },
    async verify() { return { valid: true, entries: events.length, chain_root: "abc123", failures: [] }; }
  };
}

function makeStore(overrides = {}) {
  return {
    state: {
      tenants: [{ tenant_id: "tenant_contoso", name: "Contoso", plan: "enterprise" }],
      agents: [{ tenant_id: "tenant_contoso", agent_id: "agent.test", owner: "test@co.com" }],
      missions: [],
      approvals: [],
      policy_versions: [],
      policies: {},
      metrics: {},
      sessions: {},
      ...overrides
    }
  };
}

function authEvent(overrides = {}) {
  return {
    id: `evt_${Math.random().toString(36).slice(2)}`,
    time: new Date().toISOString(),
    hash: "hashvalue",
    record: {
      event_type: "action_authorization.evaluated",
      tenant_id: "tenant_contoso",
      agent_id: "agent.test",
      tool: "gmail.send",
      action: "Send summary",
      verdict: { decision: "allow", risk_score: 20, reasons: [], safe_to_execute: true },
      ...overrides.record
    }
  };
}

test("compliance report generates executive summary from ledger events", async () => {
  const events = [
    authEvent({ record: { event_type: "action_authorization.evaluated", tenant_id: "tenant_contoso", agent_id: "agent.test", tool: "gmail.send", action: "send", verdict: { decision: "allow", risk_score: 15, reasons: [] } } }),
    authEvent({ record: { event_type: "action_authorization.evaluated", tenant_id: "tenant_contoso", agent_id: "agent.test", tool: "drive.read", action: "read", verdict: { decision: "block", risk_score: 80, reasons: [{ code: "sensitive-egress", message: "Sensitive data attempted to cross an external boundary." }] } } }),
    authEvent({ record: { event_type: "action_authorization.evaluated", tenant_id: "tenant_contoso", agent_id: "agent.test", tool: "slack.draft", action: "post", verdict: { decision: "approval", risk_score: 45, reasons: [{ code: "high-impact-action", message: "Action requires human approval." }] } } })
  ];

  const report = await generateComplianceReport({
    ledger: makeLedger(events),
    store: makeStore(),
    tenantId: "tenant_contoso",
    format: "json"
  });

  assert.equal(report.executive_summary.total_agent_actions, 3);
  assert.equal(report.executive_summary.allowed, 1);
  assert.equal(report.executive_summary.blocked, 1);
  assert.equal(report.executive_summary.human_approvals_required, 1);
  assert.equal(report.executive_summary.sensitive_egress_attempts, 1);
  assert.equal(report.executive_summary.block_rate_percent, 33.3);
});

test("compliance report includes SOC2 and EU AI Act coverage", async () => {
  const report = await generateComplianceReport({
    ledger: makeLedger([]),
    store: makeStore(),
    tenantId: "tenant_contoso",
    format: "json"
  });

  assert.ok(Array.isArray(report.compliance_mapping.SOC2));
  assert.ok(Array.isArray(report.compliance_mapping.EU_AI_Act));
  assert.ok(Array.isArray(report.compliance_mapping.HIPAA_relevant));
  assert.ok(report.compliance_mapping.SOC2.length >= 6);
  assert.ok(report.compliance_mapping.EU_AI_Act.length >= 5);
  assert.ok(report.compliance_mapping.SOC2.every((c) => c.control && c.status === "covered"));
});

test("compliance report includes ledger integrity result", async () => {
  const report = await generateComplianceReport({
    ledger: makeLedger([]),
    store: makeStore(),
    tenantId: "tenant_contoso",
    format: "json"
  });

  assert.equal(report.ledger_integrity.valid, true);
  assert.equal(report.ledger_integrity.failures, 0);
  assert.equal(report.ledger_integrity.chain_root, "abc123");
});

test("compliance report renders valid HTML with key sections", async () => {
  const events = [
    authEvent({ record: { event_type: "action_authorization.evaluated", tenant_id: "tenant_contoso", agent_id: "agent.test", tool: "gmail.send", action: "send", verdict: { decision: "block", risk_score: 90, reasons: [{ code: "prompt-influence", message: "Prompt injection detected." }] } } })
  ];

  const html = await generateComplianceReport({
    ledger: makeLedger(events),
    store: makeStore(),
    tenantId: "tenant_contoso",
    format: "html"
  });

  assert.ok(typeof html === "string");
  assert.ok(html.includes("<!DOCTYPE html>"));
  assert.ok(html.includes("ScopeZero"));
  assert.ok(html.includes("Compliance Audit Report"));
  assert.ok(html.includes("SOC 2 Control Coverage"));
  assert.ok(html.includes("EU AI Act Coverage"));
  assert.ok(html.includes("Evidence Ledger Integrity"));
  assert.ok(html.includes("VERIFIED"));
});

test("compliance report filters events by time period", async () => {
  const old = authEvent();
  old.time = "2020-01-01T00:00:00.000Z";
  old.record = { event_type: "action_authorization.evaluated", tenant_id: "tenant_contoso", agent_id: "agent.test", tool: "gmail.send", action: "old", verdict: { decision: "allow", risk_score: 10, reasons: [] } };

  const recent = authEvent();
  recent.record = { event_type: "action_authorization.evaluated", tenant_id: "tenant_contoso", agent_id: "agent.test", tool: "drive.read", action: "recent", verdict: { decision: "block", risk_score: 70, reasons: [] } };

  const report = await generateComplianceReport({
    ledger: makeLedger([old, recent]),
    store: makeStore(),
    tenantId: "tenant_contoso",
    from: "2024-01-01",
    format: "json"
  });

  // Old event from 2020 should be excluded
  assert.equal(report.executive_summary.total_agent_actions, 1);
  assert.equal(report.executive_summary.blocked, 1);
});

test("compliance report report_id is stable and period is correct", async () => {
  const report = await generateComplianceReport({
    ledger: makeLedger([]),
    store: makeStore(),
    tenantId: "tenant_contoso",
    from: "2025-01-01",
    to: "2025-03-31",
    format: "json"
  });

  assert.ok(report.report_id.startsWith("rpt_"));
  assert.ok(report.period.from.startsWith("2025-01-01"));
  assert.ok(report.period.to.startsWith("2025-03-31"));
  assert.equal(report.tenant_id, "tenant_contoso");
});
