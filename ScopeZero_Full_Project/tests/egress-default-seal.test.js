import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import basePolicy from "../config/defaultPolicy.json" with { type: "json" };
import { classifyPayload } from "../src/sensitiveData.js";
import { describeActionRequest } from "../src/actionAuthorization.js";
import { evaluatePolicy } from "../src/policyEngine.js";
import { createRuntime } from "../src/runtime.js";

// Regression tests for the egress-hardening pass:
//  - value detectors no longer evaded by separator style or trivial encoding
//  - external egress fails CLOSED by default, independent of data clearance
//  - autonomy is an explicit public-sink opt-in
//  - the runtime risk budget is mission-scoped (can't be reset by session_id)

// ── Value detectors: separator + encoding evasion ────────────────────────────

test("a card number split by dots is detected (separator evasion closed)", () => {
  assert.equal(classifyPayload({ s: "ref 4012.8888.8888.1881 ok" }).label, "restricted");
});

test("a card number split by spaces across words is detected", () => {
  assert.equal(classifyPayload({ s: "the code is 4012 8888 8888 1881 thanks" }).label, "restricted");
});

test("a base64-wrapped AWS key is decoded and detected", () => {
  const wrapped = Buffer.from("AKIAIOSFODNN7EXAMPLE").toString("base64");
  const result = classifyPayload({ s: `cfg ${wrapped} ok` });
  assert.equal(result.label, "restricted");
  assert.ok(result.findings.includes("api_secret"));
});

test("a hex-wrapped GitHub token is decoded and detected", () => {
  const wrapped = Buffer.from(`ghp_${"a".repeat(36)}`).toString("hex");
  assert.equal(classifyPayload({ s: `tok ${wrapped}` }).label, "restricted");
});

test("ordinary prose and identifiers do not false-positive after the decode pass", () => {
  assert.equal(classifyPayload({ s: "all green this week, shipping on schedule" }).label, "public");
  assert.equal(classifyPayload({ order: "order 482915037 shipped" }).label, "public");
});

// ── Default-on external-egress seal, decoupled from data clearance ────────────

const agent = { tenant_id: "t", agent_id: "a", allowed_tools: ["statuspage.update"] };

function verdictFor({ dataClasses, publicSinks = [], payload = { summary: "all green" }, address = "status.partner.example" }) {
  const policy = { ...basePolicy, require_manifest_for_mutating: false, require_manifest_for_high_impact: false };
  const mission = {
    id: "m1", status: "active", allowed_tools: ["statuspage.update"],
    allowed_data_classes: dataClasses, allowed_destinations: [address],
    public_egress_destinations: publicSinks,
    action_contracts: [{ id: "c", tools: ["statuspage.update"], operations: ["write"], data_classes: dataClasses, destinations: [address], effect: "allow" }]
  };
  const classification = classifyPayload(payload);
  const descriptor = describeActionRequest({ tool: "statuspage.update", action: "Post", operation: "write", destination: { type: "url", address }, payload }, classification, policy);
  return evaluatePolicy({
    request: { tool: "statuspage.update", action: "Post", operation: "write", payload, destination: { type: "url", address }, action_descriptor: descriptor },
    mission, agent, policy, classification,
    promptInfluence: { influenced: false, origin: "unknown", matched_patterns: [] },
    missionAlignment: { aligned: true, score: 0.6, source: "server_deterministic", reasons: [] },
    externalDestination: true, currentSessionRisk: 0, sessionIngestedClassRank: 0
  });
}

test("external egress is sealed by default even for a public/internal-only mission", () => {
  // The hole this closes: a narrow (non-confidential) mission used to get NO
  // laundering protection because the seal was clearance-gated.
  const v = verdictFor({ dataClasses: ["public", "internal"] });
  assert.equal(v.decision, "approval");
  assert.ok(v.reasons.some((r) => r.code === "external-egress-sealed"));
});

test("external egress is sealed by default for a confidential-cleared mission too", () => {
  const v = verdictFor({ dataClasses: ["public", "internal", "confidential"] });
  assert.equal(v.decision, "approval");
});

test("a declared public-broadcast sink keeps its lane autonomous", () => {
  const v = verdictFor({ dataClasses: ["public", "internal"], publicSinks: ["status.partner.example"] });
  assert.equal(v.decision, "allow", `expected allow for declared sink, got ${v.decision}: ${v.reasons.map((r) => r.code).join(", ")}`);
});

test("a detected value still blocks even when the destination is a declared sink (defense in depth)", () => {
  const v = verdictFor({ dataClasses: ["public", "internal"], publicSinks: ["status.partner.example"], payload: { summary: "card 4012.8888.8888.1881" } });
  assert.notEqual(v.decision, "allow");
});

// ── Risk budget is mission-scoped (mirrors ingest-taint) ─────────────────────

test("accumulated risk budget cannot be reset by rotating the caller session_id", async () => {
  const rootDir = await fs.mkdtemp(path.join(os.tmpdir(), "sz-risk-"));
  try {
    const runtime = await createRuntime({ rootDir, signingSecret: "risk-secret" });
    const TENANT = "tenant_contoso", AGENT = "agent.risk";
    await runtime.registerAgent({ tenant_id: TENANT, agent_id: AGENT, owner: "o", allowed_tools: ["drive.read"] });
    const { capsule } = await runtime.createMission({
      tenant_id: TENANT, agent_id: AGENT, delegated_by: "o", objective: "read the data room",
      allowed_tools: ["drive.read"], allowed_data_classes: ["public", "internal", "confidential"],
      allowed_destinations: ["diligence-room.contoso.example"]
    });
    // Burn risk under one session_id.
    let last;
    for (let i = 0; i < 8; i++) {
      last = await runtime.evaluateToolCall({
        tenant_id: TENANT, agent_id: AGENT, mission_id: capsule.id, session_id: `burn-${i}`,
        tool: "drive.read", action: "read", operation: "read",
        payload: { text: "internal notes" }, destination: { type: "resource", address: "diligence-room.contoso.example" }
      });
    }
    // A brand-new session under the same mission must see the accumulated risk,
    // not a fresh zero budget.
    const fresh = await runtime.evaluateToolCall({
      tenant_id: TENANT, agent_id: AGENT, mission_id: capsule.id, session_id: "brand-new",
      tool: "drive.read", action: "read", operation: "read",
      payload: { text: "internal notes" }, destination: { type: "resource", address: "diligence-room.contoso.example" }
    });
    assert.ok(fresh.verdict.session_risk > last.verdict.risk_contribution, "fresh session_id must inherit mission-scoped accumulated risk");
  } finally {
    await fs.rm(rootDir, { recursive: true, force: true });
  }
});
