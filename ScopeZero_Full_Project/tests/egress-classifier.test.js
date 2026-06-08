import test from "node:test";
import assert from "node:assert/strict";
import basePolicy from "../config/defaultPolicy.json" with { type: "json" };
import { classifyPayload } from "../src/sensitiveData.js";
import { describeActionRequest } from "../src/actionAuthorization.js";
import { evaluatePolicy } from "../src/policyEngine.js";

// ── Broadened structured value detection (A2) ────────────────────────────────
// Each is classified by its STRUCTURE with no topic keyword nearby.

test("value detector classifies a JWT with no keyword", () => {
  const jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dQw4w9WgXcQabc123def456";
  const result = classifyPayload({ note: `here is the token ${jwt}` });
  assert.equal(result.label, "restricted");
  assert.ok(result.findings.includes("api_secret"));
});

test("value detector classifies a Google API key and a Stripe live key", () => {
  const google = classifyPayload({ v: "AIzaSyA1234567890abcdefghijklmnopqrstuv0" });
  assert.equal(google.label, "restricted");
  const stripe = classifyPayload({ v: "sk_live_" + "51HxYzAbCdEfGhIjKlMnOpQrS" });
  assert.equal(stripe.label, "restricted");
});

test("value detector classifies a GitLab PAT and an AWS temporary key", () => {
  assert.equal(classifyPayload({ v: "glpat-" + "ABCDEF1234567890abcd" }).label, "restricted");
  assert.equal(classifyPayload({ v: "ASIAZZZZZZZZZZZZZZZZ" }).label, "restricted");
});

test("value detector does not flag an ordinary 9-digit order number (no SSN false positive)", () => {
  const result = classifyPayload({ order: "order 482915037 shipped" });
  assert.equal(result.label, "public");
  assert.equal(result.established, true);
});

// ── Sensitive-mission egress seal (A2) ───────────────────────────────────────
// Closes the residual: a confidential-cleared mission posting benign-looking
// (laundered) prose to an external host. The bytes are "established public", so
// only the mission's data clearance can trigger the hold.

const sealMission = {
  id: "mission_seal",
  status: "active",
  allowed_tools: ["statuspage.update", "broadcast.public"],
  allowed_data_classes: ["public", "internal", "confidential"],
  allowed_destinations: ["status.partner.example", "press.example"],
  action_contracts: [
    {
      id: "status-contract",
      tools: ["statuspage.update"],
      operations: ["write", "draft", "execute"],
      data_classes: ["public", "internal", "confidential"],
      destinations: ["status.partner.example"],
      effect: "allow"
    },
    {
      id: "press-contract",
      tools: ["broadcast.public"],
      operations: ["write", "draft", "execute"],
      data_classes: ["public", "internal", "confidential"],
      destinations: ["press.example"],
      effect: "allow",
      public_egress_ok: true
    }
  ]
};

const agent = { tenant_id: "tenant_contoso", agent_id: "agent.test", allowed_tools: ["statuspage.update", "broadcast.public"] };

function sealedVerdict({ tool, address, payload, seal }) {
  const policy = { ...basePolicy, seal_sensitive_mission_egress: seal, require_manifest_for_mutating: false, require_manifest_for_high_impact: false };
  const classification = classifyPayload(payload);
  const descriptor = describeActionRequest(
    { tool, action: "Post status", operation: "write", destination: { type: "url", address }, payload },
    classification,
    policy
  );
  return evaluatePolicy({
    request: { tool, action: "Post status", operation: "write", payload, destination: { type: "url", address }, action_descriptor: descriptor },
    mission: sealMission,
    agent,
    policy,
    classification,
    promptInfluence: { influenced: false, origin: "unknown", matched_patterns: [] },
    missionAlignment: { aligned: true, score: 0.6, source: "server_deterministic", reasons: [] },
    externalDestination: true,
    currentSessionRisk: 0,
    sessionIngestedClassRank: 0
  });
}

const LAUNDERED = { summary: "Quick note: northwest near one eighty-two thousand, midwest near ninety-four thousand, southern flagship just over five forty thousand. Up this quarter." };

test("seal OFF: benign-looking external egress on a confidential mission auto-allows (default behavior)", () => {
  const v = sealedVerdict({ tool: "statuspage.update", address: "status.partner.example", payload: LAUNDERED, seal: false });
  assert.equal(v.decision, "allow");
});

test("seal ON: the same egress is held for review — establishment from bytes is not trusted", () => {
  const v = sealedVerdict({ tool: "statuspage.update", address: "status.partner.example", payload: LAUNDERED, seal: true });
  assert.equal(v.decision, "approval");
  assert.ok(v.reasons.some((r) => r.code === "sensitive-mission-egress-sealed"));
});

test("seal ON: a contract-declared public-broadcast sink stays autonomous", () => {
  const v = sealedVerdict({ tool: "broadcast.public", address: "press.example", payload: LAUNDERED, seal: true });
  assert.equal(v.decision, "allow", `expected allow for public sink, got ${v.decision}: ${v.reasons.map((r) => r.code).join(", ")}`);
});
