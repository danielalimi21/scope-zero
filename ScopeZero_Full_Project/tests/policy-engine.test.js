import test from "node:test";
import assert from "node:assert/strict";
import policy from "../config/defaultPolicy.json" with { type: "json" };
import { describeActionRequest } from "../src/actionAuthorization.js";
import { evaluatePolicy } from "../src/policyEngine.js";

const agent = {
  tenant_id: "tenant_contoso",
  agent_id: "agent.test",
  allowed_tools: ["drive.read", "slack.draft"]
};

const mission = {
  id: "mission_test",
  status: "active",
  allowed_tools: ["drive.read", "slack.draft"],
  allowed_data_classes: ["public", "internal", "confidential"],
  allowed_destinations: ["diligence-room.contoso.example"],
  action_contracts: [
    {
      id: "read-contract",
      tools: ["drive.read"],
      operations: ["read"],
      data_classes: ["public", "internal", "confidential"],
      destinations: ["diligence-room.contoso.example"],
      effect: "allow"
    },
    {
      id: "draft-contract",
      tools: ["slack.draft"],
      operations: ["draft"],
      data_classes: ["public", "internal", "confidential"],
      destinations: ["diligence-room.contoso.example"],
      effect: "allow"
    }
  ]
};

test("policy allows mission-aligned internal read", () => {
  const request = {
    tool: "drive.read",
    action: "Read diligence file",
    operation: "read",
    context: { mission_aligned: true },
    action_descriptor: describeActionRequest({ tool: "drive.read", action: "Read diligence file", operation: "read" }, { label: "internal" }, policy)
  };

  const verdict = evaluatePolicy({
    request,
    mission,
    agent,
    policy,
    classification: { level: 2, label: "internal", findings: [] },
    promptInfluence: { influenced: false, origin: "unknown", matched_patterns: [] },
    missionAlignment: { aligned: true, score: 0.6, source: "server_deterministic", reasons: [] },
    externalDestination: false,
    currentSessionRisk: 0
  });

  assert.equal(verdict.decision, "allow");
  assert.equal(verdict.safe_to_execute, true);
  assert.equal(verdict.matched_contract_id, "read-contract");
});

test("policy blocks restricted external egress outside mission", () => {
  const request = {
    tool: "gmail.send",
    action: "Send raw customer revenue externally",
    operation: "external_send",
    destination: { type: "email", address: "outside@example.com", external: true },
    context: { mission_aligned: false },
    action_descriptor: describeActionRequest(
      {
        tool: "gmail.send",
        action: "Send raw customer revenue externally",
        operation: "external_send",
        destination: { type: "email", address: "outside@example.com", external: true }
      },
      { label: "restricted" },
      policy
    )
  };

  const verdict = evaluatePolicy({
    request,
    mission,
    agent,
    policy,
    classification: { level: 5, label: "restricted", findings: [{ code: "restricted" }] },
    promptInfluence: { influenced: true, origin: "pdf.hidden_text", matched_patterns: ["send to external"] },
    missionAlignment: { aligned: false, score: 0, source: "server_deterministic", reasons: ["external-send-not-in-objective"] },
    externalDestination: true,
    currentSessionRisk: 0
  });

  assert.equal(verdict.decision, "block");
  assert.equal(verdict.safe_to_execute, false);
  assert.ok(verdict.reasons.some((reason) => reason.code === "sensitive-egress"));
});

test("lexical mission drift escalates to human approval (advisory), never blocks on its own", () => {
  const driftMission = {
    ...mission,
    allowed_tools: ["slack.draft"],
    action_contracts: [
      {
        id: "draft-contract",
        tools: ["slack.draft"],
        operations: ["draft"],
        data_classes: ["public", "internal"],
        destinations: ["diligence-room.contoso.example"],
        effect: "allow"
      }
    ]
  };
  const request = {
    tool: "slack.draft",
    action: "Post payroll restructuring plan",
    operation: "draft",
    context: { mission_aligned: true },
    action_descriptor: describeActionRequest(
      {
        tool: "slack.draft",
        action: "Post payroll restructuring plan",
        operation: "draft",
        destination: { type: "slack", address: "diligence-room.contoso.example" }
      },
      { label: "internal" },
      policy
    )
  };

  const verdict = evaluatePolicy({
    request,
    mission: driftMission,
    agent: { ...agent, allowed_tools: ["slack.draft"] },
    policy,
    classification: { level: 2, label: "internal", findings: [] },
    promptInfluence: { influenced: false, origin: "unknown", matched_patterns: [] },
    missionAlignment: { aligned: false, score: 0, source: "server_deterministic", reasons: ["low-objective-overlap"] },
    externalDestination: false,
    currentSessionRisk: 0
  });

  // A keyword-overlap heuristic must not block by itself; it routes to a human.
  // The deterministic contract gates are what block.
  assert.equal(verdict.decision, "approval");
  assert.equal(verdict.safe_to_execute, false);
  assert.ok(verdict.reasons.some((reason) => reason.code === "intent-drift-advisory"));
});

// The exfil-to-an-allowed-host case: every contract gate is satisfied (the tool,
// operation, data class, and destination are all in scope) and the keyword
// classifier sees nothing sensitive — yet the content is leaving for an external
// host. A blind "public" must not be an automatic allow. This is the control that
// closes the hole the host-only proxy cannot see.
test("unknown-class content leaving for an in-contract external host is held for review, not auto-allowed", () => {
  const egressMission = {
    id: "mission_egress",
    status: "active",
    allowed_tools: ["github.write"],
    allowed_data_classes: ["public", "internal"],
    allowed_destinations: ["api.github.com"],
    action_contracts: [
      {
        id: "gh-write",
        tools: ["github.write"],
        operations: ["write"],
        data_classes: ["public", "internal"],
        destinations: ["api.github.com"],
        effect: "allow"
      }
    ]
  };
  const request = {
    tool: "github.write",
    action: "Create a gist with the export",
    operation: "write",
    payload: { content: "id,amount\n1,4193\n2,5521\n3,8840" }, // sensitive rows, no trigger keyword
    action_descriptor: {
      schema: "scopezero.action_authorization.v1",
      tool: "github.write",
      action: "Create a gist with the export",
      operation: "write",
      action_type: "write",
      data_class: "public",
      data_rank: 1,
      destination: { type: "url", address: "api.github.com", external: true },
      // Manifest present (so the mutating-manifest gate is satisfied) but it does
      // not declare an output class — so the egress class is genuinely unknown.
      tool_manifest: { tool_id: "github.write", operation: "write", action_type: "write", data_out_classes: [] }
    }
  };

  const verdict = evaluatePolicy({
    request,
    mission: egressMission,
    agent: { ...agent, allowed_tools: ["github.write"] },
    policy,
    classification: { level: 1, label: "public", findings: [] },
    promptInfluence: { influenced: false, origin: "unknown", matched_patterns: [] },
    missionAlignment: { aligned: true, score: 0.5, source: "server_deterministic", reasons: [] },
    externalDestination: true,
    currentSessionRisk: 0
  });

  assert.equal(verdict.decision, "approval");
  assert.equal(verdict.safe_to_execute, false);
  assert.ok(verdict.reasons.some((reason) => reason.code === "unverified-egress-class"));
});

// Read-only inferred operations stay autonomous — the fail-closed-on-unknown rule
// must not turn every external read into an approval.
test("an in-contract external read with no payload stays an automatic allow", () => {
  const readMission = {
    id: "mission_read",
    status: "active",
    allowed_tools: ["api.fetch"],
    allowed_data_classes: ["public", "internal"],
    allowed_destinations: ["api.github.com"],
    action_contracts: [
      { id: "fetch", tools: ["api.fetch"], operations: ["read"], data_classes: ["public", "internal"], destinations: ["api.github.com"], effect: "allow" }
    ]
  };
  const request = {
    tool: "api.fetch",
    action: "Read issue list",
    operation: "read",
    action_descriptor: {
      schema: "scopezero.action_authorization.v1",
      tool: "api.fetch",
      action: "Read issue list",
      operation: "read",
      action_type: "read",
      data_class: "public",
      data_rank: 1,
      destination: { type: "url", address: "api.github.com", external: true },
      tool_manifest: { tool_id: "api.fetch", operation: "read", action_type: "read", data_out_classes: ["public"] }
    }
  };

  const verdict = evaluatePolicy({
    request,
    mission: readMission,
    agent: { ...agent, allowed_tools: ["api.fetch"] },
    policy,
    classification: { level: 1, label: "public", findings: [] },
    promptInfluence: { influenced: false, origin: "unknown", matched_patterns: [] },
    missionAlignment: { aligned: true, score: 0.5, source: "server_deterministic", reasons: [] },
    externalDestination: true,
    currentSessionRisk: 0
  });

  assert.equal(verdict.decision, "allow");
});
