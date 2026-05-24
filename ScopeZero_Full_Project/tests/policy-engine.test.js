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
    externalDestination: true,
    currentSessionRisk: 0
  });

  assert.equal(verdict.decision, "block");
  assert.equal(verdict.safe_to_execute, false);
  assert.ok(verdict.reasons.some((reason) => reason.code === "sensitive-egress"));
});
