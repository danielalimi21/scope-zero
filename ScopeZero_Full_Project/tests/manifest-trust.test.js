import test from "node:test";
import assert from "node:assert/strict";
import policy from "../config/defaultPolicy.json" with { type: "json" };
import { evaluatePolicy } from "../src/policyEngine.js";

// A high-impact action on a tool with no authoritative manifest is escalated,
// not silently trusted — the operation was inferred from the agent's own input.

const baseArgs = (actionDescriptor) => ({
  request: { base_risk: 8, action_descriptor: actionDescriptor },
  mission: { status: "active", allowed_tools: [actionDescriptor.tool], allowed_data_classes: ["public", "internal"], action_contracts: [] },
  agent: { agent_id: "a1" },
  policy: { ...policy, action_contracts_required: false, strict_data_class_enforcement: false, strict_destination_enforcement: false, mission_lock: false, prompt_injection_shield: false },
  classification: { level: 1, label: "public" },
  promptInfluence: { influenced: false },
  missionAlignment: { aligned: true },
  externalDestination: false,
  currentSessionRisk: 0
});

test("unmanifested high-impact action escalates to approval", () => {
  const verdict = evaluatePolicy(baseArgs({
    tool: "custom.wire_money",
    action_type: "payment",
    operation: "payment",
    operation_source: "fallback_inference",
    tool_manifest: null
  }));
  assert.ok(verdict.controls.includes("unmanifested-high-impact"));
  assert.equal(verdict.decision, "approval");
});

test("manifested high-impact action is not flagged by the manifest rule", () => {
  const verdict = evaluatePolicy(baseArgs({
    tool: "gmail.send",
    action_type: "external_send",
    operation: "external_send",
    operation_source: "tool_manifest",
    tool_manifest: { tool_id: "gmail.send", operation: "external_send" }
  }));
  assert.ok(!verdict.controls.includes("unmanifested-high-impact"));
});

test("unmanifested low-impact action is not escalated by the manifest rule", () => {
  const verdict = evaluatePolicy(baseArgs({
    tool: "custom.read_notes",
    action_type: "read",
    operation: "read",
    operation_source: "fallback_inference",
    tool_manifest: null
  }));
  assert.ok(!verdict.controls.includes("unmanifested-high-impact"));
});
