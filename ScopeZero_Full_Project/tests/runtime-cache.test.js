import test from "node:test";
import assert from "node:assert/strict";
import policy from "../config/defaultPolicy.json" with { type: "json" };
import { createMissionCapsule } from "../src/capsules.js";
import { ScopeZeroRuntime } from "../src/runtime.js";

test("runtime caches repeated equivalent decisions for the hot path", async () => {
  const signingSecret = "test-secret";
  const mission = createMissionCapsule(
    {
      tenant_id: "tenant_contoso",
      agent_id: "agent.cache",
      delegated_by: "security@example.com",
      objective: "Read the approved diligence document.",
      allowed_tools: ["drive.read"],
      allowed_data_classes: ["public", "internal"],
      allowed_destinations: ["diligence-room.contoso.example"],
      action_contracts: [
        {
          id: "read-contract",
          tools: ["drive.read"],
          operations: ["read"],
          data_classes: ["public", "internal"],
          destinations: ["diligence-room.contoso.example"],
          effect: "allow"
        }
      ]
    },
    signingSecret
  );
  const ledgerEvents = [];
  const runtime = new ScopeZeroRuntime({
    signingSecret,
    ledger: {
      async append(record) {
        ledgerEvents.push(record);
        return { id: `event_${ledgerEvents.length}`, hash: `hash_${ledgerEvents.length}`, record };
      }
    },
    store: {
      getPolicy() {
        return { ...policy, decision_cache_ttl_ms: 60_000 };
      },
      getAgent() {
        return {
          tenant_id: "tenant_contoso",
          agent_id: "agent.cache",
          allowed_tools: ["drive.read"]
        };
      },
      getMission() {
        return mission;
      },
      getSessionRisk() {
        return 0;
      },
      async updateSessionRisk(_sessionId, contribution) {
        return contribution;
      },
      async addApproval() {
        throw new Error("approval should not be created for cached allow");
      },
      async recordDecision() {},
      getBehaviorProfile() { return null; },
      async recordToolCall() {}
    }
  });

  const input = {
    tenant_id: "tenant_contoso",
    agent_id: "agent.cache",
    mission_id: mission.id,
    tool: "drive.read",
    action: "Read diligence document",
    operation: "read",
    payload: { text: "internal summary" },
    destination: { type: "resource", address: "diligence-room.contoso.example" },
    context: { mission_aligned: true }
  };

  const first = await runtime.evaluateToolCall(input);
  const second = await runtime.evaluateToolCall(input);

  assert.equal(first.decision, "allow");
  assert.equal(second.decision, "allow");
  assert.equal(second.verdict.cache.status, "hit");
  assert.ok(second.verdict.controls.includes("decision-cache-hit"));
  assert.equal(ledgerEvents.length, 2);
});
