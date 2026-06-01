import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { createRuntime } from "../src/runtime.js";

// Full-stack integration: a real SQLite Store + a real hash-chained Ledger,
// driven through createRuntime exactly as the server wires it. The cache test
// uses a mock store; this exercises persistence, the keyed ledger, and the end
// to-end evaluate path together.

async function withRuntime(run) {
  const rootDir = await fs.mkdtemp(path.join(os.tmpdir(), "scopezero-integration-"));
  const runtime = await createRuntime({ rootDir, signingSecret: "integration-secret" });
  try {
    await run(runtime, rootDir);
  } finally {
    await fs.rm(rootDir, { recursive: true, force: true });
  }
}

test("evaluateToolCall allows an in-scope call and persists tamper-evident evidence", async () => {
  await withRuntime(async (runtime) => {
    const { capsule } = await runtime.createMission({
      tenant_id: "tenant_contoso",
      agent_id: "agent.ma-diligence.72f1",
      delegated_by: "vp.strategy@contoso.example",
      objective: "Read diligence documents in the approved data room.",
      allowed_tools: ["drive.read"],
      allowed_data_classes: ["public", "internal", "confidential"],
      allowed_destinations: ["diligence-room.contoso.example"]
    });

    const result = await runtime.evaluateToolCall({
      tenant_id: "tenant_contoso",
      agent_id: "agent.ma-diligence.72f1",
      mission_id: capsule.id,
      tool: "drive.read",
      action: "Read diligence document from the data room",
      operation: "read",
      payload: { text: "internal diligence summary" },
      destination: { type: "resource", address: "diligence-room.contoso.example" }
    });

    assert.equal(result.decision, "allow");
    assert.equal(result.verdict.safe_to_execute, true);
    assert.ok(result.evidence_hash, "evidence hash recorded");

    // Real store persisted the behavior profile for the agent.
    const profile = runtime.store.getBehaviorProfile("tenant_contoso", "agent.ma-diligence.72f1");
    assert.ok(profile.tools["drive.read"].total_calls >= 1);

    // Keyed ledger chain verifies clean.
    const verify = await runtime.verifyLedger();
    assert.equal(verify.valid, true);
    assert.ok(verify.entries >= 2, "mission.issued + evaluation entries present");
  });
});

test("evaluateToolCall blocks a tool outside the mission contract", async () => {
  await withRuntime(async (runtime) => {
    const { capsule } = await runtime.createMission({
      tenant_id: "tenant_contoso",
      agent_id: "agent.ma-diligence.72f1",
      delegated_by: "vp.strategy@contoso.example",
      objective: "Read diligence documents only.",
      allowed_tools: ["drive.read"],
      allowed_data_classes: ["public", "internal"],
      allowed_destinations: ["diligence-room.contoso.example"]
    });

    const result = await runtime.evaluateToolCall({
      tenant_id: "tenant_contoso",
      agent_id: "agent.ma-diligence.72f1",
      mission_id: capsule.id,
      tool: "gmail.send",
      action: "Email confidential summary to personal gmail",
      operation: "external_send",
      payload: { text: "customer revenue and salary data" },
      destination: { type: "email", address: "exfil@gmail.com", external: true }
    });

    assert.equal(result.decision, "block");
    assert.equal(result.verdict.safe_to_execute, false);

    const verify = await runtime.verifyLedger();
    assert.equal(verify.valid, true);
  });
});

test("an invalid mission capsule is blocked end-to-end", async () => {
  await withRuntime(async (runtime) => {
    const { capsule } = await runtime.createMission({
      tenant_id: "tenant_contoso",
      agent_id: "agent.ma-diligence.72f1",
      delegated_by: "vp.strategy@contoso.example",
      objective: "Read diligence documents.",
      allowed_tools: ["drive.read"]
    });

    // Tamper the stored capsule signature directly in the store.
    const stored = runtime.store.getMission(capsule.id, "tenant_contoso");
    stored.signature = "sz1.deadbeef";

    const result = await runtime.evaluateToolCall({
      tenant_id: "tenant_contoso",
      agent_id: "agent.ma-diligence.72f1",
      mission_id: capsule.id,
      tool: "drive.read",
      action: "Read document",
      operation: "read",
      payload: { text: "x" }
    });

    assert.equal(result.decision, "block");
    assert.equal(result.verdict.reasons[0].code, "invalid-mission-capsule");
  });
});
