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

// Laundering: read confidential data, then egress benign-looking prose to an
// in-contract external host. The outbound bytes are genuinely benign, so no
// content classifier can catch them — the session ingest-taint does, because the
// session was exposed to confidential material earlier.
test("ingest-taint guard holds a benign-looking egress after the session read confidential data", async () => {
  const rootDir = await fs.mkdtemp(path.join(os.tmpdir(), "scopezero-taint-"));
  const manifests = {
    "github.sync": { tool_id: "github.sync", operation: "write", action_type: "write", data_out_classes: ["public"], mutating: true }
  };
  const runtime = await createRuntime({ rootDir, signingSecret: "taint-secret", toolManifestResolver: (tool) => manifests[tool] || null });
  try {
    await runtime.registerAgent({ tenant_id: "tenant_contoso", agent_id: "agent.diligence.1", owner: "vp@contoso.example", allowed_tools: ["drive.read", "github.sync"] });
    const { capsule } = await runtime.createMission({
      tenant_id: "tenant_contoso",
      agent_id: "agent.diligence.1",
      delegated_by: "vp@contoso.example",
      objective: "Read diligence docs and write public status updates to api.github.com.",
      allowed_tools: ["drive.read", "github.sync"],
      allowed_data_classes: ["public", "internal", "confidential"],
      allowed_destinations: ["diligence-room.contoso.example", "api.github.com"]
    });
    const call = (extra) => runtime.evaluateToolCall({
      tenant_id: "tenant_contoso", agent_id: "agent.diligence.1", mission_id: capsule.id, ...extra
    });

    // 1. Read confidential material into the session (in-contract, allowed).
    const read = await call({
      tool: "drive.read", action: "Read confidential target financials", operation: "read",
      payload: { text: "Confidential: attorney-client privileged acquisition memo" },
      destination: { type: "resource", address: "diligence-room.contoso.example" }
    });
    assert.equal(read.decision, "allow");
    assert.ok(read.verdict.session_ingested_class_rank >= 4, "session tainted to confidential");

    // 2. Egress short, benign-looking prose to the in-contract external host.
    const egress = await call({
      tool: "github.sync", action: "Write public build status", operation: "write",
      payload: { summary: "Status: review complete, all green." },
      destination: { type: "url", address: "api.github.com" }
    });
    assert.equal(egress.decision, "approval");
    assert.equal(egress.verdict.safe_to_execute, false);
    assert.ok(egress.verdict.reasons.some((r) => r.code === "tainted-session-egress"));
  } finally {
    await fs.rm(rootDir, { recursive: true, force: true });
  }
});

// The pluggable classifier raises the class on content the English regex misses
// (here: a non-English confidentiality marker), and the existing egress gate acts.
test("an external classifier verdict raises the data class and the egress gate acts on it", async () => {
  const rootDir = await fs.mkdtemp(path.join(os.tmpdir(), "scopezero-classifier-"));
  const runtime = await createRuntime({
    rootDir,
    signingSecret: "classifier-secret",
    classifierResolver: ({ payload }) =>
      JSON.stringify(payload || {}).includes("totalmente confidencial")
        ? { level: 5, findings: ["external_classifier_restricted"], established: true, source: "test-embedding" }
        : null
  });
  try {
    await runtime.registerAgent({ tenant_id: "tenant_contoso", agent_id: "agent.intl.1", owner: "vp@contoso.example", allowed_tools: ["gmail.send"] });
    const { capsule } = await runtime.createMission({
      tenant_id: "tenant_contoso",
      agent_id: "agent.intl.1",
      delegated_by: "vp@contoso.example",
      objective: "Summarize and post public updates externally.",
      allowed_tools: ["gmail.send"],
      allowed_data_classes: ["public", "internal"],
      allowed_destinations: ["partner.example"]
    });
    const result = await runtime.evaluateToolCall({
      tenant_id: "tenant_contoso", agent_id: "agent.intl.1", mission_id: capsule.id,
      tool: "gmail.send", action: "Send summary externally", operation: "external_send",
      // English regex finds nothing sensitive here; the external classifier does.
      payload: { text: "Resumen: este documento es totalmente confidencial." },
      destination: { type: "email", address: "outsider@gmail.com", external: true }
    });
    assert.equal(result.decision, "block");
    assert.ok(result.verdict.action_descriptor.data_class === "restricted" || result.verdict.reasons.some((r) => r.code === "sensitive-egress"));
  } finally {
    await fs.rm(rootDir, { recursive: true, force: true });
  }
});
