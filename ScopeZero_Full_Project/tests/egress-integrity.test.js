import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { createRuntime } from "../src/runtime.js";
import { isExternalDestination } from "../src/sensitiveData.js";

// Regression tests for the egress-integrity hardening (Assignment A1): a
// prompt-injected agent must not be able to defeat the laundering guard by
// rotating the caller-supplied session_id, nor suppress the egress guards by
// self-declaring an external destination as "internal".

const TENANT = "tenant_contoso";
const AGENT = "agent.ma-diligence.72f1";

// A manifested "public" tool that writes to an in-contract external host. This is
// the realistic exfil channel: the tool is registered/legit, so the
// unmanifested-mutation backstop does NOT fire — only the taint guard stands
// between a tainted session and a laundered external write.
const manifests = {
  "statuspage.update": {
    tool_id: "statuspage.update",
    operation: "write",
    action_type: "write",
    data_out_classes: ["public"],
    mutating: true
  }
};

async function withRuntime(run) {
  const rootDir = await fs.mkdtemp(path.join(os.tmpdir(), "scopezero-egress-"));
  const runtime = await createRuntime({
    rootDir,
    signingSecret: "egress-secret",
    toolManifestResolver: (tool) => manifests[tool] || null
  });
  try {
    await run(runtime);
  } finally {
    await fs.rm(rootDir, { recursive: true, force: true });
  }
}

async function launderMission(runtime) {
  await runtime.registerAgent({
    tenant_id: TENANT,
    agent_id: AGENT,
    owner: "vp.strategy@contoso.example",
    allowed_tools: ["drive.read", "statuspage.update"]
  });
  const { capsule } = await runtime.createMission({
    tenant_id: TENANT,
    agent_id: AGENT,
    delegated_by: "vp.strategy@contoso.example",
    objective: "Read diligence docs and post public status updates to the partner status page.",
    allowed_tools: ["drive.read", "statuspage.update"],
    allowed_data_classes: ["public", "internal", "confidential"],
    allowed_destinations: ["diligence-room.contoso.example", "status.partner.example"],
    // The mission's intended public-broadcast destination — the explicit opt-out of
    // the default egress seal. Taint/laundering guards still apply on top of it.
    public_egress_destinations: ["status.partner.example"]
  });
  return capsule;
}

// The laundered payload: real confidential numbers rewritten as benign prose —
// no keyword, no Luhn card, no value pattern, well under every shape threshold.
// The bytes are genuinely benign; only the session's prior exposure betrays it.
const LAUNDERED = "Quick note: the northwest account sits near one hundred eighty-two thousand, the midwest one closer to ninety-four thousand, and the southern flagship is the big one at just over five hundred forty thousand. Trending up this quarter.";

test("ingest-taint survives a fresh caller-supplied session_id under the same mission", async () => {
  await withRuntime(async (runtime) => {
    const capsule = await launderMission(runtime);

    // Read confidential material on session A.
    await runtime.evaluateToolCall({
      tenant_id: TENANT, agent_id: AGENT, mission_id: capsule.id, session_id: "sessionA",
      tool: "drive.read", action: "Read confidential target financials", operation: "read",
      payload: { text: "Confidential: attorney-client privileged acquisition memo, customer revenue by account" },
      destination: { type: "resource", address: "diligence-room.contoso.example" }
    });

    // Launder the same data out on a DIFFERENT session_id — the historical bypass.
    const laundered = await runtime.evaluateToolCall({
      tenant_id: TENANT, agent_id: AGENT, mission_id: capsule.id, session_id: "sessionB-fresh",
      tool: "statuspage.update", action: "Post public status", operation: "write",
      payload: { summary: LAUNDERED },
      destination: { type: "url", address: "status.partner.example" }
    });

    assert.notEqual(laundered.decision, "allow", "fresh session_id must not reset mission-scoped taint");
    assert.ok(
      laundered.verdict.reasons.some((r) => r.code === "tainted-session-egress"),
      `expected tainted-session-egress, got: ${laundered.verdict.reasons.map((r) => r.code).join(", ")}`
    );
  });
});

test("a clean mission with no prior confidential ingest still auto-allows benign public egress", async () => {
  await withRuntime(async (runtime) => {
    const capsule = await launderMission(runtime);
    // No confidential read first — a genuinely public status post must stay autonomous.
    const post = await runtime.evaluateToolCall({
      tenant_id: TENANT, agent_id: AGENT, mission_id: capsule.id, session_id: "clean",
      tool: "statuspage.update", action: "Post public status", operation: "write",
      payload: { summary: "Status: review complete, all green." },
      destination: { type: "url", address: "status.partner.example" }
    });
    assert.equal(post.decision, "allow", `clean public egress should allow, got ${post.decision}: ${post.verdict.reasons.map((r) => r.code).join(", ")}`);
  });
});

test("a self-declared external=false cannot suppress external classification for an untrusted address", () => {
  const policy = { trusted_destinations: ["contoso.example"] };
  // Attacker stamps external:false on a pastebin write.
  assert.equal(isExternalDestination({ address: "pastebin.com", external: false }, policy), true);
  // A genuinely trusted internal host is still internal.
  assert.equal(isExternalDestination({ address: "diligence-room.contoso.example", external: false }, policy), false);
  // An explicit external assertion still raises.
  assert.equal(isExternalDestination({ address: "diligence-room.contoso.example", external: true }, policy), true);
});

test("a declared lower data_class cannot downgrade detected sensitivity past the contract", async () => {
  await withRuntime(async (runtime) => {
    const capsule = await launderMission(runtime);
    // Restricted content self-declared as "public" must still be treated as restricted.
    const result = await runtime.evaluateToolCall({
      tenant_id: TENANT, agent_id: AGENT, mission_id: capsule.id, session_id: "downgrade",
      tool: "statuspage.update", action: "Post status", operation: "write",
      data_class: "public",
      payload: { summary: "card 4111111111111111 ssn 123-45-6789" },
      destination: { type: "url", address: "status.partner.example" }
    });
    assert.notEqual(result.decision, "allow", "self-declared public must not downgrade detected restricted content");
  });
});
