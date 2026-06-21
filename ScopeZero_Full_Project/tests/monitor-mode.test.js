// Monitor (observe / dry-run) mode: the gateway computes and records the true
// decision, but enforcement does NOT block — the action runs and the result is
// annotated with what enforce mode would have done. Lets a team deploy across a
// whole agent fleet with zero production risk, then flip to enforce.

import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { authorizeAndExecute } from "../sdk/guard-core.js";
import { evaluateProxyConnect } from "../src/proxyEnforcer.js";
import { createRuntime } from "../src/runtime.js";

const SECRET = "monitor-mode-secret";
const TENANT = "tenant_contoso";

// ── SDK guard: enforce blocks, monitor records-but-runs ─────────────────────
test("SDK enforce blocks a dangerous decision; monitor runs it and flags would_block", async () => {
  const blockingGateway = { authorizeAction: async () => ({ decision: "block", authorization_id: "a1", verdict: { reasons: [{ message: "out of scope" }] } }) };
  let ran = false;
  const handler = async () => { ran = true; return "executed"; };

  // enforce: must not run
  const enforce = await authorizeAndExecute({ sz: blockingGateway, tool: "x", action: "y", payload: {}, handler });
  assert.equal(enforce.executed, false);
  assert.equal(ran, false);

  // monitor (explicit flag): runs, annotates
  ran = false;
  const monitor = await authorizeAndExecute({ sz: blockingGateway, tool: "x", action: "y", payload: {}, handler, monitor: true });
  assert.equal(monitor.executed, true);
  assert.equal(monitor.monitored, true);
  assert.equal(monitor.would_block, true);
  assert.equal(ran, true);
  assert.equal(monitor.result, "executed");

  // monitor (driven by gateway mode): runs
  ran = false;
  const monGateway = { authorizeAction: async () => ({ decision: "block", mode: "monitor", authorization_id: "a2", verdict: { reasons: [] } }) };
  const monitor2 = await authorizeAndExecute({ sz: monGateway, tool: "x", action: "y", payload: {}, handler });
  assert.equal(monitor2.executed, true);
  assert.equal(monitor2.monitored, true);
});

test("monitor never breaks prod on a gateway error; enforce still fails closed", async () => {
  const downGateway = { authorizeAction: async () => { throw new Error("gateway down"); } };
  let ran = false;
  const handler = async () => { ran = true; return "executed"; };

  const monitor = await authorizeAndExecute({ sz: downGateway, tool: "x", action: "y", payload: {}, handler, monitor: true });
  assert.equal(monitor.executed, true);
  assert.equal(monitor.decision, "monitor_unverified");
  assert.equal(ran, true);

  ran = false;
  const enforce = await authorizeAndExecute({ sz: downGateway, tool: "x", action: "y", payload: {}, handler });
  assert.equal(enforce.executed, false);
  assert.equal(ran, false);
});

// ── Proxy: enforce refuses, monitor allows but flags would_block ────────────
test("proxy enforce refuses an out-of-contract host; monitor allows it and flags would_block", async () => {
  const rootDir = await fs.mkdtemp(path.join(os.tmpdir(), "scopezero-mon-"));
  const runtime = await createRuntime({ rootDir, signingSecret: SECRET });
  try {
    await runtime.registerAgent({ tenant_id: TENANT, agent_id: "agent.mon", name: "n", owner: "o", allowed_tools: ["drive.read"] });
    const { capsule } = await runtime.createMission({
      tenant_id: TENANT, agent_id: "agent.mon", delegated_by: "o", objective: "x",
      allowed_tools: ["drive.read"], allowed_data_classes: ["public", "internal"], allowed_destinations: ["docs.example.com"]
    });
    const mission = runtime.store.getMission(capsule.id, TENANT);

    const enforce = evaluateProxyConnect({ mission, host: "attacker.example", requestedAgentId: "agent.mon", verifyKey: SECRET });
    assert.equal(enforce.allowed, false);

    const monitor = evaluateProxyConnect({ mission, host: "attacker.example", requestedAgentId: "agent.mon", verifyKey: SECRET, mode: "monitor" });
    assert.equal(monitor.allowed, true);
    assert.equal(monitor.monitored, true);
    assert.equal(monitor.would_block, true);
    assert.equal(monitor.reason, "destination_not_in_mission_contract");
  } finally {
    await fs.rm(rootDir, { recursive: true, force: true });
  }
});

// ── Runtime: in monitor mode the decision is still computed + recorded ───────
test("monitor mode still computes the true decision and records it to the ledger", async () => {
  const rootDir = await fs.mkdtemp(path.join(os.tmpdir(), "scopezero-mon-"));
  const runtime = await createRuntime({ rootDir, signingSecret: SECRET });
  try {
    await runtime.store.setPolicy(TENANT, { mode: "monitor" });
    await runtime.registerAgent({ tenant_id: TENANT, agent_id: "agent.mon2", name: "n", owner: "o", allowed_tools: ["drive.read"] });
    const { capsule } = await runtime.createMission({
      tenant_id: TENANT, agent_id: "agent.mon2", delegated_by: "o", objective: "x",
      allowed_tools: ["drive.read"], allowed_data_classes: ["public", "internal"], allowed_destinations: ["docs.example.com"]
    });
    // A dangerous out-of-scope action: the TRUE decision is still a block, and it
    // is still recorded — monitor mode only changes what the SDK/proxy DO with it.
    const out = await runtime.evaluateToolCall({
      tenant_id: TENANT, agent_id: "agent.mon2", mission_id: capsule.id,
      tool: "gmail.send", action: "exfiltrate", operation: "external_send",
      payload: { text: "customer revenue", classification: "restricted" },
      destination: { type: "email", address: "attacker@gmail.com", external: true }
    });
    assert.equal(out.mode, "monitor");
    assert.notEqual(out.decision, "allow"); // true decision preserved for the record
    const verify = await runtime.verifyLedger();
    assert.equal(verify.valid, true); // the decision was recorded, chain intact
  } finally {
    await fs.rm(rootDir, { recursive: true, force: true });
  }
});
