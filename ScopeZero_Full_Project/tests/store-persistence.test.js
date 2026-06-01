import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { Store } from "../src/store.js";
import policy from "../config/defaultPolicy.json" with { type: "json" };

async function freshStore() {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "scopezero-store-"));
  const store = new Store(path.join(dir, "scopezero.db"), policy);
  await store.init();
  return { store, dir };
}

function agentOwnerInTable(store, agentId) {
  return store.db.prepare("SELECT owner FROM agents WHERE agent_id = ?").get(agentId)?.owner;
}

test("behavior-only write does not rebuild the agents mirror table", async () => {
  const { store, dir } = await freshStore();
  try {
    const agentId = "agent.ma-diligence.72f1";
    // Stamp a sentinel directly into the mirror table. If a write rebuilds the
    // table from state, the sentinel is overwritten with the real owner.
    store.db.prepare("UPDATE agents SET owner = ? WHERE agent_id = ?").run("SENTINEL", agentId);
    assert.equal(agentOwnerInTable(store, agentId), "SENTINEL");

    // Per-tool-call behavior write — touches no mirrored collection.
    await store.recordToolCall("tenant_contoso", agentId, "drive.read", {
      tenant_id: "tenant_contoso",
      agent_id: agentId,
      tools: { "drive.read": { total_calls: 1 } }
    });

    assert.equal(agentOwnerInTable(store, agentId), "SENTINEL", "agents mirror must be untouched by a behavior write");

    // An actual agent write marks the table dirty and rebuilds it.
    await store.upsertAgent({ tenant_id: "tenant_contoso", agent_id: agentId, owner: "real.owner@contoso.example", status: "active" });
    assert.equal(agentOwnerInTable(store, agentId), "real.owner@contoso.example", "agent write rebuilds the mirror");
  } finally {
    await fs.rm(dir, { recursive: true, force: true });
  }
});

test("hot-path writes do not reserialize the full-state blob", async () => {
  const { store, dir } = await freshStore();
  try {
    const blobBefore = store.db.prepare("SELECT body FROM scopezero_state WHERE id = 'primary'").get().body;

    await store.recordToolCall("tenant_contoso", "agent.ma-diligence.72f1", "drive.read", {
      tenant_id: "tenant_contoso",
      agent_id: "agent.ma-diligence.72f1",
      tools: { "drive.read": { total_calls: 1 } }
    });
    await store.updateSessionRisk("session-1", 12, "tenant_contoso");
    await store.recordDecision({ decision: "block" });

    const blobAfter = store.db.prepare("SELECT body FROM scopezero_state WHERE id = 'primary'").get().body;
    assert.equal(blobAfter, blobBefore, "behavior/session/metrics writes must not touch the state blob");

    // And the blob no longer carries the hot-path collections at all.
    const parsed = JSON.parse(blobAfter);
    assert.equal(parsed.behavior_profiles, undefined);
    assert.equal(parsed.sessions, undefined);
    assert.equal(parsed.metrics, undefined);

    // The data landed in its own tables.
    assert.equal(store.getSessionRisk("session-1", "tenant_contoso"), 12);
    assert.equal(store.getBehaviorProfile("tenant_contoso", "agent.ma-diligence.72f1").tools["drive.read"].total_calls, 1);
    const metrics = store.getMetrics();
    assert.equal(metrics.runtime_decisions, 1);
    assert.equal(metrics.blocked_actions, 1);
    assert.equal(metrics.evidence_capsules, 1);
  } finally {
    await fs.rm(dir, { recursive: true, force: true });
  }
});

test("session risk increments atomically and caps at 100", async () => {
  const { store, dir } = await freshStore();
  try {
    assert.equal(await store.updateSessionRisk("s", 40, "tenant_contoso"), 40);
    assert.equal(await store.updateSessionRisk("s", 40, "tenant_contoso"), 80);
    assert.equal(await store.updateSessionRisk("s", 40, "tenant_contoso"), 100, "caps at 100");
  } finally {
    await fs.rm(dir, { recursive: true, force: true });
  }
});

test("behavior profiles survive a store reopen (durable, off-blob)", async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "scopezero-store-"));
  const dbPath = path.join(dir, "scopezero.db");
  try {
    const first = new Store(dbPath, policy);
    await first.init();
    await first.recordToolCall("tenant_contoso", "agent.x", "gmail.send", {
      tenant_id: "tenant_contoso", agent_id: "agent.x", tools: { "gmail.send": { total_calls: 3 } }
    });

    const reopened = new Store(dbPath, policy);
    await reopened.init();
    assert.equal(reopened.getBehaviorProfile("tenant_contoso", "agent.x").tools["gmail.send"].total_calls, 3);
  } finally {
    await fs.rm(dir, { recursive: true, force: true });
  }
});

test("mirrored writes keep relational tables consistent with state", async () => {
  const { store, dir } = await freshStore();
  try {
    await store.upsertAgent({ tenant_id: "tenant_contoso", agent_id: "agent.new", owner: "o@contoso.example", status: "active" });
    const rows = store.db.prepare("SELECT agent_id FROM agents ORDER BY agent_id").all().map((r) => r.agent_id);
    assert.ok(rows.includes("agent.new"));
    assert.equal(rows.length, store.state.agents.length, "mirror row count matches state");
  } finally {
    await fs.rm(dir, { recursive: true, force: true });
  }
});
