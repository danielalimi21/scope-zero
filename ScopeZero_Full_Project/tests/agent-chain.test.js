import test from "node:test";
import assert from "node:assert/strict";
import { resolveChain, validateChainForNewMission, buildChainForest, describeChain } from "../src/agentChain.js";

function makeStore(missions = []) {
  return {
    getMission(id, tenantId = null) {
      return missions.find((m) => m.id === id && (!tenantId || m.tenant_id === tenantId)) || null;
    }
  };
}

function mission(overrides = {}) {
  return {
    id: `mission_${Math.random().toString(36).slice(2, 8)}`,
    tenant_id: "tenant_contoso",
    agent_id: "agent.default",
    delegated_by: "human@contoso.example",
    objective: "Test mission",
    status: "active",
    delegation_depth: 0,
    parent_mission_id: null,
    expires_at: new Date(Date.now() + 60 * 60 * 1000).toISOString(),
    ...overrides
  };
}

test("resolveChain returns single mission for root mission", () => {
  const root = mission({ id: "m_root" });
  const store = makeStore([root]);
  const chain = resolveChain("m_root", store);
  assert.equal(chain.length, 1);
  assert.equal(chain[0].id, "m_root");
});

test("resolveChain walks parent chain to root", () => {
  const root = mission({ id: "m_root", agent_id: "agent.a", delegation_depth: 0 });
  const child = mission({ id: "m_child", agent_id: "agent.b", parent_mission_id: "m_root", delegation_depth: 1 });
  const grandchild = mission({ id: "m_grand", agent_id: "agent.c", parent_mission_id: "m_child", delegation_depth: 2 });
  const store = makeStore([root, child, grandchild]);

  const chain = resolveChain("m_grand", store);
  assert.equal(chain.length, 3);
  assert.equal(chain[0].id, "m_root");
  assert.equal(chain[1].id, "m_child");
  assert.equal(chain[2].id, "m_grand");
});

test("resolveChain throws on cycle detection", () => {
  const a = mission({ id: "m_a", agent_id: "agent.a", parent_mission_id: "m_b" });
  const b = mission({ id: "m_b", agent_id: "agent.b", parent_mission_id: "m_a" });
  const store = makeStore([a, b]);

  assert.throws(
    () => resolveChain("m_a", store),
    (err) => err.code === "chain_cycle"
  );
});

test("validateChainForNewMission allows valid sub-mission", () => {
  const parent = mission({ id: "m_parent", agent_id: "agent.a", delegation_depth: 0 });
  const store = makeStore([parent]);

  const result = validateChainForNewMission({
    parentMission: parent,
    newAgentId: "agent.b",
    maxDelegationDepth: 2,
    store
  });

  assert.equal(result.depth, 1);
});

test("validateChainForNewMission blocks depth exceeding policy", () => {
  const parent = mission({ id: "m_parent", agent_id: "agent.a", delegation_depth: 1 });
  const store = makeStore([parent]);

  assert.throws(
    () => validateChainForNewMission({
      parentMission: parent,
      newAgentId: "agent.b",
      maxDelegationDepth: 1,
      store
    }),
    (err) => err.code === "chain_depth_exceeded"
  );
});

test("validateChainForNewMission blocks cycle — same agent in chain", () => {
  const root = mission({ id: "m_root", agent_id: "agent.a", delegation_depth: 0 });
  const child = mission({ id: "m_child", agent_id: "agent.b", parent_mission_id: "m_root", delegation_depth: 1 });
  const store = makeStore([root, child]);

  // agent.a trying to be spawned as grandchild — cycle
  assert.throws(
    () => validateChainForNewMission({
      parentMission: child,
      newAgentId: "agent.a",
      maxDelegationDepth: 3,
      store
    }),
    (err) => err.code === "chain_cycle"
  );
});

test("validateChainForNewMission blocks expired parent", () => {
  const expired = mission({
    id: "m_expired",
    agent_id: "agent.a",
    delegation_depth: 0,
    expires_at: new Date(Date.now() - 1000).toISOString()
  });
  const store = makeStore([expired]);

  assert.throws(
    () => validateChainForNewMission({
      parentMission: expired,
      newAgentId: "agent.b",
      maxDelegationDepth: 2,
      store
    }),
    (err) => err.code === "parent_mission_expired"
  );
});

test("validateChainForNewMission blocks inactive parent", () => {
  const inactive = mission({ id: "m_inactive", agent_id: "agent.a", status: "revoked" });
  const store = makeStore([inactive]);

  assert.throws(
    () => validateChainForNewMission({
      parentMission: inactive,
      newAgentId: "agent.b",
      maxDelegationDepth: 2,
      store
    }),
    (err) => err.code === "parent_mission_inactive"
  );
});

test("buildChainForest builds tree from flat mission list", () => {
  const root = mission({ id: "m_root", agent_id: "agent.a", delegation_depth: 0 });
  const child1 = mission({ id: "m_c1", agent_id: "agent.b", parent_mission_id: "m_root", delegation_depth: 1 });
  const child2 = mission({ id: "m_c2", agent_id: "agent.c", parent_mission_id: "m_root", delegation_depth: 1 });
  const grandchild = mission({ id: "m_gc", agent_id: "agent.d", parent_mission_id: "m_c1", delegation_depth: 2 });

  const forest = buildChainForest([root, child1, child2, grandchild]);
  assert.equal(forest.length, 1);
  assert.equal(forest[0].id, "m_root");
  assert.equal(forest[0].children.length, 2);
  const c1 = forest[0].children.find((c) => c.id === "m_c1");
  assert.ok(c1);
  assert.equal(c1.children.length, 1);
  assert.equal(c1.children[0].id, "m_gc");
});

test("describeChain returns correct accountability summary", () => {
  const root = mission({ id: "m_root", agent_id: "agent.a", delegated_by: "ciso@contoso.example", delegation_depth: 0 });
  const child = mission({ id: "m_child", agent_id: "agent.b", delegation_depth: 1 });

  const summary = describeChain([root, child]);
  assert.equal(summary.chain_length, 2);
  assert.equal(summary.root_agent_id, "agent.a");
  assert.equal(summary.human_delegator, "ciso@contoso.example");
  assert.equal(summary.leaf_agent_id, "agent.b");
  assert.equal(summary.max_depth_in_chain, 1);
  assert.equal(summary.hops.length, 2);
});
