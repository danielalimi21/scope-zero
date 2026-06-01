import { httpError } from "./runtime.js";

// Resolves the full delegation chain for a mission, walking up to the root.
// Returns ordered array from root (human-delegated) to the given mission.
export function resolveChain(missionId, store) {
  const visited = new Set();
  const chain = [];
  let current = store.getMission(missionId);

  while (current) {
    if (visited.has(current.id)) {
      throw httpError(422, "chain_cycle", `Delegation cycle detected at mission ${current.id}.`);
    }
    visited.add(current.id);
    chain.unshift(current);
    if (!current.parent_mission_id) break;
    current = store.getMission(current.parent_mission_id);
  }

  return chain;
}

// Validates a proposed new mission against chain rules before creation.
export function validateChainForNewMission({ parentMission, newAgentId, maxDelegationDepth, store }) {
  if (!parentMission) return { depth: 0 };

  // Cycle check — new agent must not already appear in the parent's chain
  const parentChain = resolveChain(parentMission.id, store);
  const agentsInChain = new Set(parentChain.map((m) => m.agent_id));
  if (agentsInChain.has(newAgentId)) {
    throw httpError(422, "chain_cycle", `Agent ${newAgentId} already exists in the delegation chain — cycle detected.`);
  }

  const depth = (parentMission.delegation_depth ?? 0) + 1;
  const policyMax = Number(maxDelegationDepth ?? 1);

  if (depth > policyMax) {
    throw httpError(422, "chain_depth_exceeded", `Delegation depth ${depth} exceeds policy maximum of ${policyMax}.`);
  }

  if (parentMission.status !== "active") {
    throw httpError(422, "parent_mission_inactive", `Parent mission ${parentMission.id} is not active.`);
  }

  if (parentMission.expires_at && new Date(parentMission.expires_at).getTime() < Date.now()) {
    throw httpError(422, "parent_mission_expired", `Parent mission ${parentMission.id} has expired.`);
  }

  return { depth };
}

// Builds a forest (array of root trees) from all missions.
export function buildChainForest(missions) {
  const byId = new Map(missions.map((m) => [m.id, { ...m, children: [] }]));
  const roots = [];

  for (const node of byId.values()) {
    if (node.parent_mission_id && byId.has(node.parent_mission_id)) {
      byId.get(node.parent_mission_id).children.push(node);
    } else {
      roots.push(node);
    }
  }

  return roots;
}

// Returns chain summary for a mission — readable accountability path.
export function describeChain(chain) {
  if (!chain.length) return null;
  const root = chain[0];
  const leaf = chain[chain.length - 1];
  return {
    chain_length: chain.length,
    root_mission_id: root.id,
    root_agent_id: root.agent_id,
    human_delegator: root.delegated_by,
    leaf_mission_id: leaf.id,
    leaf_agent_id: leaf.agent_id,
    max_depth_in_chain: chain.length - 1,
    hops: chain.map((m) => ({
      mission_id: m.id,
      agent_id: m.agent_id,
      objective: m.objective,
      delegation_depth: m.delegation_depth ?? 0,
      status: m.status,
      expires_at: m.expires_at
    }))
  };
}
