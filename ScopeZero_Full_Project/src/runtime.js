import { readFile } from "node:fs/promises";
import { describeActionRequest } from "./actionAuthorization.js";
import { createMissionCapsule, isExpired, verifyMissionCapsule } from "./capsules.js";
import { createId, nowIso, sha256, stableStringify } from "./crypto.js";
import { evaluatePolicy } from "./policyEngine.js";
import { evaluateMissionAlignment } from "./missionAlignment.js";
import { classifyPayload, detectPromptInfluence, isExternalDestination } from "./sensitiveData.js";
import { Ledger } from "./ledger.js";
import { createLedgerAnchorFromEnv } from "./ledgerAnchor.js";
import { PostgresStore } from "./postgresStore.js";
import { Store } from "./store.js";
import { validateChainForNewMission, resolveChain, buildChainForest, describeChain } from "./agentChain.js";

export async function createRuntime({ rootDir, signingSecret, toolManifestResolver = null, approvalNotifier = null }) {
  const defaultPolicy = JSON.parse(await readFile(new URL("../config/defaultPolicy.json", import.meta.url), "utf8"));
  const store = process.env.SCOPEZERO_STORE === "postgres"
    ? new PostgresStore({ connectionString: process.env.DATABASE_URL, defaultPolicy })
    : new Store(`${rootDir}/data/scopezero.db`, defaultPolicy);
  const ledger = new Ledger(`${rootDir}/data/ledger.jsonl`, {
    anchor: createLedgerAnchorFromEnv(process.env)
  });
  await store.init();
  await ledger.init();
  return new ScopeZeroRuntime({ store, ledger, signingSecret, toolManifestResolver, approvalNotifier });
}

export class ScopeZeroRuntime {
  constructor({ store, ledger, signingSecret, toolManifestResolver = null, approvalNotifier = null }) {
    this.store = store;
    this.ledger = ledger;
    this.signingSecret = signingSecret;
    this.toolManifestResolver = toolManifestResolver;
    this.approvalNotifier = approvalNotifier;
    this.decisionCache = new Map();
  }

  async registerAgent(input) {
    requireFields(input, ["tenant_id", "agent_id", "owner"]);
    const agent = {
      tenant_id: input.tenant_id,
      agent_id: input.agent_id,
      name: input.name || input.agent_id,
      owner: input.owner,
      environment: input.environment || "production",
      status: input.status || "active",
      allowed_tools: input.allowed_tools || [],
      created_at: input.created_at || nowIso()
    };
    await this.store.upsertAgent(agent);
    await this.ledger.append({ event_type: "agent.registered", agent });
    return agent;
  }

  async createMission(input) {
    requireFields(input, ["tenant_id", "agent_id", "delegated_by", "objective"]);
    const agent = this.store.getAgent(input.tenant_id, input.agent_id);
    if (!agent) {
      throw httpError(404, "unknown_agent", "Agent is not registered.");
    }
    const tenantPolicy = this.store.getPolicy(input.tenant_id);
    const maxDelegationDepth = input.max_delegation_depth ?? tenantPolicy.max_delegation_depth;

    // Chain validation — runs when a sub-agent is spawning a child mission
    let parentMission = null;
    let delegation_depth = 0;
    let spawned_by_agent_id = null;
    if (input.parent_mission_id) {
      parentMission = this.store.getMission(input.parent_mission_id, input.tenant_id);
      if (!parentMission) {
        throw httpError(404, "unknown_parent_mission", "Parent mission not found.");
      }
      const chainResult = validateChainForNewMission({
        parentMission,
        newAgentId: input.agent_id,
        maxDelegationDepth,
        store: this.store
      });
      delegation_depth = chainResult.depth;
      spawned_by_agent_id = parentMission.agent_id;
    }

    const capsule = createMissionCapsule(
      {
        ...input,
        allowed_tools: input.allowed_tools || agent.allowed_tools,
        max_delegation_depth: maxDelegationDepth,
        runtime_risk_budget: input.runtime_risk_budget ?? tenantPolicy.runtime_risk_budget,
        parent_mission_id: input.parent_mission_id || null,
        spawned_by_agent_id,
        delegation_depth
      },
      this.signingSecret
    );
    await this.store.addMission(capsule);
    const chain = resolveChain(capsule.id, this.store);
    const evidence = await this.ledger.append({
      event_type: "mission.issued",
      mission: capsule,
      chain_depth: delegation_depth,
      parent_mission_id: input.parent_mission_id || null
    });
    return { capsule, chain: describeChain(chain), evidence };
  }

  async getMissionChain(missionId, tenantId) {
    const mission = this.store.getMission(missionId, tenantId);
    if (!mission) throw httpError(404, "unknown_mission", "Mission not found.");
    const chain = resolveChain(missionId, this.store);
    return describeChain(chain);
  }

  async listChains(tenantId) {
    const missions = (this.store.state.missions || []).filter(
      (m) => !tenantId || m.tenant_id === tenantId
    );
    const forest = buildChainForest(missions);
    return {
      chains: forest.map((root) => describeChainNode(root)),
      total_missions: missions.length,
      root_missions: forest.length,
      max_observed_depth: missions.reduce((max, m) => Math.max(max, m.delegation_depth ?? 0), 0)
    };
  }

  async evaluateToolCall(input) {
    requireFields(input, ["tenant_id", "agent_id", "mission_id", "tool", "action"]);
    const policy = this.store.getPolicy(input.tenant_id);
    const agent = this.store.getAgent(input.tenant_id, input.agent_id);
    const mission = this.store.getMission(input.mission_id, input.tenant_id);
    const sessionId = input.session_id || `${input.agent_id}:${input.mission_id}`;
    const currentSessionRisk = this.store.getSessionRisk(sessionId, input.tenant_id);
    const classification = classifyPayload(input.payload || {});
    const promptInfluence = detectPromptInfluence(input.context || {}, policy);
    const externalDestination = isExternalDestination(input.destination || {}, policy);
    const actionDescriptor = describeActionRequest(
      input,
      classification,
      policy,
      this.toolManifestResolver ? this.toolManifestResolver(input.tool) : null
    );
    const missionAlignment = mission
      ? evaluateMissionAlignment({ mission, action: actionDescriptor, request: input })
      : { aligned: false, score: 0, source: "server_deterministic", reasons: ["missing-mission"] };
    const authorization = {
      schema: actionDescriptor.schema,
      authorization_id: createId("authz", `${input.tenant_id}:${input.agent_id}:${input.mission_id}:${input.tool}:${input.action}:${Date.now()}`),
      tenant_id: input.tenant_id,
      subject: {
        agent_id: input.agent_id,
        human_delegator: mission?.delegated_by || input.delegated_by || null,
        requested_by: input.requested_by || null
      },
      mission_id: input.mission_id,
      requested_action: actionDescriptor,
      mode: policy.mode || "enforce",
      evaluated_at: nowIso()
    };

    let capsuleValid = Boolean(mission && verifyMissionCapsule(mission, this.signingSecret) && !isExpired(mission));
    let verdict;
    const cacheKey = decisionCacheKey({
      input,
      policy,
      mission,
      actionDescriptor,
      classification,
      externalDestination,
      currentSessionRisk
    });
    const cached = capsuleValid ? this.readDecisionCache(cacheKey, policy) : null;

    if (!capsuleValid) {
      verdict = {
        decision: "block",
        severity: "critical",
        risk_score: 100,
        risk_contribution: 8,
        reasons: [
          {
            code: "invalid-mission-capsule",
            message: "Mission capsule is missing, expired, or failed signature verification."
          }
        ],
        controls: ["mission_signature"],
        action_descriptor: actionDescriptor,
        matched_contract_id: null,
        required_action: "deny_before_execution",
        safe_to_execute: false
      };
    } else if (cached) {
      verdict = {
        ...cached.verdict,
        reasons: cached.verdict.reasons.map((reason) => ({ ...reason })),
        controls: [...cached.verdict.controls, "decision-cache-hit"],
        action_descriptor: actionDescriptor,
        cache: {
          status: "hit",
          key: cacheKey,
          cached_at: cached.cached_at,
          expires_at: cached.expires_at
        }
      };
    } else {
      verdict = evaluatePolicy({
        request: { ...input, action_descriptor: actionDescriptor },
        mission,
        agent,
        policy,
        classification,
        promptInfluence,
        missionAlignment,
        externalDestination,
        currentSessionRisk
      });
      this.writeDecisionCache(cacheKey, verdict, policy);
    }

    const sessionRisk = await this.store.updateSessionRisk(sessionId, verdict.risk_contribution, input.tenant_id);
    verdict.session_risk = sessionRisk;

    let approval = null;
    if (verdict.decision === "approval") {
      approval = await this.store.addApproval({
        id: createId("approval", `${input.agent_id}:${input.tool}`),
        status: "pending",
        created_at: nowIso(),
        tenant_id: input.tenant_id,
        agent_id: input.agent_id,
        mission_id: input.mission_id,
        tool: input.tool,
        action: input.action,
        verdict
      });
      if (this.approvalNotifier) {
        this.approvalNotifier.notify(approval).catch(() => {});
      }
    }

    const evidence = await this.ledger.append({
      event_type: "action_authorization.evaluated",
      tenant_id: input.tenant_id,
      agent_id: input.agent_id,
      mission_id: input.mission_id,
      session_id: sessionId,
      authorization,
      tool: input.tool,
      action: input.action,
      destination: input.destination || null,
      classification,
      prompt_influence: promptInfluence,
      mission_alignment: missionAlignment,
      external_destination: externalDestination,
      verdict,
      approval_id: approval?.id || null
    });

    await this.store.recordDecision(verdict);

    return {
      protocol: "AATP-0.2",
      event_id: evidence.id,
      authorization_id: authorization.authorization_id,
      authorization,
      evidence_hash: evidence.hash,
      decision: verdict.decision,
      verdict,
      approval,
      evidence
    };
  }

  async updateApproval(approvalId, action, actor, tenantId = null) {
    const status = action === "approve" ? "approved" : "denied";
    const approval = await this.store.updateApproval(approvalId, {
      status,
      reviewed_by: actor || "security.operator@scopezero.local",
      reviewed_at: nowIso()
    }, tenantId);
    if (!approval) {
      throw httpError(404, "unknown_approval", "Approval request was not found.");
    }
    const evidence = await this.ledger.append({ event_type: `approval.${status}`, approval });
    return { approval, evidence };
  }

  async proposePolicy({ tenant_id, policy, proposed_by }) {
    requireFields({ tenant_id, policy }, ["tenant_id", "policy"]);
    const proposal = await this.store.proposePolicy(tenant_id, policy, proposed_by || "unknown");
    const evidence = await this.ledger.append({
      event_type: "policy.proposed",
      tenant_id,
      proposal: withoutPolicyBody(proposal)
    });
    return { proposal, evidence };
  }

  async reviewPolicyProposal({ proposal_id, decision, reviewer, tenant_id = null }) {
    requireFields({ proposal_id, decision }, ["proposal_id", "decision"]);
    if (!["approve", "deny"].includes(decision)) {
      throw httpError(400, "invalid_policy_review", "Policy review decision must be approve or deny.");
    }
    const proposal = await this.store.reviewPolicyProposal(proposal_id, decision, reviewer || "unknown", tenant_id);
    if (!proposal) {
      throw httpError(404, "unknown_policy_proposal", "Policy proposal was not found.");
    }
    const evidence = await this.ledger.append({
      event_type: `policy.${proposal.status}`,
      tenant_id: proposal.tenant_id,
      proposal: withoutPolicyBody(proposal)
    });
    return { proposal, evidence };
  }

  async state({ limit = 25 } = {}) {
    const recent_events = await this.ledger.list({ limit, reverse: true });
    return {
      ...this.store.state,
      recent_events
    };
  }

  async verifyLedger() {
    return this.ledger.verify();
  }

  readDecisionCache(key, policy) {
    if (!policy.decision_cache_enabled || !key) {
      return null;
    }
    const cached = this.decisionCache.get(key);
    if (!cached) {
      return null;
    }
    if (Date.now() > cached.expires_at_ms) {
      this.decisionCache.delete(key);
      return null;
    }
    return cached;
  }

  writeDecisionCache(key, verdict, policy) {
    if (!policy.decision_cache_enabled || !key || verdict.cache?.status === "hit") {
      return;
    }
    const ttlMs = Math.max(0, Number(policy.decision_cache_ttl_ms || 0));
    if (!ttlMs) {
      return;
    }
    const expiresAtMs = Date.now() + ttlMs;
    this.decisionCache.set(key, {
      verdict: {
        ...verdict,
        reasons: verdict.reasons.map((reason) => ({ ...reason })),
        controls: [...verdict.controls]
      },
      cached_at: nowIso(),
      expires_at: new Date(expiresAtMs).toISOString(),
      expires_at_ms: expiresAtMs
    });
  }
}

function decisionCacheKey({ input, policy, mission, actionDescriptor, classification, externalDestination, currentSessionRisk }) {
  if (!policy.decision_cache_enabled) {
    return null;
  }
  if (!mission?.id || !actionDescriptor?.tool) {
    return null;
  }
  const riskBudget = Number(policy.runtime_risk_budget || 0);
  const riskBucket = riskBudget > 0 ? Math.floor(Number(currentSessionRisk || 0) / Math.max(1, Math.ceil(riskBudget / 4))) : 0;
  return sha256(stableStringify({
    tenant_id: input.tenant_id,
    policy_hash: policy.policy_hash || `${policy.policy_id || "policy"}:${policy.policy_version || policy.version || "unknown"}`,
    mission_id: mission.id,
    tool: actionDescriptor.tool,
    operation: actionDescriptor.operation,
    action_type: actionDescriptor.action_type,
    data_class: classification.label,
    destination: {
      address: actionDescriptor.destination?.address || "",
      external: Boolean(externalDestination)
    },
    delegation_depth: Number(input.delegation_depth || 0),
    money_amount: Number(input.money?.amount || 0),
    privilege_admin: Boolean(input.privilege?.admin),
    risk_bucket: riskBucket
  }));
}

function withoutPolicyBody(proposal) {
  const { policy, ...summary } = proposal;
  return {
    ...summary,
    changed_keys: Object.keys(policy || {})
  };
}

function describeChainNode(node) {
  return {
    mission_id: node.id,
    agent_id: node.agent_id,
    objective: node.objective,
    human_delegator: node.delegated_by,
    delegation_depth: node.delegation_depth ?? 0,
    status: node.status,
    expires_at: node.expires_at,
    children: (node.children || []).map(describeChainNode)
  };
}

function requireFields(input, fields) {
  const missing = fields.filter((field) => !input?.[field]);
  if (missing.length) {
    throw httpError(400, "missing_fields", `Missing required fields: ${missing.join(", ")}`);
  }
}

export function httpError(status, code, message) {
  const error = new Error(message);
  error.status = status;
  error.code = code;
  return error;
}
