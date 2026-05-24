import { readFile } from "node:fs/promises";
import { describeActionRequest } from "./actionAuthorization.js";
import { createMissionCapsule, isExpired, verifyMissionCapsule } from "./capsules.js";
import { createId, nowIso } from "./crypto.js";
import { evaluatePolicy } from "./policyEngine.js";
import { classifyPayload, detectPromptInfluence, isExternalDestination } from "./sensitiveData.js";
import { Ledger } from "./ledger.js";
import { PostgresStore } from "./postgresStore.js";
import { Store } from "./store.js";

export async function createRuntime({ rootDir, signingSecret }) {
  const defaultPolicy = JSON.parse(await readFile(new URL("../config/defaultPolicy.json", import.meta.url), "utf8"));
  const store = process.env.SCOPEZERO_STORE === "postgres"
    ? new PostgresStore({ connectionString: process.env.DATABASE_URL, defaultPolicy })
    : new Store(`${rootDir}/data/scopezero.db`, defaultPolicy);
  const ledger = new Ledger(`${rootDir}/data/ledger.jsonl`);
  await store.init();
  await ledger.init();
  return new ScopeZeroRuntime({ store, ledger, signingSecret });
}

export class ScopeZeroRuntime {
  constructor({ store, ledger, signingSecret }) {
    this.store = store;
    this.ledger = ledger;
    this.signingSecret = signingSecret;
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
    const capsule = createMissionCapsule(
      {
        ...input,
        allowed_tools: input.allowed_tools || agent.allowed_tools,
        max_delegation_depth: input.max_delegation_depth ?? tenantPolicy.max_delegation_depth,
        runtime_risk_budget: input.runtime_risk_budget ?? tenantPolicy.runtime_risk_budget
      },
      this.signingSecret
    );
    await this.store.addMission(capsule);
    const evidence = await this.ledger.append({ event_type: "mission.issued", mission: capsule });
    return { capsule, evidence };
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
    const actionDescriptor = describeActionRequest(input, classification, policy);
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
    } else {
      verdict = evaluatePolicy({
        request: { ...input, action_descriptor: actionDescriptor },
        mission,
        agent,
        policy,
        classification,
        promptInfluence,
        externalDestination,
        currentSessionRisk
      });
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
}

function withoutPolicyBody(proposal) {
  const { policy, ...summary } = proposal;
  return {
    ...summary,
    changed_keys: Object.keys(policy || {})
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
