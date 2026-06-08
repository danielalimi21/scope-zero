import { readFile } from "node:fs/promises";
import { describeActionRequest } from "./actionAuthorization.js";
import { createMissionCapsule, isExpired, verifyMissionCapsule } from "./capsules.js";
import { buildVerificationKeyset, createId, keyFingerprint, loadSigningKeys, nowIso, publicKeyToPem, sha256, stableStringify } from "./crypto.js";
import { evaluatePolicy } from "./policyEngine.js";
import { evaluateMissionAlignment } from "./missionAlignment.js";
import { classifyPayload, detectPromptInfluence, isExternalDestination, mergeClassification } from "./sensitiveData.js";
import { Ledger } from "./ledger.js";
import { createLedgerAnchorFromEnv } from "./ledgerAnchor.js";
import { PostgresStore } from "./postgresStore.js";
import { Store } from "./store.js";
import { validateChainForNewMission, resolveChain, buildChainForest, describeChain } from "./agentChain.js";
import { analyzeToolCallBehavior, createEmptyProfile, updateBehaviorProfile } from "./behaviorAnalyzer.js";
import { assessMcpCall, buildMcpServerRecord, isValidTrustLevel, computeTrustDecay, queryOsvVulnerabilities, applyTrustSignals } from "./mcpTrustRegistry.js";
import { issueAgentCertificate, verifyAgentCertificate, verifyCertIdentity } from "./agentCert.js";

export async function createRuntime({ rootDir, signingSecret, signingPrivateKeyPem = process.env.SCOPEZERO_SIGNING_PRIVATE_KEY || "", additionalPublicKeyPems = parsePublicKeyPems(process.env.SCOPEZERO_SIGNING_PUBLIC_KEYS), toolManifestResolver = null, approvalNotifier = null, classifierResolver = null }) {
  const defaultPolicy = JSON.parse(await readFile(new URL("../config/defaultPolicy.json", import.meta.url), "utf8"));
  const store = process.env.SCOPEZERO_STORE === "postgres"
    ? new PostgresStore({ connectionString: process.env.DATABASE_URL, defaultPolicy })
    : new Store(`${rootDir}/data/scopezero.db`, defaultPolicy);
  const ledger = new Ledger(`${rootDir}/data/ledger.jsonl`, {
    anchor: createLedgerAnchorFromEnv(process.env),
    secret: process.env.SCOPEZERO_LEDGER_SECRET || signingSecret
  });
  await store.init();
  await ledger.init();
  return new ScopeZeroRuntime({ store, ledger, signingSecret, signingPrivateKeyPem, additionalPublicKeyPems, toolManifestResolver, approvalNotifier, classifierResolver });
}

// Parse retired/rotated verification public keys from env: PEM blocks joined by
// commas or newlines, or comma-separated file paths. Kept in the keyset so
// capsules/certs signed under a previous key still verify after rotation.
function parsePublicKeyPems(raw) {
  if (!raw) return [];
  return String(raw)
    .split(/,(?=\s*-----BEGIN)|\n\n/)
    .map((part) => part.trim())
    .filter((part) => part.includes("-----BEGIN"));
}

export class ScopeZeroRuntime {
  constructor({ store, ledger, signingSecret, signingPrivateKeyPem = "", additionalPublicKeyPems = [], toolManifestResolver = null, approvalNotifier = null, classifierResolver = null }) {
    this.store = store;
    this.ledger = ledger;
    this.signingSecret = signingSecret;
    // Ed25519 keypair. Private key signs capsules + certs; the public key verifies
    // and is safe to distribute to the proxy and external auditors. In production
    // pass signingPrivateKeyPem so the secret string is never the key material.
    this.signingKeys = loadSigningKeys({ privateKeyPem: signingPrivateKeyPem, secret: signingSecret });
    this.publicKeyPem = publicKeyToPem(this.signingKeys.publicKey);
    this.signingKid = keyFingerprint(this.signingKeys.publicKey);
    // Verification keyset = current public key + any retired/rotated public keys.
    // Capsules/certs carry a `kid`, so rotation keeps verifying live artifacts.
    this.verificationKeyset = buildVerificationKeyset({ current: this.signingKeys.publicKey, additionalPublicKeyPems });
    this.toolManifestResolver = toolManifestResolver;
    this.approvalNotifier = approvalNotifier;
    // Optional external classifier (embedding / model-graded / commercial DLP).
    // Receives { payload, context, tool }, may return { level, findings, established,
    // source }. Merged over the deterministic classifier — can only raise the class.
    this.classifierResolver = classifierResolver;
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

  async issueAgentCert(input) {
    requireFields(input, ["tenant_id", "agent_id"]);
    const agent = this.store.getAgent(input.tenant_id, input.agent_id);
    if (!agent) throw httpError(404, "unknown_agent", "Agent is not registered.");
    const cert = issueAgentCertificate(agent, this.signingKeys.privateKey, {
      ttlMs: input.ttl_ms || undefined
    });
    await this.store.addAgentCert(cert);
    const evidence = await this.ledger.append({
      event_type: "agent_cert.issued",
      cert_id: cert.cert_id,
      tenant_id: cert.tenant_id,
      agent_id: cert.agent_id,
      fingerprint: cert.fingerprint,
      expires_at: cert.expires_at
    });
    return { cert, evidence };
  }

  async revokeAgentCert({ cert_id, revoked_by, reason, tenant_id = null }) {
    requireFields({ cert_id }, ["cert_id"]);
    const cert = await this.store.revokeCert(cert_id, { revoked_by, reason, tenant_id });
    if (!cert) throw httpError(404, "unknown_cert", `Certificate ${cert_id} not found.`);
    const evidence = await this.ledger.append({
      event_type: "agent_cert.revoked",
      cert_id,
      tenant_id: cert.tenant_id,
      agent_id: cert.agent_id,
      revoked_by: cert.revoked_by,
      reason: cert.revocation_reason
    });
    return { cert, evidence };
  }

  listAgentCerts({ tenant_id, agent_id }) {
    return this.store.listAgentCerts(tenant_id, agent_id);
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
      this.signingKeys.privateKey
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
    const currentSessionRisk = await this.store.getSessionRisk(sessionId, input.tenant_id);
    const priorIngestedClassRank = this.store.getSessionIngestedClass
      ? await this.store.getSessionIngestedClass(sessionId, input.tenant_id)
      : 0;
    let classification = classifyPayload(input.payload || {});
    if (this.classifierResolver) {
      const external = await this.classifierResolver({ payload: input.payload, context: input.context, tool: input.tool });
      classification = mergeClassification(classification, external);
    }
    // What sensitive material has this call exposed the session to — the outbound
    // payload AND the inbound context (retrieved docs / prior tool output). Drives
    // the session ingest-taint high-water mark used by the laundering guard.
    const contextClassification = classifyPayload(contextTextForTaint(input.context));
    const ingestedClassRank = Math.max(classification.level, contextClassification.level);
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

    let capsuleValid = Boolean(mission && verifyMissionCapsule(mission, this.verificationKeyset) && !isExpired(mission));
    let verdict;
    const cacheKey = decisionCacheKey({
      input,
      policy,
      mission,
      actionDescriptor,
      classification,
      externalDestination,
      currentSessionRisk,
      promptInfluence,
      missionAlignment,
      sessionIngestedClassRank: priorIngestedClassRank
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
        currentSessionRisk,
        sessionIngestedClassRank: priorIngestedClassRank
      });
      this.writeDecisionCache(cacheKey, verdict, policy);
    }

    // Agent certificate verification
    if (input.agent_cert_id) {
      const cert = this.store.getAgentCert(input.agent_cert_id);
      let certResult;
      if (!cert) {
        certResult = { valid: false, code: "cert-not-found", message: `Certificate ${input.agent_cert_id} not found.` };
      } else {
        certResult = verifyAgentCertificate(cert, this.verificationKeyset);
        if (certResult.valid) {
          const identityCheck = verifyCertIdentity(cert, input.agent_id, input.tenant_id);
          if (!identityCheck.valid) certResult = identityCheck;
        }
      }
      verdict.cert_verification = certResult;
      if (!certResult.valid) {
        verdict.reasons.push({ code: certResult.code, message: certResult.message, source: "agent_cert" });
        if (policy.require_agent_cert) {
          verdict.decision = "block";
          verdict.safe_to_execute = false;
          verdict.risk_score = Math.min(100, (verdict.risk_score || 0) + 30);
          verdict.controls = [...(verdict.controls || []), "agent_cert_enforcement"];
          verdict.required_action = "deny_before_execution";
        }
      } else {
        verdict.controls = [...(verdict.controls || []), "agent_cert_verified"];
      }
    } else if (policy.require_agent_cert) {
      const nocert = { valid: false, code: "cert-required", message: "Policy requires an agent certificate but none was provided." };
      verdict.cert_verification = nocert;
      verdict.reasons.push({ code: nocert.code, message: nocert.message, source: "agent_cert" });
      verdict.decision = "block";
      verdict.safe_to_execute = false;
      verdict.risk_score = Math.min(100, (verdict.risk_score || 0) + 30);
      verdict.controls = [...(verdict.controls || []), "agent_cert_enforcement"];
      verdict.required_action = "deny_before_execution";
    }

    // Behavioral anomaly detection — runs on every non-cached path and cache hits alike
    const now = new Date();
    const behaviorProfile = (await this.store.getBehaviorProfile(input.tenant_id, input.agent_id))
      || createEmptyProfile(input.tenant_id, input.agent_id);
    const { anomalies, risk_delta } = analyzeToolCallBehavior(behaviorProfile, input.tool, now, {
      dailyVolumeCap: policy.behavior_daily_volume_cap,
      dailyVolumeCapHighRisk: policy.behavior_daily_volume_cap_high_risk
    });
    if (anomalies.length > 0) {
      verdict.behavioral_anomalies = anomalies;
      verdict.risk_score = Math.min(100, (verdict.risk_score || 0) + risk_delta);
      for (const anomaly of anomalies) {
        verdict.reasons.push({ code: anomaly.code, message: anomaly.message, source: "behavioral_anomaly" });
      }
      const hasHighSeverity = anomalies.some(a => a.severity === "high");
      if (hasHighSeverity && verdict.decision === "allow") {
        verdict.decision = "approval";
        verdict.required_action = "human_approval_required";
        verdict.safe_to_execute = false;
        verdict.controls = [...(verdict.controls || []), "behavioral_anomaly_escalation"];
      }
    }
    updateBehaviorProfile(behaviorProfile, input.tool, now);
    await this.store.recordToolCall(input.tenant_id, input.agent_id, input.tool, behaviorProfile);

    const sessionRisk = await this.store.updateSessionRisk(sessionId, verdict.risk_contribution, input.tenant_id);
    verdict.session_risk = sessionRisk;

    // Raise the session ingest-taint high-water mark AFTER the decision, so this
    // call is judged against what the session had touched before it, and the next
    // call inherits the exposure this one added.
    if (this.store.updateSessionIngestedClass && ingestedClassRank > 0) {
      verdict.session_ingested_class_rank = await this.store.updateSessionIngestedClass(sessionId, ingestedClassRank, input.tenant_id);
    } else {
      verdict.session_ingested_class_rank = priorIngestedClassRank;
    }

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

  async registerMcpServer(input) {
    const server = buildMcpServerRecord(input);
    await this.store.upsertMcpServer(server);
    const evidence = await this.ledger.append({ event_type: "mcp_trust.server_registered", server_id: server.server_id, trust_level: server.trust_level, tenant_id: server.tenant_id });
    return { server, evidence };
  }

  async updateMcpServerTrust({ server_id, trust_level, reviewed_by, tenant_id = null }) {
    if (!isValidTrustLevel(trust_level)) {
      throw httpError(400, "invalid_trust_level", `Trust level must be one of: verified, community, unverified, blocked.`);
    }
    const server = this.store.getMcpServer(server_id, tenant_id);
    if (!server) throw httpError(404, "unknown_mcp_server", `MCP server "${server_id}" not found.`);
    const previous = server.trust_level;
    server.trust_level = trust_level;
    if (trust_level === "verified") {
      server.verified_at = nowIso();
      server.verified_by = reviewed_by || "security.operator@scopezero.local";
    }
    server.last_reviewed_at = nowIso();
    server.last_reviewed_by = reviewed_by || "security.operator@scopezero.local";
    await this.store.upsertMcpServer(server);
    const evidence = await this.ledger.append({
      event_type: "mcp_trust.updated",
      server_id,
      tenant_id,
      previous_trust: previous,
      new_trust: trust_level,
      reviewed_by: server.last_reviewed_by
    });
    return { server, evidence };
  }

  async refreshMcpServerTrust({ server_id, tenant_id = null, fetchFn = undefined }) {
    const server = this.store.getMcpServer(server_id, tenant_id);
    if (!server) throw httpError(404, "unknown_mcp_server", `MCP server "${server_id}" not found.`);
    const now = new Date();
    const decay = computeTrustDecay(server, now);
    const osvResult = server.package_name
      ? await queryOsvVulnerabilities(server.package_name, server.package_ecosystem || "npm", fetchFn)
      : { vulns: [], error: null };
    applyTrustSignals(server, decay, osvResult, now);
    await this.store.upsertMcpServer(server);
    const evidence = await this.ledger.append({
      event_type: "mcp_trust.refreshed",
      server_id,
      tenant_id,
      trust_signals: server.trust_signals,
      demoted: decay?.demoted || false
    });
    return { server, evidence };
  }

  // Refresh trust signals (OSV CVE lookup + time-based decay) for every
  // registered MCP server that has a package_name. Used by the scheduled
  // background refresh so the registry does not rely on manual /refresh calls.
  async refreshAllMcpServers({ fetchFn = undefined } = {}) {
    const servers = (this.store.listAllMcpServers
      ? this.store.listAllMcpServers()
      : this.store.listMcpServers({ tenantId: null })
    ).filter((server) => server.package_name);

    const results = [];
    for (const server of servers) {
      try {
        const { server: refreshed } = await this.refreshMcpServerTrust({
          server_id: server.server_id,
          tenant_id: server.tenant_id ?? null,
          fetchFn
        });
        results.push({
          server_id: server.server_id,
          tenant_id: server.tenant_id ?? null,
          signal_summary: refreshed.trust_signals?.signal_summary || null,
          demoted: refreshed.trust_signals?.demoted || false
        });
      } catch (error) {
        results.push({ server_id: server.server_id, tenant_id: server.tenant_id ?? null, error: error.message });
      }
    }
    return { refreshed_at: nowIso(), candidates: servers.length, results };
  }

  async evaluateMcpToolCall(input) {
    requireFields(input, ["tenant_id", "agent_id", "mission_id", "server_id", "tool"]);
    const server = this.store.getMcpServer(input.server_id, input.tenant_id);
    const assessment = assessMcpCall({
      server,
      toolName: input.tool,
      currentDecision: "allow"
    });

    if (assessment.block) {
      const evidence = await this.ledger.append({
        event_type: "mcp_trust.blocked",
        tenant_id: input.tenant_id,
        agent_id: input.agent_id,
        server_id: input.server_id,
        tool: input.tool,
        trust_level: "blocked"
      });
      return {
        decision: "block",
        safe_to_execute: false,
        mcp_trust: { server_id: input.server_id, trust_level: "blocked", risk_delta: 100, server_name: server?.name || null },
        verdict: {
          decision: "block",
          risk_score: 100,
          risk_contribution: 8,
          reasons: [assessment.reason],
          controls: ["mcp_trust_block"],
          safe_to_execute: false,
          required_action: "deny_before_execution"
        },
        evidence_hash: evidence.hash
      };
    }

    const result = await this.evaluateToolCall({
      ...input,
      action: input.action || `MCP call ${input.server_id}/${input.tool}`,
      mcp_server_id: input.server_id,
      mcp_trust_level: assessment.trust.trust_level
    });

    if (assessment.trust.risk_delta > 0) {
      result.verdict.risk_score = Math.min(100, (result.verdict.risk_score || 0) + assessment.trust.risk_delta);
      result.verdict.reasons.push(assessment.reason);
      if (assessment.escalate) {
        result.verdict.decision = "approval";
        result.verdict.required_action = "human_approval_required";
        result.verdict.safe_to_execute = false;
        result.verdict.controls = [...(result.verdict.controls || []), "mcp_trust_escalation"];
        result.decision = "approval";
      }
    }

    result.mcp_trust = {
      server_id: input.server_id,
      trust_level: assessment.trust.trust_level,
      risk_delta: assessment.trust.risk_delta,
      server_name: server?.name || null
    };

    return result;
  }

  async state({ limit = 25 } = {}) {
    const recent_events = await this.ledger.list({ limit, reverse: true });
    const snapshot = {
      ...this.store.state,
      recent_events
    };
    // Hot-path collections live in their own tables now; re-attach for reporting.
    if (this.store.getAllSessions) snapshot.sessions = await this.store.getAllSessions();
    if (this.store.getAllBehaviorProfiles) snapshot.behavior_profiles = await this.store.getAllBehaviorProfiles();
    if (this.store.getMetrics) snapshot.metrics = await this.store.getMetrics();
    return snapshot;
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

// The inbound material the agent pulled into context (retrieved docs, prior tool
// output, the working prompt). Classified for ingest-taint so the session is
// judged by what it has been exposed to, not only the bytes it sends out.
function contextTextForTaint(context = {}) {
  return [context.source_text, context.tool_output, context.document_text, context.prompt, context.instruction, context.retrieved]
    .filter(Boolean)
    .map((value) => (typeof value === "string" ? value : JSON.stringify(value)))
    .join("\n");
}

function decisionCacheKey({ input, policy, mission, actionDescriptor, classification, externalDestination, currentSessionRisk, promptInfluence, missionAlignment, sessionIngestedClassRank }) {
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
    data_class: actionDescriptor.data_class || classification.label,
    // Two level-1 payloads share the "public" label but differ in whether the
    // class was positively established from the bytes (benign prose vs. an opaque
    // dump). Without this, an unestablished egress could reuse a clean cached allow.
    egress_class_established: classification.established === true,
    egress_shape: classification.egress_shape || null,
    // Session ingest-taint changes the egress verdict (laundering guard), so a
    // tainted session must not reuse a clean-session allow.
    session_ingested_class_rank: Number(sessionIngestedClassRank || 0),
    destination: {
      address: actionDescriptor.destination?.address || "",
      external: Boolean(externalDestination)
    },
    delegation_depth: Number(input.delegation_depth || 0),
    money_amount: Number(input.money?.amount || 0),
    privilege_admin: Boolean(input.privilege?.admin),
    risk_bucket: riskBucket,
    // Context-derived verdict inputs MUST be in the key. Without them a clean
    // cached "allow" would be served to a request carrying a poisoned context
    // (prompt injection) or a drifted action, skipping the policy evaluation
    // that would have caught it.
    prompt_influenced: Boolean(promptInfluence?.influenced),
    mission_aligned: missionAlignment ? missionAlignment.aligned !== false : true,
    self_reported_misaligned: input.context?.mission_aligned === false
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
