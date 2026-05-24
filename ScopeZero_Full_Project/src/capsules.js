import { createId, hmacSha256, nowIso, stableStringify } from "./crypto.js";
import { buildDefaultActionContracts } from "./actionAuthorization.js";

export function createMissionCapsule(input, signingSecret) {
  const issuedAt = nowIso();
  const ttlMinutes = Number(input.ttl_minutes || 45);
  const expiresAt = new Date(Date.now() + ttlMinutes * 60 * 1000).toISOString();
  const capsule = {
    capsule_type: "mission_action_contract",
    protocol: "AATP-0.2",
    id: createId("mission", `${input.agent_id}:${input.objective}`),
    tenant_id: input.tenant_id,
    agent_id: input.agent_id,
    delegated_by: input.delegated_by,
    objective: input.objective,
    allowed_tools: input.allowed_tools || [],
    allowed_data_classes: input.allowed_data_classes || ["public", "internal"],
    allowed_destinations: input.allowed_destinations || [],
    action_contracts: input.action_contracts || buildDefaultActionContracts(input),
    evidence_schema: input.evidence_schema || "scopezero.action_authorization.v1",
    approval_profile: input.approval_profile || "standard",
    max_delegation_depth: Number(input.max_delegation_depth ?? 1),
    runtime_risk_budget: Number(input.runtime_risk_budget ?? 68),
    issued_at: issuedAt,
    expires_at: expiresAt,
    status: "active"
  };

  return signCapsule(capsule, signingSecret);
}

export function signCapsule(capsule, signingSecret) {
  const unsigned = { ...capsule };
  delete unsigned.signature;
  return {
    ...unsigned,
    signature: `sz1.${hmacSha256(signingSecret, stableStringify(unsigned))}`
  };
}

export function verifyMissionCapsule(capsule, signingSecret) {
  if (!capsule || !capsule.signature) {
    return false;
  }

  const expected = signCapsule(capsule, signingSecret).signature;
  return capsule.signature === expected;
}

export function isExpired(capsule) {
  return !capsule?.expires_at || new Date(capsule.expires_at).getTime() < Date.now();
}
