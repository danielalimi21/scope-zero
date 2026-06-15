import { createId, ed25519Sign, ed25519Verify, ed25519VerifyWithKeyset, keyFingerprint, nowIso, stableStringify } from "./crypto.js";
import { buildDefaultActionContracts } from "./actionAuthorization.js";

export function createMissionCapsule(input, signingKey) {
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
    // External destinations this mission may post to autonomously (the explicit
    // opt-out of the default egress seal). Signed into the capsule so it can't be
    // widened after issue.
    public_egress_destinations: input.public_egress_destinations || [],
    action_contracts: input.action_contracts || buildDefaultActionContracts(input),
    evidence_schema: input.evidence_schema || "scopezero.action_authorization.v1",
    approval_profile: input.approval_profile || "standard",
    max_delegation_depth: Number(input.max_delegation_depth ?? 1),
    runtime_risk_budget: Number(input.runtime_risk_budget ?? 68),
    parent_mission_id: input.parent_mission_id || null,
    spawned_by_agent_id: input.spawned_by_agent_id || null,
    delegation_depth: Number(input.delegation_depth ?? 0),
    issued_at: issuedAt,
    expires_at: expiresAt,
    status: "active"
  };

  return signCapsule(capsule, signingKey);
}

// sz2 = Ed25519 signature over the canonical (key-sorted) unsigned capsule.
// signingKey may be a private KeyObject or a shared-secret string (derived). The
// signing key's `kid` is stamped into the (signed) body so a verifier with a
// keyset can pick the right key and so a rotated-out key's capsules keep verifying.
export function signCapsule(capsule, signingKey) {
  const unsigned = { ...capsule, kid: capsule.kid || keyFingerprint(signingKey) };
  delete unsigned.signature;
  return {
    ...unsigned,
    signature: `sz2.${ed25519Sign(signingKey, stableStringify(unsigned))}`
  };
}

// verifyKey may be a single public KeyObject / shared-secret string, OR a keyset
// array of { kid, key } (from buildVerificationKeyset) to support rotation. A
// verifier holding only public keys can confirm authenticity but cannot forge.
export function verifyMissionCapsule(capsule, verifyKey) {
  if (!capsule || typeof capsule.signature !== "string") {
    return false;
  }
  if (!capsule.signature.startsWith("sz2.")) {
    return false;
  }
  const unsigned = { ...capsule };
  delete unsigned.signature;
  const message = stableStringify(unsigned);
  const signature = capsule.signature.slice(4);
  if (Array.isArray(verifyKey)) {
    return ed25519VerifyWithKeyset(verifyKey, message, signature, capsule.kid) !== null;
  }
  return ed25519Verify(verifyKey, message, signature);
}

export function isExpired(capsule) {
  return !capsule?.expires_at || new Date(capsule.expires_at).getTime() < Date.now();
}
