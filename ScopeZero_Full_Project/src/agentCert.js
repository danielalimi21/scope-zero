import { createId, ed25519Sign, ed25519Verify, nowIso, sha256, stableStringify, timingSafeEqualStr } from "./crypto.js";

const CERT_VERSION = "scopezero.agent.cert.v1";
export const DEFAULT_TTL_MS = 90 * 24 * 60 * 60 * 1000; // 90 days

export function issueAgentCertificate(agent, signingKey, { ttlMs = DEFAULT_TTL_MS } = {}) {
  const issuedAt = new Date();
  const expiresAt = new Date(issuedAt.getTime() + ttlMs);

  const body = {
    version: CERT_VERSION,
    tenant_id: agent.tenant_id,
    agent_id: agent.agent_id,
    agent_name: agent.name || agent.agent_id,
    owner: agent.owner || null,
    issued_by: "scopezero",
    issued_at: issuedAt.toISOString(),
    expires_at: expiresAt.toISOString(),
    capabilities: {
      allowed_tools: agent.allowed_tools || [],
      max_delegation_depth: agent.max_delegation_depth ?? 1,
      environments: [agent.environment || "production"]
    }
  };

  const fingerprint = sha256(stableStringify(body));
  const signature = signCert(fingerprint, agent.agent_id, agent.tenant_id, expiresAt.toISOString(), signingKey);

  return {
    cert_id: createId("cert", `${agent.tenant_id}:${agent.agent_id}`),
    ...body,
    fingerprint,
    signature,
    status: "active"
  };
}

export function verifyAgentCertificate(cert, verifyKey) {
  if (!cert) {
    return { valid: false, code: "missing-cert", message: "No certificate provided." };
  }
  if (cert.version !== CERT_VERSION) {
    return { valid: false, code: "cert-version-mismatch", message: "Unrecognized certificate version." };
  }
  if (cert.status === "revoked") {
    return { valid: false, code: "cert-revoked", message: `Certificate ${cert.cert_id} has been revoked.` };
  }
  if (new Date(cert.expires_at) < new Date()) {
    return { valid: false, code: "cert-expired", message: `Certificate expired at ${cert.expires_at}.` };
  }

  // Recompute fingerprint from body (exclude cert_id, fingerprint, signature, status)
  const { cert_id, fingerprint, signature, status, ...body } = cert;
  const expectedFingerprint = sha256(stableStringify(body));
  if (!timingSafeEqualStr(fingerprint, expectedFingerprint)) {
    return { valid: false, code: "cert-fingerprint-mismatch", message: "Certificate body has been tampered with." };
  }

  const signedMessage = certSigningMessage(fingerprint, cert.agent_id, cert.tenant_id, cert.expires_at);
  if (!ed25519Verify(verifyKey, signedMessage, signature)) {
    return { valid: false, code: "cert-signature-invalid", message: "Certificate signature verification failed." };
  }

  return { valid: true, code: "cert-valid", fingerprint, cert_id };
}

// Verify cert belongs to the claimed agent + tenant
export function verifyCertIdentity(cert, agentId, tenantId) {
  if (cert.agent_id !== agentId) {
    return { valid: false, code: "cert-agent-mismatch", message: "Certificate agent_id does not match the requesting agent." };
  }
  if (cert.tenant_id !== tenantId) {
    return { valid: false, code: "cert-tenant-mismatch", message: "Certificate tenant_id does not match." };
  }
  return { valid: true };
}

export function certFingerprint(cert) {
  return cert?.fingerprint || null;
}

function certSigningMessage(fingerprint, agentId, tenantId, expiresAt) {
  return `${fingerprint}:${agentId}:${tenantId}:${expiresAt}`;
}

function signCert(fingerprint, agentId, tenantId, expiresAt, signingKey) {
  return ed25519Sign(signingKey, certSigningMessage(fingerprint, agentId, tenantId, expiresAt));
}
