import test from "node:test";
import assert from "node:assert/strict";
import {
  issueAgentCertificate,
  verifyAgentCertificate,
  verifyCertIdentity,
  certFingerprint,
  DEFAULT_TTL_MS
} from "../src/agentCert.js";

const SECRET = "test-signing-secret-for-certs";
const agent = {
  tenant_id: "tenant_contoso",
  agent_id: "agent.test.001",
  name: "Test Agent",
  owner: "test@contoso.example",
  environment: "production",
  allowed_tools: ["drive.read", "slack.draft"],
  max_delegation_depth: 1
};

function issueFresh(overrides = {}) {
  return issueAgentCertificate({ ...agent, ...overrides }, SECRET);
}

// Issuance

test("issued cert has required fields", () => {
  const cert = issueFresh();
  assert.ok(cert.cert_id.startsWith("cert_"));
  assert.equal(cert.tenant_id, agent.tenant_id);
  assert.equal(cert.agent_id, agent.agent_id);
  assert.equal(cert.version, "scopezero.agent.cert.v1");
  assert.equal(cert.issued_by, "scopezero");
  assert.equal(cert.status, "active");
  assert.ok(cert.fingerprint);
  assert.ok(cert.signature);
  assert.ok(cert.expires_at > cert.issued_at);
});

test("cert capabilities reflect agent allowed_tools", () => {
  const cert = issueFresh();
  assert.deepEqual(cert.capabilities.allowed_tools, agent.allowed_tools);
});

test("custom ttl_ms shifts expiry", () => {
  const oneDay = 24 * 60 * 60 * 1000;
  const cert = issueAgentCertificate(agent, SECRET, { ttlMs: oneDay });
  const diffMs = new Date(cert.expires_at).getTime() - new Date(cert.issued_at).getTime();
  assert.ok(Math.abs(diffMs - oneDay) < 5000, "expiry should be ~1 day from issuance");
});

test("default ttl is 90 days", () => {
  const cert = issueFresh();
  const diffMs = new Date(cert.expires_at).getTime() - new Date(cert.issued_at).getTime();
  assert.ok(Math.abs(diffMs - DEFAULT_TTL_MS) < 5000);
});

// Verification

test("valid cert verifies successfully", () => {
  const cert = issueFresh();
  const result = verifyAgentCertificate(cert, SECRET);
  assert.equal(result.valid, true);
  assert.equal(result.code, "cert-valid");
  assert.equal(result.fingerprint, cert.fingerprint);
});

test("wrong signing secret fails verification", () => {
  const cert = issueFresh();
  const result = verifyAgentCertificate(cert, "wrong-secret");
  assert.equal(result.valid, false);
  assert.equal(result.code, "cert-signature-invalid");
});

test("tampered body fails fingerprint check", () => {
  const cert = issueFresh();
  const tampered = { ...cert, agent_name: "EVIL AGENT" };
  const result = verifyAgentCertificate(tampered, SECRET);
  assert.equal(result.valid, false);
  assert.equal(result.code, "cert-fingerprint-mismatch");
});

test("expired cert fails verification", () => {
  const past = new Date(Date.now() - 1000).toISOString();
  const cert = issueAgentCertificate(agent, SECRET, { ttlMs: -1000 });
  const result = verifyAgentCertificate(cert, SECRET);
  assert.equal(result.valid, false);
  assert.equal(result.code, "cert-expired");
});

test("revoked cert fails verification", () => {
  const cert = { ...issueFresh(), status: "revoked" };
  const result = verifyAgentCertificate(cert, SECRET);
  assert.equal(result.valid, false);
  assert.equal(result.code, "cert-revoked");
});

test("null cert returns missing-cert", () => {
  const result = verifyAgentCertificate(null, SECRET);
  assert.equal(result.valid, false);
  assert.equal(result.code, "missing-cert");
});

test("unknown version returns version-mismatch", () => {
  const cert = { ...issueFresh(), version: "scopezero.agent.cert.v99" };
  const result = verifyAgentCertificate(cert, SECRET);
  assert.equal(result.valid, false);
  assert.equal(result.code, "cert-version-mismatch");
});

// Identity checks

test("verifyCertIdentity passes when agent and tenant match", () => {
  const cert = issueFresh();
  const result = verifyCertIdentity(cert, agent.agent_id, agent.tenant_id);
  assert.equal(result.valid, true);
});

test("verifyCertIdentity fails on agent_id mismatch", () => {
  const cert = issueFresh();
  const result = verifyCertIdentity(cert, "agent.different", agent.tenant_id);
  assert.equal(result.valid, false);
  assert.equal(result.code, "cert-agent-mismatch");
});

test("verifyCertIdentity fails on tenant_id mismatch", () => {
  const cert = issueFresh();
  const result = verifyCertIdentity(cert, agent.agent_id, "tenant_other");
  assert.equal(result.valid, false);
  assert.equal(result.code, "cert-tenant-mismatch");
});

// certFingerprint helper

test("certFingerprint returns the fingerprint field", () => {
  const cert = issueFresh();
  assert.equal(certFingerprint(cert), cert.fingerprint);
});

test("certFingerprint returns null for null input", () => {
  assert.equal(certFingerprint(null), null);
});
