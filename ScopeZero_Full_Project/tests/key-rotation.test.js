import test from "node:test";
import assert from "node:assert/strict";
import { createMissionCapsule, verifyMissionCapsule } from "../src/capsules.js";
import { issueAgentCertificate, verifyAgentCertificate } from "../src/agentCert.js";
import { buildVerificationKeyset, deriveSigningKeys, keyFingerprint, publicKeyToPem } from "../src/crypto.js";

const keyA = deriveSigningKeys("retired-key-secret");
const keyB = deriveSigningKeys("current-key-secret");

const missionInput = {
  tenant_id: "tenant_contoso",
  agent_id: "agent.rotate.1",
  delegated_by: "vp@contoso.example",
  objective: "Read diligence docs.",
  allowed_tools: ["drive.read"],
  allowed_destinations: ["diligence-room.contoso.example"]
};

test("a capsule carries the signing key's kid", () => {
  const capsule = createMissionCapsule(missionInput, keyA.privateKey);
  assert.equal(capsule.kid, keyFingerprint(keyA.publicKey));
});

test("a capsule signed by a retired key still verifies when its public key is in the keyset", () => {
  const capsule = createMissionCapsule(missionInput, keyA.privateKey);
  const keyset = buildVerificationKeyset({
    current: keyB.publicKey,
    additionalPublicKeyPems: [publicKeyToPem(keyA.publicKey)]
  });
  assert.equal(verifyMissionCapsule(capsule, keyset), true);
});

test("a capsule does NOT verify against a keyset missing its key", () => {
  const capsule = createMissionCapsule(missionInput, keyA.privateKey);
  const keyset = buildVerificationKeyset({ current: keyB.publicKey });
  assert.equal(verifyMissionCapsule(capsule, keyset), false);
});

test("single-key verification stays backward compatible", () => {
  const capsule = createMissionCapsule(missionInput, keyA.privateKey);
  assert.equal(verifyMissionCapsule(capsule, keyA.publicKey), true);
  assert.equal(verifyMissionCapsule(capsule, keyB.publicKey), false);
});

test("a tampered capsule fails keyset verification", () => {
  const capsule = createMissionCapsule(missionInput, keyA.privateKey);
  capsule.allowed_tools = ["drive.read", "gmail.send"]; // widen scope after signing
  const keyset = buildVerificationKeyset({
    current: keyB.publicKey,
    additionalPublicKeyPems: [publicKeyToPem(keyA.publicKey)]
  });
  assert.equal(verifyMissionCapsule(capsule, keyset), false);
});

test("an agent cert signed by a retired key verifies via the keyset", () => {
  const cert = issueAgentCertificate({ tenant_id: "tenant_contoso", agent_id: "agent.rotate.1", allowed_tools: ["drive.read"] }, keyA.privateKey);
  const keyset = buildVerificationKeyset({
    current: keyB.publicKey,
    additionalPublicKeyPems: [publicKeyToPem(keyA.publicKey)]
  });
  assert.equal(verifyAgentCertificate(cert, keyset).valid, true);
  assert.equal(verifyAgentCertificate(cert, buildVerificationKeyset({ current: keyB.publicKey })).valid, false);
});
