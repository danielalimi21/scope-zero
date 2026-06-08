import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { signCapsule, verifyMissionCapsule } from "../src/capsules.js";
import { publicKeyToPem, buildVerificationKeyset, ed25519Sign } from "../src/crypto.js";

// The load-bearing crypto claim: a verifier holding only the PUBLIC key can
// confirm a mission capsule is authentic but CANNOT forge one. These tests
// exercise the explicit-keypair path (the production posture), not the dev
// shared-secret derivation — so they prove the asymmetric property end to end.

function freshKeypair() {
  return crypto.generateKeyPairSync("ed25519");
}

const baseCapsule = {
  capsule_type: "mission_action_contract",
  protocol: "AATP-0.2",
  id: "mission_forgery_test",
  tenant_id: "tenant_contoso",
  agent_id: "agent.test",
  delegated_by: "vp@contoso.example",
  objective: "Read the data room.",
  allowed_tools: ["drive.read"],
  allowed_data_classes: ["public", "internal"],
  allowed_destinations: ["diligence-room.contoso.example"],
  action_contracts: [],
  status: "active",
  issued_at: "2026-01-01T00:00:00.000Z",
  expires_at: "2099-01-01T00:00:00.000Z"
};

test("a capsule signed by the private key verifies against the public key alone", () => {
  const gw = freshKeypair();
  const signed = signCapsule(baseCapsule, gw.privateKey);
  // Verifier holds only the public key (as it would in the proxy / an auditor).
  const publicOnly = crypto.createPublicKey(publicKeyToPem(gw.publicKey));
  assert.equal(verifyMissionCapsule(signed, publicOnly), true);
});

test("a verifier holding only the public key cannot forge a signature", () => {
  const gw = freshKeypair();
  const publicOnly = crypto.createPublicKey(publicKeyToPem(gw.publicKey));
  // Attempting to SIGN with public-only material must fail — there is no private
  // scalar to produce a valid Ed25519 signature.
  assert.throws(() => signCapsule(baseCapsule, publicOnly), /Unsupported signing key material/);
  assert.throws(() => ed25519Sign(publicOnly, "anything"), /Unsupported signing key material/);
});

test("a capsule forged with an attacker's own keypair fails verification against the gateway key", () => {
  const gw = freshKeypair();
  const attacker = freshKeypair();
  // Attacker mints a capsule widening their own scope, signed with THEIR key.
  const forged = signCapsule({ ...baseCapsule, allowed_destinations: ["*"], allowed_tools: ["*"] }, attacker.privateKey);
  // It is internally well-formed and verifies under the attacker's key...
  assert.equal(verifyMissionCapsule(forged, attacker.publicKey), true);
  // ...but the gateway/proxy only trusts the gateway public key, so it is rejected.
  assert.equal(verifyMissionCapsule(forged, gw.publicKey), false);
  assert.equal(verifyMissionCapsule(forged, buildVerificationKeyset({ current: gw.publicKey })), false);
});

test("tampering a signed capsule's scope after signing breaks verification", () => {
  const gw = freshKeypair();
  const signed = signCapsule(baseCapsule, gw.privateKey);
  const tampered = { ...signed, allowed_destinations: ["*"], allowed_tools: ["*"] };
  assert.equal(verifyMissionCapsule(tampered, gw.publicKey), false);
});

test("rotation keyset still verifies a capsule signed under a retired key", () => {
  const retired = freshKeypair();
  const current = freshKeypair();
  const signed = signCapsule(baseCapsule, retired.privateKey);
  const keyset = buildVerificationKeyset({
    current: current.publicKey,
    additionalPublicKeyPems: [publicKeyToPem(retired.publicKey)]
  });
  assert.equal(verifyMissionCapsule(signed, keyset), true);
});
