import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { createMissionCapsule, signCapsule, verifyMissionCapsule } from "../src/capsules.js";
import { Ledger } from "../src/ledger.js";
import { deriveSigningKeys, loadSigningKeys, publicKeyToPem } from "../src/crypto.js";

test("mission capsule signature detects tampering", () => {
  const secret = "test-signing-secret";
  const capsule = createMissionCapsule(
    {
      tenant_id: "tenant_contoso",
      agent_id: "agent.test",
      delegated_by: "owner@example.com",
      objective: "Summarize diligence documents.",
      allowed_tools: ["drive.read"],
      ttl_minutes: 5
    },
    secret
  );

  assert.equal(verifyMissionCapsule(capsule, secret), true);
  assert.equal(verifyMissionCapsule({ ...capsule, objective: "Export all customer data." }, secret), false);
});

test("capsules are Ed25519-signed: the public key verifies but cannot forge", () => {
  const keys = loadSigningKeys({ secret: "gateway-private-seed" });
  const capsule = createMissionCapsule(
    {
      tenant_id: "tenant_contoso",
      agent_id: "agent.test",
      delegated_by: "owner@example.com",
      objective: "Read the data room.",
      allowed_tools: ["drive.read"],
      ttl_minutes: 5
    },
    keys.privateKey
  );

  // Signature is Ed25519 (sz2), not the legacy HMAC (sz1).
  assert.ok(capsule.signature.startsWith("sz2."));

  // A verifier holding ONLY the public key (even as a distributable PEM) can
  // confirm authenticity.
  assert.equal(verifyMissionCapsule(capsule, keys.publicKey), true);
  assert.equal(verifyMissionCapsule(capsule, publicKeyToPem(keys.publicKey)), true);

  // A different keypair (an attacker without the gateway's private key) cannot
  // produce a signature that the real public key accepts.
  const attacker = deriveSigningKeys("attacker-seed");
  const forged = signCapsule({ ...capsule, allowed_tools: ["*"] }, attacker.privateKey);
  assert.equal(verifyMissionCapsule(forged, keys.publicKey), false);
});

test("legacy HMAC (sz1) signatures are rejected", () => {
  const keys = loadSigningKeys({ secret: "seed" });
  const capsule = createMissionCapsule(
    { tenant_id: "t", agent_id: "a", delegated_by: "o", objective: "x", allowed_tools: [], ttl_minutes: 5 },
    keys.privateKey
  );
  const legacy = { ...capsule, signature: "sz1.deadbeef" };
  assert.equal(verifyMissionCapsule(legacy, keys.publicKey), false);
});

test("ledger verification detects hash-chain tampering", async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "scopezero-ledger-"));
  const ledgerPath = path.join(dir, "ledger.jsonl");
  const ledger = new Ledger(ledgerPath);
  await ledger.init();
  await ledger.append({ event_type: "test.one", tenant_id: "tenant_contoso" });
  await ledger.append({ event_type: "test.two", tenant_id: "tenant_contoso" });

  const valid = await ledger.verify();
  assert.equal(valid.valid, true);

  const lines = (await fs.readFile(ledgerPath, "utf8")).trim().split("\n");
  const first = JSON.parse(lines[0]);
  first.record.tenant_id = "tenant_evil";
  await fs.writeFile(ledgerPath, [JSON.stringify(first), lines[1]].join("\n") + "\n");

  const tampered = await ledger.verify();
  assert.equal(tampered.valid, false);
  assert.ok(tampered.failures.some((failure) => failure.reason === "hash_mismatch"));
});
