// Generate an Ed25519 signing keypair for ScopeZero.
//
//   node tools/gen-keys.js
//
// Prints a PEM private key (set as SCOPEZERO_SIGNING_PRIVATE_KEY on the gateway,
// or hand it to your KMS/secret manager) and the matching public key + key id.
// In production the private key must be set explicitly — the gateway refuses to
// boot deriving it from the shared secret. The public key is safe to distribute
// to verifiers (the proxy, an external auditor); add a rotated-out public key to
// SCOPEZERO_SIGNING_PUBLIC_KEYS so its live capsules/certs keep verifying.

import crypto from "node:crypto";
import { keyFingerprint, publicKeyToPem } from "../src/crypto.js";

const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
const privatePem = privateKey.export({ type: "pkcs8", format: "pem" }).toString();
const publicPem = publicKeyToPem(publicKey);
const kid = keyFingerprint(publicKey);

const json = process.argv.includes("--json");

if (json) {
  console.log(JSON.stringify({ kid, private_key_pem: privatePem, public_key_pem: publicPem }, null, 2));
} else {
  console.log(`# ScopeZero Ed25519 signing key — kid ${kid}`);
  console.log(`#`);
  console.log(`# Gateway (private key — keep secret, prefer a KMS/secret manager):`);
  console.log(`#   export SCOPEZERO_SIGNING_PRIVATE_KEY="$(cat scopezero-signing.key)"`);
  console.log(`# Verifiers / rotation (public key — safe to distribute):`);
  console.log(`#   export SCOPEZERO_SIGNING_PUBLIC_KEYS="$(cat scopezero-signing.pub)"`);
  console.log("");
  console.log(privatePem.trim());
  console.log("");
  console.log(publicPem.trim());
}
