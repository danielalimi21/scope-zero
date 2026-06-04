import crypto from "node:crypto";

export function stableStringify(value) {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value);
  }

  if (Array.isArray(value)) {
    return `[${value.map((item) => stableStringify(item)).join(",")}]`;
  }

  return `{${Object.keys(value)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${stableStringify(value[key])}`)
    .join(",")}}`;
}

export function sha256(value) {
  return crypto.createHash("sha256").update(String(value)).digest("hex");
}

export function hmacSha256(secret, value) {
  return crypto.createHmac("sha256", secret).update(String(value)).digest("hex");
}

// Constant-time comparison for signatures/MACs. The compared values are
// fixed-length hex/base64url MAC digests, so the length itself is not secret —
// a length mismatch can short-circuit without leaking byte-level timing.
export function timingSafeEqualStr(a, b) {
  const left = Buffer.from(String(a));
  const right = Buffer.from(String(b));
  if (left.length !== right.length) {
    return false;
  }
  return crypto.timingSafeEqual(left, right);
}

// ── Ed25519 asymmetric signing ──────────────────────────────────────────────
// Mission capsules and agent certs are signed with an Ed25519 private key and
// verified with the public key. The public key is safe to hand to verifiers (the
// proxy, an external auditor) — they can confirm authenticity without the power
// to forge. In production set SCOPEZERO_SIGNING_PRIVATE_KEY so the private key
// never leaves the gateway; in dev/tests the keypair is derived deterministically
// from the shared secret so a single secret still works end to end.

// 16-byte PKCS8 DER prefix for an Ed25519 private key, followed by the 32-byte seed.
const ED25519_PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");

export function ed25519KeyPairFromSeed(seed32) {
  const der = Buffer.concat([ED25519_PKCS8_PREFIX, Buffer.from(seed32).subarray(0, 32)]);
  const privateKey = crypto.createPrivateKey({ key: der, format: "der", type: "pkcs8" });
  const publicKey = crypto.createPublicKey(privateKey);
  return { privateKey, publicKey };
}

export function deriveSigningKeys(secret) {
  const seed = crypto.createHash("sha256").update(String(secret)).digest();
  return ed25519KeyPairFromSeed(seed);
}

export function loadSigningKeys({ privateKeyPem = "", secret = "" } = {}) {
  if (privateKeyPem) {
    const privateKey = crypto.createPrivateKey(privateKeyPem);
    return { privateKey, publicKey: crypto.createPublicKey(privateKey) };
  }
  return deriveSigningKeys(secret);
}

export function publicKeyToPem(publicKey) {
  return publicKey.export({ type: "spki", format: "pem" }).toString();
}

export function ed25519Sign(privateKey, message) {
  return crypto.sign(null, Buffer.from(String(message)), asPrivateKey(privateKey)).toString("base64");
}

export function ed25519Verify(publicKey, message, signatureB64) {
  try {
    return crypto.verify(null, Buffer.from(String(message)), asPublicKey(publicKey), Buffer.from(String(signatureB64), "base64"));
  } catch {
    return false;
  }
}

// Coerce signing material into a KeyObject. Accepts a private KeyObject, a
// { privateKey } pair, a PEM string starting with "-----BEGIN", or a raw shared
// secret (derived deterministically). Lets call sites pass either keys or a
// secret string without churn.
export function asPrivateKey(material) {
  if (isKeyObject(material) && material.type === "private") return material;
  if (material?.privateKey && isKeyObject(material.privateKey)) return material.privateKey;
  if (typeof material === "string") {
    return material.includes("-----BEGIN")
      ? crypto.createPrivateKey(material)
      : deriveSigningKeys(material).privateKey;
  }
  throw new TypeError("Unsupported signing key material.");
}

export function asPublicKey(material) {
  if (isKeyObject(material) && material.type === "public") return material;
  if (isKeyObject(material) && material.type === "private") return crypto.createPublicKey(material);
  if (material?.publicKey && isKeyObject(material.publicKey)) return material.publicKey;
  if (typeof material === "string") {
    return material.includes("-----BEGIN")
      ? crypto.createPublicKey(material)
      : deriveSigningKeys(material).publicKey;
  }
  throw new TypeError("Unsupported verification key material.");
}

function isKeyObject(value) {
  return value instanceof crypto.KeyObject;
}

export function createId(prefix, payload = "") {
  const entropy = `${Date.now()}:${crypto.randomUUID()}:${payload}`;
  return `${prefix}_${sha256(entropy).slice(0, 16)}`;
}

export function nowIso() {
  return new Date().toISOString();
}
