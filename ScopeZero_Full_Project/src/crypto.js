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

export function createId(prefix, payload = "") {
  const entropy = `${Date.now()}:${crypto.randomUUID()}:${payload}`;
  return `${prefix}_${sha256(entropy).slice(0, 16)}`;
}

export function nowIso() {
  return new Date().toISOString();
}
