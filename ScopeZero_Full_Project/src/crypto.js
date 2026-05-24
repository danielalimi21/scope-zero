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

export function createId(prefix, payload = "") {
  const entropy = `${Date.now()}:${crypto.randomUUID()}:${payload}`;
  return `${prefix}_${sha256(entropy).slice(0, 16)}`;
}

export function nowIso() {
  return new Date().toISOString();
}
