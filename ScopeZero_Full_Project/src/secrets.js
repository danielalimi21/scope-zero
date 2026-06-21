import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import { nowIso } from "./crypto.js";

const ALGORITHM = "aes-256-gcm";
const GCM_TAG_BYTES = 16; // pin the full GCM auth-tag length (forgery resistance)

export class SecretManager {
  constructor({ rootDir, masterKey = "", provider = "local" }) {
    this.rootDir = rootDir;
    this.masterKey = masterKey;
    this.provider = provider;
    this.filePath = path.join(rootDir, "data", "secrets.enc.json");
  }

  async put({ tenant_id, name, value, created_by = "unknown" }) {
    if (!tenant_id || !name || typeof value !== "string") {
      throw new Error("tenant_id, name, and string value are required.");
    }
    const store = await this.load();
    const ref = `secret://${tenant_id}/${name}`;
    store[ref] = {
      ref,
      tenant_id,
      name,
      provider: this.provider,
      ciphertext: this.encrypt(value),
      created_by,
      created_at: nowIso(),
      updated_at: nowIso()
    };
    await this.save(store);
    return this.describe(store[ref]);
  }

  async list(tenantId) {
    const store = await this.load();
    return Object.values(store)
      .filter((secret) => secret.tenant_id === tenantId)
      .map((secret) => this.describe(secret));
  }

  async get(ref, tenantId) {
    const store = await this.load();
    const secret = store[ref];
    if (!secret || secret.tenant_id !== tenantId) {
      return null;
    }
    return this.decrypt(secret.ciphertext);
  }

  describe(secret) {
    return {
      ref: secret.ref,
      tenant_id: secret.tenant_id,
      name: secret.name,
      provider: secret.provider,
      created_by: secret.created_by,
      created_at: secret.created_at,
      updated_at: secret.updated_at
    };
  }

  encrypt(plaintext) {
    const key = this.key();
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv(ALGORITHM, key, iv, { authTagLength: GCM_TAG_BYTES });
    const encrypted = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
    const tag = cipher.getAuthTag();
    return `${iv.toString("base64url")}.${tag.toString("base64url")}.${encrypted.toString("base64url")}`;
  }

  decrypt(value) {
    const [ivRaw, tagRaw, encryptedRaw] = value.split(".");
    const tag = Buffer.from(tagRaw || "", "base64url");
    // Pin the GCM auth-tag length and reject a short/truncated tag before use. A
    // shorter-than-full tag weakens forgery resistance, so a tampered ciphertext
    // with a truncated tag must fail loudly, not verify against a weaker tag.
    if (tag.length !== GCM_TAG_BYTES) {
      throw new Error("Invalid authentication tag length on encrypted secret.");
    }
    const decipher = crypto.createDecipheriv(ALGORITHM, this.key(), Buffer.from(ivRaw, "base64url"), { authTagLength: GCM_TAG_BYTES });
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(Buffer.from(encryptedRaw, "base64url")), decipher.final()]).toString("utf8");
  }

  key() {
    if (!this.masterKey || this.masterKey.length < 16) {
      throw new Error("SCOPEZERO_SECRETS_MASTER_KEY must be set to use encrypted local secrets.");
    }
    return crypto.createHash("sha256").update(this.masterKey).digest();
  }

  async load() {
    try {
      return JSON.parse(await fs.readFile(this.filePath, "utf8"));
    } catch {
      return {};
    }
  }

  async save(store) {
    await fs.mkdir(path.dirname(this.filePath), { recursive: true });
    await fs.writeFile(this.filePath, JSON.stringify(store, null, 2));
  }
}
