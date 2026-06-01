import fs from "node:fs/promises";
import path from "node:path";
import { hmacSha256, nowIso, stableStringify } from "./crypto.js";

export class LedgerAnchor {
  constructor({
    filePath = "",
    url = "",
    secret = "",
    every = 1,
    required = false,
    fetchImpl = globalThis.fetch
  } = {}) {
    this.filePath = filePath;
    this.url = url;
    this.secret = secret;
    this.every = Math.max(1, Number(every || 1));
    this.required = Boolean(required);
    this.fetchImpl = fetchImpl;
    this.count = 0;
  }

  get enabled() {
    return Boolean(this.filePath || this.url);
  }

  async record(entry) {
    if (!this.enabled) {
      return null;
    }
    this.count += 1;
    if (this.count % this.every !== 0) {
      return null;
    }

    const anchor = this.anchorPayload(entry);
    try {
      if (this.filePath) {
        await fs.mkdir(path.dirname(this.filePath), { recursive: true });
        await fs.appendFile(this.filePath, `${JSON.stringify(anchor)}\n`, { mode: 0o600 });
      }
      if (this.url) {
        await this.postAnchor(anchor);
      }
      return anchor;
    } catch (error) {
      if (this.required) {
        throw error;
      }
      return {
        ...anchor,
        anchored: false,
        error: error.message
      };
    }
  }

  anchorPayload(entry) {
    const payload = {
      schema: "scopezero.ledger_anchor.v1",
      anchored_at: nowIso(),
      event_id: entry.id,
      event_time: entry.time,
      event_type: entry.record?.event_type || "unknown",
      tenant_id: entry.record?.tenant_id || entry.record?.agent?.tenant_id || entry.record?.mission?.tenant_id || entry.record?.approval?.tenant_id || null,
      previous_hash: entry.previous_hash,
      chain_root: entry.hash
    };
    return {
      ...payload,
      signature: this.secret ? hmacSha256(this.secret, stableStringify(payload)) : null,
      anchored: true
    };
  }

  async postAnchor(anchor) {
    if (!this.fetchImpl) {
      throw new Error("Ledger anchor URL is configured but fetch is not available.");
    }
    const response = await this.fetchImpl(this.url, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "user-agent": "scopezero-ledger-anchor"
      },
      body: JSON.stringify(anchor)
    });
    if (!response.ok) {
      throw new Error(`Ledger anchor endpoint returned ${response.status}.`);
    }
  }
}

export function createLedgerAnchorFromEnv(env = process.env, fetchImpl = globalThis.fetch) {
  return new LedgerAnchor({
    filePath: env.SCOPEZERO_LEDGER_ANCHOR_FILE || "",
    url: env.SCOPEZERO_LEDGER_ANCHOR_URL || "",
    secret: env.SCOPEZERO_LEDGER_ANCHOR_SECRET || env.SCOPEZERO_SIGNING_SECRET || "",
    every: env.SCOPEZERO_LEDGER_ANCHOR_EVERY || 1,
    required: env.SCOPEZERO_LEDGER_ANCHOR_REQUIRED === "true",
    fetchImpl
  });
}
