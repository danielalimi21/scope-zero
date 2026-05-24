import fs from "node:fs/promises";
import path from "node:path";
import { createId, nowIso, sha256, stableStringify } from "./crypto.js";

export class Ledger {
  constructor(filePath) {
    this.filePath = filePath;
    this.previousHash = "genesis";
  }

  async init() {
    await fs.mkdir(path.dirname(this.filePath), { recursive: true });
    try {
      const entries = await this.list({ limit: 1, reverse: true });
      this.previousHash = entries[0]?.hash || "genesis";
    } catch {
      await fs.writeFile(this.filePath, "", { flag: "a" });
    }
  }

  async append(record) {
    const entry = {
      id: createId("evt", record.event_type || "decision"),
      time: nowIso(),
      previous_hash: this.previousHash,
      record
    };
    entry.hash = sha256(stableStringify(entry));
    this.previousHash = entry.hash;
    await fs.appendFile(this.filePath, `${JSON.stringify(entry)}\n`);
    return entry;
  }

  async list({ limit = 100, reverse = false } = {}) {
    try {
      const raw = await fs.readFile(this.filePath, "utf8");
      const entries = raw
        .split(/\r?\n/)
        .filter(Boolean)
        .map((line) => JSON.parse(line));
      const ordered = reverse ? entries.reverse() : entries;
      return ordered.slice(0, limit);
    } catch {
      return [];
    }
  }

  async verify() {
    const entries = await this.list({ limit: Number.MAX_SAFE_INTEGER, reverse: false });
    let expectedPrevious = "genesis";
    const failures = [];

    for (const [index, entry] of entries.entries()) {
      const { hash, ...unsigned } = entry;
      const expectedHash = sha256(stableStringify(unsigned));
      if (entry.previous_hash !== expectedPrevious) {
        failures.push({
          index,
          id: entry.id,
          reason: "previous_hash_mismatch",
          expected: expectedPrevious,
          actual: entry.previous_hash
        });
      }
      if (hash !== expectedHash) {
        failures.push({
          index,
          id: entry.id,
          reason: "hash_mismatch",
          expected: expectedHash,
          actual: hash
        });
      }
      expectedPrevious = hash;
    }

    return {
      valid: failures.length === 0,
      entries: entries.length,
      chain_root: entries.at(-1)?.hash || "genesis",
      failures
    };
  }
}
