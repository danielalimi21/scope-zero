import { createId, hmacSha256, nowIso, sha256, stableStringify } from "./crypto.js";

// Postgres-backed evidence ledger with a SHARED SEQUENCER.
//
// The file Ledger serializes appends within one process — correct for a single
// replica, but two replicas would each chain from their own head and fork the
// chain. This ledger serializes appends across ALL replicas using a Postgres
// transaction-scoped advisory lock: only one append runs at a time cluster-wide,
// each reads the true chain head from the table inside the lock, and a monotonic
// `seq` fixes a total order independent of wall-clock time. So the hash chain
// stays valid under concurrency AND across replicas.
export class PostgresLedger {
  // Arbitrary stable key for the global ledger advisory lock.
  static LOCK_KEY = 728010n;

  constructor({ pool, secret = "", anchor = null }) {
    this.pool = pool;
    this.secret = secret || "";
    this.anchor = anchor;
  }

  chainHash(serialized) {
    return this.secret ? hmacSha256(this.secret, serialized) : sha256(serialized);
  }

  async init() {
    // The evidence_ledger table is created by the Postgres store migrate(); add the
    // monotonic ordering column + sequence + index idempotently.
    await this.pool.query(`
      ALTER TABLE evidence_ledger ADD COLUMN IF NOT EXISTS seq BIGINT;
      CREATE SEQUENCE IF NOT EXISTS evidence_ledger_seq OWNED BY evidence_ledger.seq;
      CREATE INDEX IF NOT EXISTS evidence_ledger_seq_idx ON evidence_ledger (seq);
    `);
  }

  async append(record) {
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      // Cross-tenant write (the ledger spans tenants); RLS is satisfied with the
      // wildcard GUC. The advisory lock is released automatically at COMMIT/ROLLBACK.
      await client.query("SET LOCAL scopezero.tenant_id = '*'");
      await client.query("SELECT pg_advisory_xact_lock($1)", [PostgresLedger.LOCK_KEY.toString()]);

      const head = await client.query("SELECT hash FROM evidence_ledger ORDER BY seq DESC LIMIT 1");
      const previousHash = head.rows[0]?.hash || "genesis";

      const entry = {
        id: createId("evt", record.event_type || "decision"),
        time: nowIso(),
        previous_hash: previousHash,
        record
      };
      // Hash over {id, previous_hash, record} only. `time` is stored as a typed
      // TIMESTAMPTZ column (lossy round-trip), so it is display metadata, not part
      // of the chain — the id + previous_hash + record linkage is what's
      // tamper-evident. verify() recomputes over the same subset.
      entry.hash = this.chainHash(stableStringify({ id: entry.id, previous_hash: entry.previous_hash, record: entry.record }));

      await client.query(
        `INSERT INTO evidence_ledger (id, time, tenant_id, event_type, previous_hash, hash, record, seq)
         VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, nextval('evidence_ledger_seq'))`,
        [entry.id, entry.time, record.tenant_id || null, record.event_type || "decision", entry.previous_hash, entry.hash, JSON.stringify(record)]
      );
      await client.query("COMMIT");
      await this.anchor?.record(entry);
      return entry;
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally {
      client.release();
    }
  }

  async list({ limit = 100, reverse = false } = {}) {
    const result = await this.pool.query(
      `SELECT id, time, previous_hash, hash, record FROM evidence_ledger ORDER BY seq ${reverse ? "DESC" : "ASC"} LIMIT $1`,
      [limit]
    );
    return result.rows.map((r) => ({ id: r.id, time: r.time, previous_hash: r.previous_hash, hash: r.hash, record: r.record }));
  }

  async verify() {
    const result = await this.pool.query("SELECT id, time, previous_hash, hash, record FROM evidence_ledger ORDER BY seq ASC");
    let expectedPrevious = "genesis";
    const failures = [];
    for (const [index, row] of result.rows.entries()) {
      const expectedHash = this.chainHash(stableStringify({ id: row.id, previous_hash: row.previous_hash, record: row.record }));
      if (row.previous_hash !== expectedPrevious) {
        failures.push({ index, id: row.id, reason: "previous_hash_mismatch", expected: expectedPrevious, actual: row.previous_hash });
      }
      if (row.hash !== expectedHash) {
        failures.push({ index, id: row.id, reason: "hash_mismatch", expected: expectedHash, actual: row.hash });
      }
      expectedPrevious = row.hash;
    }
    return {
      valid: failures.length === 0,
      entries: result.rows.length,
      chain_root: result.rows.at(-1)?.hash || "genesis",
      failures
    };
  }
}
