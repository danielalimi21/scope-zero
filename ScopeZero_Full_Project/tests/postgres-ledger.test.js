// Multi-replica ledger integrity. Runs only when DATABASE_URL points at a real
// Postgres (skipped otherwise, so the default suite stays dependency-free). Proves
// the shared-sequencer ledger keeps a valid hash chain under concurrent appends
// from multiple replicas, and still detects tampering.
//
//   DATABASE_URL=postgres://... node --test tests/postgres-ledger.test.js

import test from "node:test";
import assert from "node:assert/strict";

const RUN = Boolean(process.env.DATABASE_URL && process.env.SCOPEZERO_STORE === "postgres");

test("shared-sequencer ledger stays valid under multi-replica concurrent appends", { skip: !RUN }, async () => {
  const { PostgresStore } = await import("../src/postgresStore.js");
  const { PostgresLedger } = await import("../src/postgresLedger.js");
  const pg = (await import("pg")).default;
  const policy = (await import("../config/defaultPolicy.json", { with: { type: "json" } })).default;
  const url = process.env.DATABASE_URL;

  const store = new PostgresStore({ connectionString: url, defaultPolicy: policy });
  await store.init();
  await store.pool.query("DELETE FROM evidence_ledger");

  // Two independent ledgers (separate pools) = two replicas sharing the DB.
  const repA = new PostgresLedger({ pool: new pg.Pool({ connectionString: url, ssl: false }), secret: "led-secret" });
  const repB = new PostgresLedger({ pool: new pg.Pool({ connectionString: url, ssl: false }), secret: "led-secret" });
  await repA.init(); await repB.init();

  await Promise.all(Array.from({ length: 400 }, (_, i) =>
    (i % 2 ? repB : repA).append({ event_type: "x", tenant_id: "tenant_contoso", n: i, verdict: { decision: "allow", risk_score: 8 } })
  ));

  const v = await repA.verify();
  assert.equal(v.valid, true, `chain must be valid across replicas (${v.failures.length} failures)`);
  assert.equal(v.entries, 400);

  // Tampering a stored record must break verification.
  await repA.pool.query("UPDATE evidence_ledger SET record = jsonb_set(record,'{n}','999') WHERE seq=(SELECT min(seq) FROM evidence_ledger)");
  const v2 = await repA.verify();
  assert.equal(v2.valid, false, "a tampered record must fail verification");

  await repA.pool.end(); await repB.pool.end(); await store.pool.end();
});
