import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

const TENANT_TABLES = ["tenants", "agents", "missions", "approvals", "policies", "policy_versions", "behavior_profiles", "sessions", "evidence_ledger"];

test("postgres target schema enables tenant row-level security", async () => {
  const schema = await readFile(new URL("../db/postgres/schema.sql", import.meta.url), "utf8");

  for (const table of TENANT_TABLES) {
    assert.match(schema, new RegExp(`ALTER TABLE ${table} ENABLE ROW LEVEL SECURITY;`));
    assert.match(schema, new RegExp(`ALTER TABLE ${table} FORCE ROW LEVEL SECURITY;`));
    assert.match(schema, new RegExp(`CREATE POLICY ${table}_scopezero_tenant_isolation ON ${table}`));
  }
  assert.match(schema, /current_setting\('scopezero\.tenant_id', true\)/);
});

test("postgres adapter mirrors state into tenant-scoped relational tables under RLS", async () => {
  const source = await readFile(new URL("../src/postgresStore.js", import.meta.url), "utf8");

  assert.match(source, /enableTenantRls/);
  assert.match(source, /SET LOCAL scopezero\.tenant_id = '\*'/);
  for (const table of ["tenants", "agents", "missions", "approvals", "policies", "policy_versions"]) {
    assert.match(source, new RegExp(`INSERT INTO ${table}`));
  }
});

test("postgres hot-path tables (behavior_profiles, sessions) are RLS-protected and written per-row", async () => {
  const source = await readFile(new URL("../src/postgresStore.js", import.meta.url), "utf8");

  for (const table of ["behavior_profiles", "sessions"]) {
    // table created, RLS enabled+forced, tenant-isolation policy, per-row upsert
    assert.match(source, new RegExp(`CREATE TABLE IF NOT EXISTS ${table}`));
    assert.match(source, new RegExp(`ALTER TABLE ${table} ENABLE ROW LEVEL SECURITY`));
    assert.match(source, new RegExp(`ALTER TABLE ${table} FORCE ROW LEVEL SECURITY`));
    assert.match(source, new RegExp(`INSERT INTO ${table}`));
  }
  // hot-path writes run in a tenant-scoped transaction, not through the global write lock
  assert.match(source, /withTenant\(/);
  assert.match(source, /set_config\('scopezero\.tenant_id'/);
  // metrics are atomic counters, not a full-state rewrite
  assert.match(source, /INSERT INTO metrics .*ON CONFLICT \(name\) DO UPDATE SET value = metrics\.value \+ 1/s);
  // the old global-lock wrapper for the hot path is gone
  assert.doesNotMatch(source, /withWriteLock\(\(\) => super\.updateSessionRisk/);
  assert.doesNotMatch(source, /withWriteLock\(\(\) => super\.recordDecision/);
});
