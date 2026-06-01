import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

const TENANT_TABLES = ["tenants", "agents", "missions", "approvals", "policies", "policy_versions", "evidence_ledger"];

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
