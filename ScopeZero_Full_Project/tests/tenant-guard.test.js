import test from "node:test";
import assert from "node:assert/strict";
import { enforceTenant } from "../src/tenantGuard.js";

test("enforceTenant allows platform admin on any tenant", () => {
  const admin = { tenants: ["*"] };
  assert.equal(enforceTenant(admin, "tenant_a"), "tenant_a");
  assert.equal(enforceTenant(admin, "tenant_b"), "tenant_b");
});

test("enforceTenant allows matching tenant", () => {
  const principal = { tenants: ["tenant_contoso"] };
  assert.equal(enforceTenant(principal, "tenant_contoso"), "tenant_contoso");
});

test("enforceTenant blocks mismatched tenant", () => {
  const principal = { tenants: ["tenant_contoso"] };
  assert.throws(
    () => enforceTenant(principal, "tenant_evil"),
    (err) => err.code === "tenant_mismatch" && err.status === 403
  );
});

test("enforceTenant blocks missing tenant_id", () => {
  const principal = { tenants: ["tenant_contoso"] };
  assert.throws(
    () => enforceTenant(principal, ""),
    (err) => err.code === "missing_tenant" && err.status === 400
  );
});
