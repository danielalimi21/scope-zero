import test from "node:test";
import assert from "node:assert/strict";
import { assessStartupReadiness } from "../src/startupGate.js";

const prodBase = {
  NODE_ENV: "production",
  SCOPEZERO_SIGNING_PRIVATE_KEY: "-----BEGIN PRIVATE KEY-----\nx\n-----END PRIVATE KEY-----",
  SCOPEZERO_SIGNING_SECRET: "a-real-secret",
  SCOPEZERO_EGRESS_LOCKDOWN: "k8s",
  SCOPEZERO_REQUIRE_AUTH: "true",
  SCOPEZERO_ALLOW_DEV_TOKEN: "false"
};

test("dev mode never blocks boot, only warns on derived keys", () => {
  const result = assessStartupReadiness({ NODE_ENV: "development" });
  assert.equal(result.ok, true);
  assert.ok(result.warnings.some((w) => w.includes("derived from the shared secret")));
});

test("a fully configured production env passes the gate", () => {
  const result = assessStartupReadiness(prodBase);
  assert.equal(result.ok, true);
  assert.equal(result.fatal.length, 0);
});

test("production without an explicit signing private key is fatal", () => {
  const { SCOPEZERO_SIGNING_PRIVATE_KEY, ...env } = prodBase;
  const result = assessStartupReadiness(env);
  assert.equal(result.ok, false);
  assert.ok(result.fatal.some((f) => f.includes("SCOPEZERO_SIGNING_PRIVATE_KEY")));
});

test("production without a declared egress lockdown is fatal", () => {
  const result = assessStartupReadiness({ ...prodBase, SCOPEZERO_EGRESS_LOCKDOWN: "none" });
  assert.equal(result.ok, false);
  assert.ok(result.fatal.some((f) => f.includes("SCOPEZERO_EGRESS_LOCKDOWN")));
});

test("production with the default signing secret is fatal", () => {
  const result = assessStartupReadiness({ ...prodBase, SCOPEZERO_SIGNING_SECRET: "dev-scopezero-signing-secret-change-me" });
  assert.equal(result.ok, false);
  assert.ok(result.fatal.some((f) => f.includes("SCOPEZERO_SIGNING_SECRET")));
});

test("production with auth disabled or dev tokens on is fatal", () => {
  const noAuth = assessStartupReadiness({ ...prodBase, SCOPEZERO_REQUIRE_AUTH: "false" });
  assert.ok(noAuth.fatal.some((f) => f.includes("SCOPEZERO_REQUIRE_AUTH")));
  const devToken = assessStartupReadiness({ ...prodBase, SCOPEZERO_ALLOW_DEV_TOKEN: "true" });
  assert.ok(devToken.fatal.some((f) => f.includes("SCOPEZERO_ALLOW_DEV_TOKEN")));
});
