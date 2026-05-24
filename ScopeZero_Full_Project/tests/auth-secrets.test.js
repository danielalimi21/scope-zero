import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { AuthService } from "../src/auth.js";
import { SecretManager } from "../src/secrets.js";

test("auth service issues and verifies scoped bearer token", async () => {
  const auth = new AuthService({ secret: "test-auth-secret" });
  const token = auth.issueToken({
    subject: "security@example.com",
    tenant_id: "tenant_contoso",
    roles: ["tenant_admin"]
  });
  const principal = await auth.verifyToken(token);

  assert.equal(principal.subject, "security@example.com");
  assert.deepEqual(principal.tenants, ["tenant_contoso"]);
  assert.equal(auth.authorize(principal, "policy:write", "tenant_contoso"), true);
  assert.throws(() => auth.authorize(principal, "policy:write", "tenant_other"), /Principal cannot access this tenant/);
});

test("secret manager stores encrypted references without returning plaintext", async () => {
  const rootDir = await fs.mkdtemp(path.join(os.tmpdir(), "scopezero-secrets-"));
  const secrets = new SecretManager({
    rootDir,
    masterKey: "a-long-test-master-key-for-aes-gcm",
    provider: "local"
  });

  const ref = await secrets.put({
    tenant_id: "tenant_contoso",
    name: "slack-token",
    value: "test-sensitive-token",
    created_by: "security@example.com"
  });

  assert.equal(ref.ref, "secret://tenant_contoso/slack-token");
  assert.equal(ref.value, undefined);

  const raw = await fs.readFile(path.join(rootDir, "data", "secrets.enc.json"), "utf8");
  assert.equal(raw.includes("test-sensitive-token"), false);
  assert.equal(await secrets.get(ref.ref, "tenant_contoso"), "test-sensitive-token");
});
