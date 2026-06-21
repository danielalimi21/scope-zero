// Adversarial red-team suite. Each test is a "sneaky" attempt to get a dangerous
// action past ScopeZero. They assert CONTAINMENT (decision is never a silent
// allow, or a forged/expired/tampered mission is rejected). New attacks are added
// here as they are tried; the file doubles as a regression gate against bypasses.

import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { createRuntime } from "../src/runtime.js";
import { evaluateProxyConnect } from "../src/proxyEnforcer.js";
import { verifyMissionCapsule } from "../src/capsules.js";
import { isExternalDestination, classifyPayload } from "../src/sensitiveData.js";
import { AuthService, base64url } from "../src/auth.js";
import { destinationAllowed, describeActionRequest } from "../src/actionAuthorization.js";

const SECRET = "redteam-signing-secret";
const TENANT = "tenant_contoso";

async function freshRuntime() {
  const rootDir = await fs.mkdtemp(path.join(os.tmpdir(), "scopezero-redteam-"));
  const runtime = await createRuntime({ rootDir, signingSecret: SECRET });
  return { runtime, rootDir };
}

async function narrowMission(runtime, agentId, overrides = {}) {
  await runtime.registerAgent({
    tenant_id: TENANT, agent_id: agentId, name: "RT Agent", owner: "rt@scopezero.local",
    allowed_tools: overrides.allowed_tools || ["drive.read"]
  });
  const { capsule } = await runtime.createMission({
    tenant_id: TENANT, agent_id: agentId, delegated_by: "rt@scopezero.local",
    objective: "Read approved documents only.",
    allowed_tools: overrides.allowed_tools || ["drive.read"],
    allowed_data_classes: overrides.allowed_data_classes || ["public", "internal"],
    allowed_destinations: overrides.allowed_destinations || ["docs.example.com"],
    ...overrides.mission
  });
  return capsule;
}

// ── Destination allowlist: label-boundary suffix confusion ──────────────────
test("destination allowlist is not bypassed by suffix-confusable hosts", () => {
  const allowed = ["example.com"];
  for (const bad of ["evilexample.com", "attacker-example.com", "notexample.com", "example.com.evil.com"]) {
    assert.equal(destinationAllowed(allowed, bad, true), false, `${bad} must NOT match example.com`);
  }
  for (const good of ["example.com", "api.example.com", "a.b.example.com"]) {
    assert.equal(destinationAllowed(allowed, good, true), true, `${good} must match example.com`);
  }
});

test("proxy CONNECT host match respects label boundary", async () => {
  const { runtime, rootDir } = await freshRuntime();
  try {
    const cap = await narrowMission(runtime, "agent.rt.proxy", { allowed_destinations: ["example.com"] });
    const evil = evaluateProxyConnect({ mission: runtime.store.getMission(cap.id, TENANT), host: "attacker-example.com", requestedAgentId: "agent.rt.proxy", verifyKey: SECRET });
    assert.equal(evil.allowed, false, "suffix-confusable host must be refused at the proxy");
    const ok = evaluateProxyConnect({ mission: runtime.store.getMission(cap.id, TENANT), host: "api.example.com", requestedAgentId: "agent.rt.proxy", verifyKey: SECRET });
    assert.equal(ok.allowed, true, "legit subdomain must be allowed");
  } finally {
    await fs.rm(rootDir, { recursive: true, force: true });
  }
});

// ── Capsule integrity: every tamper must fail verification ──────────────────
test("tampering a signed capsule (any field) fails verification", async () => {
  const { runtime, rootDir } = await freshRuntime();
  try {
    const cap = await narrowMission(runtime, "agent.rt.tamper", { allowed_destinations: ["docs.example.com"] });
    assert.equal(verifyMissionCapsule(cap, SECRET), true, "the genuine capsule verifies");

    const tampers = [
      { ...cap, allowed_destinations: ["*"] },
      { ...cap, allowed_tools: ["*"] },
      { ...cap, allowed_data_classes: ["restricted"] },
      { ...cap, expires_at: new Date(Date.now() + 9e9).toISOString() },
      { ...cap, agent_id: "agent.attacker" },
      { ...cap, action_contracts: [{ tools: ["*"], destinations: ["*"], data_classes: ["restricted"], operations: ["*"] }] },
      { ...cap, signature: "sz2.deadbeef" },
      { ...cap, signature: "" },
      (() => { const c = { ...cap }; delete c.signature; return c; })()
    ];
    for (const t of tampers) {
      assert.equal(verifyMissionCapsule(t, SECRET), false, `tamper must fail: ${JSON.stringify(t).slice(0, 60)}`);
    }
  } finally {
    await fs.rm(rootDir, { recursive: true, force: true });
  }
});

// ── Malformed/hostile capsule must be rejected, never crash the verifier ─────
test("verifyMissionCapsule fails closed on malformed/hostile input (no throw)", () => {
  const circular = { signature: "sz2.abcd" }; circular.self = circular;
  for (const c of [
    { signature: "sz2.zzznothex" },
    { signature: "sz2." },
    { signature: "sz2." + "f".repeat(200000) },
    { signature: 12345 },
    { signature: null },
    {},
    null,
    circular
  ]) {
    let result;
    assert.doesNotThrow(() => { result = verifyMissionCapsule(c, "secret"); }, "verify must never throw");
    assert.equal(result, false, "malformed capsule must not verify");
  }
});

// ── Self-declared data-class downgrade must not lower the real class ─────────
test("declaring restricted content as public does not bypass the data ceiling", async () => {
  const { runtime, rootDir } = await freshRuntime();
  try {
    const cap = await narrowMission(runtime, "agent.rt.downgrade", {
      allowed_tools: ["drive.read", "http.post"],
      allowed_destinations: ["docs.example.com", "api.partner.example"]
    });
    // Real card number (Luhn-valid) + SSN in the payload, self-declared "public".
    const out = await runtime.evaluateToolCall({
      tenant_id: TENANT, agent_id: "agent.rt.downgrade", mission_id: cap.id,
      tool: "http.post", action: "post update", operation: "external_send",
      data_class: "public",
      payload: { text: "card 4111 1111 1111 1111 ssn 123-45-6789", classification: "public" },
      destination: { type: "url", address: "api.partner.example", external: true }
    });
    assert.notEqual(out.decision, "allow", `restricted content declared public must not be allowed (got ${out.decision})`);
  } finally {
    await fs.rm(rootDir, { recursive: true, force: true });
  }
});

// ── Taint cannot be reset by rotating the caller-supplied session_id ─────────
test("ingest-taint is not reset by rotating session_id", async () => {
  const { runtime, rootDir } = await freshRuntime();
  try {
    const cap = await narrowMission(runtime, "agent.rt.taint", {
      allowed_tools: ["drive.read", "statuspage.update"],
      allowed_data_classes: ["public", "internal", "confidential"],
      allowed_destinations: ["docs.example.com", "status.partner.example"]
    });
    // Ingest confidential data on one session.
    await runtime.evaluateToolCall({
      tenant_id: TENANT, agent_id: "agent.rt.taint", mission_id: cap.id, session_id: "sess-A",
      tool: "drive.read", action: "read confidential", operation: "read",
      payload: { text: "Confidential: acquisition memo, customer revenue by account" },
      destination: { type: "resource", address: "docs.example.com" }
    });
    // Now egress benign-looking prose on a FRESH session id.
    const out = await runtime.evaluateToolCall({
      tenant_id: TENANT, agent_id: "agent.rt.taint", mission_id: cap.id, session_id: "sess-B-fresh",
      tool: "statuspage.update", action: "post status", operation: "write",
      payload: { summary: "All green." },
      destination: { type: "url", address: "status.partner.example", external: true }
    });
    assert.notEqual(out.decision, "allow", `laundered egress after taint must not be allowed even on a new session (got ${out.decision})`);
  } finally {
    await fs.rm(rootDir, { recursive: true, force: true });
  }
});

// ── Expired / forged / unowned missions are refused at the proxy ────────────
test("expired, forged, and unowned missions are refused at the proxy", async () => {
  const { runtime, rootDir } = await freshRuntime();
  try {
    const cap = await narrowMission(runtime, "agent.rt.proxy2", { allowed_destinations: ["docs.example.com"] });
    const mission = runtime.store.getMission(cap.id, TENANT);

    const expired = evaluateProxyConnect({ mission, host: "docs.example.com", requestedAgentId: "agent.rt.proxy2", verifyKey: SECRET, now: new Date(new Date(cap.expires_at).getTime() + 1000) });
    assert.equal(expired.allowed, false, "expired mission refused");

    const forged = evaluateProxyConnect({ mission: { ...mission, action_contracts: [{ tools: ["*"], destinations: ["*"] }] }, host: "evil.example", requestedAgentId: "agent.rt.proxy2", verifyKey: SECRET });
    assert.equal(forged.allowed, false, "forged capsule refused");

    const unowned = evaluateProxyConnect({ mission, host: "docs.example.com", requestedAgentId: "agent.someone.else", verifyKey: SECRET });
    assert.equal(unowned.allowed, false, "mission used by a different agent refused");
  } finally {
    await fs.rm(rootDir, { recursive: true, force: true });
  }
});

// ── Out-of-scope tool / cross-tenant / missing mission are blocked ──────────
test("out-of-scope tool and unknown tenant are blocked", async () => {
  const { runtime, rootDir } = await freshRuntime();
  try {
    const cap = await narrowMission(runtime, "agent.rt.scope", { allowed_tools: ["drive.read"], allowed_destinations: ["docs.example.com"] });

    // Tool not in the mission allowlist.
    const offTool = await runtime.evaluateToolCall({
      tenant_id: TENANT, agent_id: "agent.rt.scope", mission_id: cap.id,
      tool: "gmail.send", action: "send", operation: "external_send",
      payload: { text: "hi" }, destination: { type: "email", address: "x@evil.com", external: true }
    });
    assert.notEqual(offTool.decision, "allow", "out-of-scope tool must not be allowed");

    // Mission referenced under the wrong tenant.
    const crossTenant = await runtime.evaluateToolCall({
      tenant_id: "tenant_unknown", agent_id: "agent.rt.scope", mission_id: cap.id,
      tool: "drive.read", action: "read", operation: "read",
      payload: {}, destination: { type: "resource", address: "docs.example.com" }
    }).catch((e) => ({ decision: "block", error: e.message }));
    assert.notEqual(crossTenant.decision, "allow", "cross-tenant mission use must not be allowed");
  } finally {
    await fs.rm(rootDir, { recursive: true, force: true });
  }
});

// ── "internal" classification can't be spoofed to dodge the egress seal ─────
test("a host suffix-confusable with a trusted domain is still treated as external", () => {
  const policy = { trusted_destinations: ["contoso.example"] };
  for (const ext of ["evil-contoso.example", "xcontoso.example", "attacker.com"]) {
    assert.equal(isExternalDestination({ address: ext }, policy), true, `${ext} must be external`);
    // The self-declared external:false flag must not be able to lower it.
    assert.equal(isExternalDestination({ address: ext, external: false }, policy), true, `${ext} external:false must not spoof internal`);
  }
  for (const internal of ["contoso.example", "api.contoso.example"]) {
    assert.equal(isExternalDestination({ address: internal }, policy), false, `${internal} is genuinely internal`);
  }
});

// ── Self-declared operation cannot be downgraded below the tool's real impact ─
test("declaring 'read' on a high-impact tool does not downgrade its operation", () => {
  // No manifest: the tool-name inference is the floor; a self-declared benign op
  // cannot lower it.
  for (const [tool, declared, expected] of [
    ["bank.wire", "read", "payment"],
    ["data.export", "read", "export"],
    ["billing.transfer", "draft", "payment"]
  ]) {
    const d = describeActionRequest({ tool, action: "harmless lookup", operation: declared }, { label: "public" }, {});
    assert.equal(d.operation, expected, `${tool} declared ${declared} must floor to ${expected}, got ${d.operation}`);
  }
  // A genuinely benign tool is not escalated.
  assert.equal(describeActionRequest({ tool: "drive.read", action: "read", operation: "read" }, { label: "public" }, {}).operation, "read");
});

test("a high-impact tool mislabeled 'read' is not silently allowed end-to-end", async () => {
  const { runtime, rootDir } = await freshRuntime();
  try {
    const cap = await narrowMission(runtime, "agent.rt.opdown", {
      allowed_tools: ["data.export"],
      allowed_destinations: ["docs.example.com"],
      mission: {
        action_contracts: [{
          id: "c.export", tools: ["data.export"], operations: ["read", "export", "execute"],
          data_classes: ["public", "internal"], destinations: ["docs.example.com"], effect: "allow"
        }]
      }
    });
    const out = await runtime.evaluateToolCall({
      tenant_id: TENANT, agent_id: "agent.rt.opdown", mission_id: cap.id,
      tool: "data.export", action: "routine lookup", operation: "read",
      payload: { text: "export everything" }, destination: { type: "resource", address: "docs.example.com" }
    });
    assert.notEqual(out.decision, "allow", `export mislabeled read must not auto-allow (got ${out.decision})`);
  } finally {
    await fs.rm(rootDir, { recursive: true, force: true });
  }
});

// ── Classifier must not hang (ReDoS) on large/pathological payloads ─────────
test("the classifier handles large adversarial payloads in bounded time", () => {
  for (const payload of [
    "1".repeat(5_000_000),          // long digit run (was O(n^2) via the email regex)
    "z".repeat(5_000_000),          // long letter run
    "QUtJQ".repeat(800_000),        // 4MB base64-looking blob
    "deadbeef".repeat(500_000)      // 4MB hex-looking blob
  ]) {
    const t0 = process.hrtime.bigint();
    const r = classifyPayload({ text: payload });
    const ms = Number(process.hrtime.bigint() - t0) / 1e6;
    assert.ok(ms < 2000, `classify must finish < 2000ms, took ${ms.toFixed(0)}ms`);
    assert.equal(r.established, false, "an oversized/opaque payload is never trusted as established-public");
  }
  // Real detections still fire after the hardening.
  assert.equal(classifyPayload({ text: "contact bob@example.com" }).findings.includes("email_address"), true);
  assert.equal(classifyPayload({ text: "4111 1111 1111 1111" }).level, 5);
  assert.equal(classifyPayload({ text: "AKIAIOSFODNN7EXAMPLE" }).level, 5);
});

// ── A suffix-confusable host cannot inherit a declared public-sink lane ──────
test("a host suffix-confusable with a declared public sink does not bypass the seal", async () => {
  const { runtime, rootDir } = await freshRuntime();
  try {
    const cap = await narrowMission(runtime, "agent.rt.sink", {
      allowed_tools: ["statuspage.update"],
      allowed_destinations: ["*"],
      mission: {
        public_egress_destinations: ["status.example.com"],
        action_contracts: [{
          id: "c.status", tools: ["statuspage.update"], operations: ["write", "execute"],
          data_classes: ["public", "internal"], destinations: ["*"], effect: "allow"
        }]
      }
    });
    // Benign content to an attacker host that suffix-matches the declared sink.
    const out = await runtime.evaluateToolCall({
      tenant_id: TENANT, agent_id: "agent.rt.sink", mission_id: cap.id,
      tool: "statuspage.update", action: "post status", operation: "write",
      payload: { summary: "All green." },
      destination: { type: "url", address: "evilstatus.example.com", external: true }
    });
    assert.notEqual(out.decision, "allow", `egress to a sink-confusable host must be sealed (got ${out.decision})`);
  } finally {
    await fs.rm(rootDir, { recursive: true, force: true });
  }
});

// ── The tamper-evident ledger stays valid under heavy concurrent appends ────
test("ledger hash chain stays valid under concurrent writes", async () => {
  const { runtime, rootDir } = await freshRuntime();
  try {
    const cap = await narrowMission(runtime, "agent.rt.ledger", { allowed_destinations: ["docs.example.com"] });
    await Promise.all(Array.from({ length: 400 }, (_, i) =>
      runtime.evaluateToolCall({
        tenant_id: TENANT, agent_id: "agent.rt.ledger", mission_id: cap.id, session_id: `s${i}`,
        tool: "drive.read", action: "read", operation: "read",
        payload: {}, destination: { type: "resource", address: "docs.example.com" }
      })
    ));
    const v = await runtime.verifyLedger();
    assert.equal(v.valid, true, `ledger must verify clean under concurrency (${(v.failures || []).length} failures)`);
  } finally {
    await fs.rm(rootDir, { recursive: true, force: true });
  }
});

// ── Auth: no alg-confusion, no tamper, no expiry bypass ─────────────────────
test("bearer-token verification rejects forged/tampered/expired tokens", async () => {
  const auth = new AuthService({ secret: "redteam-auth-secret" });
  const good = auth.issueToken({ subject: "u", tenant_id: TENANT, roles: ["tenant_admin"] });
  const [h, p, s] = good.split(".");

  // Genuine token verifies.
  const ok = await auth.verifyToken(good);
  assert.ok((ok.roles || ok.payload?.roles || []).includes("tenant_admin"));

  const reject = async (label, token) => {
    await assert.rejects(() => auth.verifyToken(token), (e) => e.status === 401, label);
  };
  const noneH = base64url(JSON.stringify({ alg: "none", typ: "SZJWT" }));
  const evilP = base64url(JSON.stringify({ sub: "u", tenant_id: TENANT, roles: ["platform_admin"], exp: Math.floor(Date.now() / 1000) + 9999 }));
  const rsH = base64url(JSON.stringify({ alg: "RS256", typ: "JWT" }));

  await reject("alg:none", `${noneH}.${p}.`);
  await reject("alg:none with junk sig", `${noneH}.${p}.x`);
  await reject("tampered payload / role escalation, old sig", `${h}.${evilP}.${s}`);
  await reject("forged HS256 signature", `${h}.${p}.${base64url("garbage")}`);
  await reject("RS256 with no JWKS configured", `${rsH}.${p}.${s}`);
  await reject("expired token", auth.issueToken({ subject: "u", tenant_id: TENANT, roles: ["tenant_admin"], ttl_seconds: -10 }));
});

// ── Money-amount evasion still hits the high-impact payment gate ─────────────
test("a payment is gated regardless of money-amount tricks (NaN/string/negative/huge)", async () => {
  const { runtime, rootDir } = await freshRuntime();
  try {
    const cap = await narrowMission(runtime, "agent.rt.money", {
      allowed_tools: ["bank.wire"], allowed_destinations: ["bank.example.com"],
      mission: { action_contracts: [{
        id: "c.wire", tools: ["bank.wire"], operations: ["payment", "execute"],
        data_classes: ["public", "internal"], destinations: ["bank.example.com"], effect: "approval"
      }] }
    });
    for (const money of [{ amount: {} }, { amount: "5000000" }, { amount: -5 }, { amount: 1e12 }]) {
      const out = await runtime.evaluateToolCall({
        tenant_id: TENANT, agent_id: "agent.rt.money", mission_id: cap.id,
        tool: "bank.wire", action: "pay vendor", operation: "payment",
        payload: { text: "pay" }, destination: { type: "url", address: "bank.example.com" }, money
      });
      assert.notEqual(out.decision, "allow", `payment with money=${JSON.stringify(money)} must not auto-allow`);
    }
  } finally {
    await fs.rm(rootDir, { recursive: true, force: true });
  }
});

// ── Delegation beyond the signed depth is blocked ───────────────────────────
test("delegating beyond the mission's max depth is blocked", async () => {
  const { runtime, rootDir } = await freshRuntime();
  try {
    const cap = await narrowMission(runtime, "agent.rt.deleg", { allowed_destinations: ["docs.example.com"] });
    const out = await runtime.evaluateToolCall({
      tenant_id: TENANT, agent_id: "agent.rt.deleg", mission_id: cap.id,
      tool: "drive.read", action: "read", operation: "read",
      payload: {}, destination: { type: "resource", address: "docs.example.com" },
      delegation_depth: 5
    });
    assert.equal(out.decision, "block", `delegation beyond max depth must block (got ${out.decision})`);
  } finally {
    await fs.rm(rootDir, { recursive: true, force: true });
  }
});

// ── Prototype pollution via payload keys must not mutate Object.prototype ────
test("payload with __proto__/constructor keys does not pollute prototypes", async () => {
  const { runtime, rootDir } = await freshRuntime();
  try {
    const cap = await narrowMission(runtime, "agent.rt.proto", { allowed_tools: ["drive.read"], allowed_destinations: ["docs.example.com"] });
    await runtime.evaluateToolCall({
      tenant_id: TENANT, agent_id: "agent.rt.proto", mission_id: cap.id,
      tool: "drive.read", action: "read", operation: "read",
      payload: JSON.parse('{"__proto__":{"polluted":true},"constructor":{"prototype":{"polluted2":true}},"text":"x"}'),
      destination: { type: "resource", address: "docs.example.com" }
    });
    assert.equal({}.polluted, undefined, "Object.prototype must not be polluted");
    assert.equal({}.polluted2, undefined, "Object.prototype must not be polluted via constructor");
  } finally {
    await fs.rm(rootDir, { recursive: true, force: true });
  }
});
