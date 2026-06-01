import test from "node:test";
import assert from "node:assert/strict";
import { authorizeAndExecute } from "../sdk/guard-core.js";

const identity = { tenantId: "tenant_contoso", agentId: "agent.x", missionId: "mission_1" };

function fakeSz(decision, extra = {}) {
  return {
    async authorizeAction() {
      return { decision, authorization_id: "authz_1", verdict: { decision, reasons: [{ message: `reason for ${decision}` }], ...extra } };
    }
  };
}

test("allow executes the handler with the payload", async () => {
  let ran = false;
  const out = await authorizeAndExecute({
    ...identity, sz: fakeSz("allow"), tool: "drive.read", action: "a",
    payload: { q: "x" }, handler: async (args) => { ran = true; return { ok: true, args }; }
  });
  assert.equal(out.executed, true);
  assert.equal(ran, true);
  assert.deepEqual(out.result, { ok: true, args: { q: "x" } });
});

test("block never executes the handler", async () => {
  let ran = false;
  const out = await authorizeAndExecute({
    ...identity, sz: fakeSz("block"), tool: "gmail.send", action: "a",
    payload: {}, handler: async () => { ran = true; }
  });
  assert.equal(out.executed, false);
  assert.equal(ran, false);
  assert.equal(out.result.scopezero_blocked, true);
});

test("approval does not execute (awaits a human)", async () => {
  let ran = false;
  const out = await authorizeAndExecute({
    ...identity, sz: fakeSz("approval"), tool: "gmail.send", action: "a",
    payload: {}, handler: async () => { ran = true; }
  });
  assert.equal(out.executed, false);
  assert.equal(ran, false);
});

test("redact WITHOUT a redactor refuses to execute on the raw payload", async () => {
  let ran = false;
  const out = await authorizeAndExecute({
    ...identity, sz: fakeSz("redact"), tool: "slack.draft", action: "a",
    payload: { secret: "ssn 123" }, handler: async () => { ran = true; }
  });
  assert.equal(out.executed, false);
  assert.equal(ran, false);
  assert.match(out.result.reason, /Redaction required/);
});

test("redact WITH a redactor executes on the redacted payload", async () => {
  let received = null;
  const out = await authorizeAndExecute({
    ...identity, sz: fakeSz("redact"), tool: "slack.draft", action: "a",
    payload: { body: "ssn 123-45-6789" },
    redactor: (p) => ({ ...p, body: p.body.replace(/\d/g, "#") }),
    handler: async (args) => { received = args; return "sent"; }
  });
  assert.equal(out.executed, true);
  assert.equal(out.redacted, true);
  assert.equal(received.body, "ssn ###-##-####", "handler must receive the redacted payload, not the raw one");
});

test("gateway error fails closed — denies, never executes", async () => {
  let ran = false;
  const throwingSz = { async authorizeAction() { throw new Error("ECONNREFUSED"); } };
  const out = await authorizeAndExecute({
    ...identity, sz: throwingSz, tool: "gmail.send", action: "a",
    payload: {}, handler: async () => { ran = true; }
  });
  assert.equal(out.executed, false);
  assert.equal(ran, false);
  assert.equal(out.decision, "error");
  assert.equal(out.result.scopezero_blocked, true);
});

test("missing handler reports cleanly without executing anything else", async () => {
  const out = await authorizeAndExecute({
    ...identity, sz: fakeSz("allow"), tool: "unknown.tool", action: "a", payload: {}, handler: undefined
  });
  assert.equal(out.executed, true);
  assert.match(out.result.error, /No handler registered/);
});
