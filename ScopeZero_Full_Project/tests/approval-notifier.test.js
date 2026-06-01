import test from "node:test";
import assert from "node:assert/strict";
import { ApprovalNotifier } from "../src/approvalNotifier.js";

test("approval notifier is disabled when no token is configured", async () => {
  const notifier = new ApprovalNotifier({ slackToken: "", channelId: "", gatewayBaseUrl: "" });
  assert.equal(notifier.enabled, false);
  const result = await notifier.notify({ id: "approval_1", agent_id: "agent.test", tool: "gmail.send", action: "send", mission_id: "m1", tenant_id: "t1", verdict: {} });
  assert.equal(result, null);
});

test("approval notifier posts Block Kit message to Slack", async () => {
  const calls = [];
  const notifier = new ApprovalNotifier({
    slackToken: "xoxb-test-token",
    channelId: "C_APPROVALS",
    gatewayBaseUrl: "http://localhost:8788",
    fetchImpl: async (url, options) => {
      calls.push({ url, body: JSON.parse(options.body) });
      return {
        ok: true,
        async json() { return { ok: true, ts: "1779193000.000200", channel: "C_APPROVALS" }; }
      };
    }
  });

  const result = await notifier.notify({
    id: "approval_abc123",
    agent_id: "agent.diligence",
    tool: "gmail.send",
    action: "Send external summary",
    mission_id: "mission_q3",
    tenant_id: "tenant_contoso",
    verdict: {
      risk_score: 62,
      reasons: [
        { code: "high-impact-action", message: "Action type external_send requires human approval." }
      ]
    }
  });

  assert.equal(result.ts, "1779193000.000200");
  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, "https://slack.com/api/chat.postMessage");
  assert.equal(calls[0].body.channel, "C_APPROVALS");
  assert.ok(Array.isArray(calls[0].body.blocks));

  const actionBlock = calls[0].body.blocks.find((b) => b.type === "actions");
  assert.ok(actionBlock, "Block Kit message should contain an actions block");
  assert.ok(actionBlock.elements.some((e) => e.action_id === "approve_approval_abc123"), "Approve button should reference approval id");
  assert.ok(actionBlock.elements.some((e) => e.action_id === "deny_approval_abc123"), "Deny button should reference approval id");
});

test("approval notifier handles Slack API errors gracefully", async () => {
  const notifier = new ApprovalNotifier({
    slackToken: "xoxb-test-token",
    channelId: "C_APPROVALS",
    gatewayBaseUrl: "http://localhost:8788",
    fetchImpl: async () => ({
      ok: false,
      async json() { return { ok: false, error: "channel_not_found" }; }
    })
  });

  const result = await notifier.notify({
    id: "approval_xyz",
    agent_id: "agent.test",
    tool: "drive.read",
    action: "Read file",
    mission_id: "mission_1",
    tenant_id: "tenant_1",
    verdict: { risk_score: 30, reasons: [] }
  });

  assert.equal(result, null);
});
