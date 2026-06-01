// Pushes Slack Block Kit messages when actions need human approval
// Requires: SCOPEZERO_APPROVAL_SLACK_BOT_TOKEN, SCOPEZERO_APPROVAL_SLACK_CHANNEL_ID

const SLACK_POST = "https://slack.com/api/chat.postMessage";

export class ApprovalNotifier {
  constructor({ slackToken, channelId, gatewayBaseUrl, fetchImpl = globalThis.fetch }) {
    this.slackToken = slackToken;
    this.channelId = channelId;
    this.gatewayBaseUrl = (gatewayBaseUrl || "http://localhost:8788").replace(/\/$/, "");
    this.fetchImpl = fetchImpl;
    this.enabled = Boolean(slackToken && channelId);
  }

  async notify(approval) {
    if (!this.enabled) return null;

    const { id, agent_id, tool, action, mission_id, tenant_id, verdict } = approval;
    const riskScore = verdict?.risk_score || 0;
    const reasons = (verdict?.reasons || []).map((r) => `• ${r.message}`).join("\n") || "No details.";

    const blocks = [
      {
        type: "header",
        text: { type: "plain_text", text: "ScopeZero: Human Approval Required", emoji: true }
      },
      {
        type: "section",
        fields: [
          { type: "mrkdwn", text: `*Agent:*\n${agent_id}` },
          { type: "mrkdwn", text: `*Tool:*\n${tool}` },
          { type: "mrkdwn", text: `*Action:*\n${action}` },
          { type: "mrkdwn", text: `*Risk Score:*\n${riskScore}/100` },
          { type: "mrkdwn", text: `*Mission:*\n${mission_id}` },
          { type: "mrkdwn", text: `*Tenant:*\n${tenant_id}` }
        ]
      },
      {
        type: "section",
        text: { type: "mrkdwn", text: `*Why approval is required:*\n${reasons}` }
      },
      {
        type: "actions",
        block_id: `approval_${id}`,
        elements: [
          {
            type: "button",
            text: { type: "plain_text", text: "Approve", emoji: true },
            style: "primary",
            action_id: `approve_${id}`,
            value: id,
            confirm: {
              title: { type: "plain_text", text: "Approve this action?" },
              text: { type: "mrkdwn", text: `Allow *${agent_id}* to call *${tool}* — ${action}?` },
              confirm: { type: "plain_text", text: "Approve" },
              deny: { type: "plain_text", text: "Cancel" }
            }
          },
          {
            type: "button",
            text: { type: "plain_text", text: "Deny", emoji: true },
            style: "danger",
            action_id: `deny_${id}`,
            value: id
          }
        ]
      },
      {
        type: "context",
        elements: [
          { type: "mrkdwn", text: `Approval ID: \`${id}\` | <${this.gatewayBaseUrl}|ScopeZero Gateway>` }
        ]
      }
    ];

    try {
      const res = await this.fetchImpl(SLACK_POST, {
        method: "POST",
        headers: {
          authorization: `Bearer ${this.slackToken}`,
          "content-type": "application/json; charset=utf-8",
          "user-agent": "scopezero-gateway"
        },
        body: JSON.stringify({
          channel: this.channelId,
          blocks,
          text: `Approval required: ${agent_id} wants to call ${tool} — ${action}`
        })
      });
      const payload = await res.json();
      if (!res.ok || !payload.ok) {
        console.error(`[scopezero] Approval notification failed: ${payload.error || res.status}`);
        return null;
      }
      return { ts: payload.ts, channel: payload.channel };
    } catch (error) {
      console.error(`[scopezero] Approval notification error: ${error.message}`);
      return null;
    }
  }
}

export function createApprovalNotifierFromEnv(env, fetchImpl = globalThis.fetch) {
  return new ApprovalNotifier({
    slackToken: env.SCOPEZERO_APPROVAL_SLACK_BOT_TOKEN || "",
    channelId: env.SCOPEZERO_APPROVAL_SLACK_CHANNEL_ID || "",
    gatewayBaseUrl: env.SCOPEZERO_PUBLIC_BASE_URL || "http://localhost:8788",
    fetchImpl
  });
}
