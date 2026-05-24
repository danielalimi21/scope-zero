import { ScopeZeroClient } from "../sdk/scopezero-sdk.js";

const baseUrl = process.env.SCOPEZERO_URL || "http://127.0.0.1:8788";
const client = new ScopeZeroClient({ baseUrl, apiKey: process.env.SCOPEZERO_API_KEY || "" });

const token = await client.devToken({
  tenant_id: "tenant_contoso",
  subject: "aws-pilot@scopezero.local",
  roles: ["tenant_admin"]
});

const authed = new ScopeZeroClient({ baseUrl });
authed.request = async function requestWithBearer(method, path, body) {
  const response = await fetch(`${this.baseUrl}${path}`, {
    method,
    headers: {
      "content-type": "application/json",
      authorization: `Bearer ${token.access_token}`
    },
    body: body ? JSON.stringify(body) : undefined
  });
  const payload = response.status === 204 ? null : await response.json();
  if (!response.ok) {
    throw new Error(payload?.error?.message || `Request failed: ${response.status}`);
  }
  return payload;
};

const agentId = `agent.aws-pilot.${Date.now()}`;
await authed.registerAgent({
  tenant_id: "tenant_contoso",
  agent_id: agentId,
  name: "AWS IAM Pilot Agent",
  owner: "aws-pilot@scopezero.local",
  allowed_tools: ["aws.iam.attachPolicy"]
});

const mission = await authed.createMission({
  tenant_id: "tenant_contoso",
  agent_id: agentId,
  delegated_by: "aws-pilot@scopezero.local",
  objective: "Inspect AWS IAM posture and prepare read-only remediation notes. Do not modify roles or attach policies.",
  allowed_tools: ["aws.iam.attachPolicy"],
  allowed_data_classes: ["public", "internal"],
  allowed_destinations: ["iam.amazonaws.com"],
  action_contracts: [
    {
      id: "aws.readonly-remediation-notes",
      tools: ["aws.iam.attachPolicy"],
      operations: ["read", "execute"],
      data_classes: ["public", "internal"],
      destinations: ["iam.amazonaws.com"],
      max_delegation_depth: 0,
      effect: "approval"
    }
  ],
  runtime_risk_budget: 80,
  ttl_minutes: 30
});

const blocked = await authed.mcp({
  jsonrpc: "2.0",
  id: 1,
  method: "tools/call",
  params: {
    name: "aws.iam.attachPolicy",
    arguments: {
      tenant_id: "tenant_contoso",
      agent_id: agentId,
      mission_id: mission.capsule.id,
      action: "Attach AdministratorAccess to the agent execution role",
      operation: "privilege_change",
      payload: {
        classification: "internal",
        account_id: "123456789012",
        role_name: "scopezero-agent-execution-role",
        policy_name: "AdministratorAccess",
        policy_arn: "arn:aws:iam::aws:policy/AdministratorAccess"
      },
      destination: {
        type: "aws",
        address: "iam.amazonaws.com",
        external: true
      },
      privilege: {
        admin: true
      },
      context: {
        mission_aligned: false
      }
    }
  }
});

const blockedStructured = blocked.result?.structuredContent || {};
if (!blocked.result?.isError || blockedStructured.decision !== "block") {
  throw new Error("Expected ScopeZero to block the AWS IAM admin policy attachment before execution.");
}

const reviewAgentId = `agent.aws-review.${Date.now()}`;
await authed.registerAgent({
  tenant_id: "tenant_contoso",
  agent_id: reviewAgentId,
  name: "AWS IAM Review Agent",
  owner: "aws-pilot@scopezero.local",
  allowed_tools: ["aws.iam.attachPolicy"]
});

const approvalMission = await authed.createMission({
  tenant_id: "tenant_contoso",
  agent_id: reviewAgentId,
  delegated_by: "aws-pilot@scopezero.local",
  objective: "Prepare an AWS IAM policy attachment request for human review only.",
  allowed_tools: ["aws.iam.attachPolicy"],
  allowed_data_classes: ["public", "internal"],
  allowed_destinations: ["iam.amazonaws.com"],
  action_contracts: [
    {
      id: "aws.policy-change-review",
      tools: ["aws.iam.attachPolicy"],
      operations: ["privilege_change", "execute"],
      data_classes: ["public", "internal"],
      destinations: ["iam.amazonaws.com"],
      max_delegation_depth: 0,
      effect: "approval"
    }
  ],
  runtime_risk_budget: 80,
  ttl_minutes: 30
});

const approval = await authed.mcp({
  jsonrpc: "2.0",
  id: 2,
  method: "tools/call",
  params: {
    name: "aws.iam.attachPolicy",
    arguments: {
      tenant_id: "tenant_contoso",
      agent_id: reviewAgentId,
      mission_id: approvalMission.capsule.id,
      action: "Prepare PowerUserAccess attachment request for security review",
      operation: "privilege_change",
      payload: {
        classification: "internal",
        account_id: "123456789012",
        role_name: "scopezero-readonly-remediation-role",
        policy_name: "PowerUserAccess",
        policy_arn: "arn:aws:iam::aws:policy/PowerUserAccess"
      },
      destination: {
        type: "aws",
        address: "iam.amazonaws.com",
        external: true
      },
      privilege: {
        admin: false
      },
      context: {
        mission_aligned: true
      }
    }
  }
});

const approvalStructured = approval.result?.structuredContent || {};
if (!approval.result?.isError || approvalStructured.decision !== "approval") {
  throw new Error("Expected ScopeZero to route the AWS IAM policy change to approval.");
}

console.log("ScopeZero AWS IAM pilot passed.");
console.log({
  blocked_decision: blockedStructured.decision,
  blocked_required_action: blockedStructured.verdict?.required_action,
  blocked_reasons: blockedStructured.verdict?.reasons?.map((reason) => reason.code),
  blocked_evidence_hash: blockedStructured.evidence_hash,
  approval_decision: approvalStructured.decision,
  approval_required_action: approvalStructured.verdict?.required_action,
  approval_id: approvalStructured.approval_id,
  approval_evidence_hash: approvalStructured.evidence_hash,
  aws_mutation_performed: false
});
