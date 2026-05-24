import { ScopeZeroClient } from "../sdk/scopezero-sdk.js";

const baseUrl = process.env.SCOPEZERO_URL || "http://127.0.0.1:8788";
const owner = process.env.SCOPEZERO_GITHUB_OWNER;
const repo = process.env.SCOPEZERO_GITHUB_REPO;

if (!process.env.SCOPEZERO_GITHUB_TOKEN || !owner || !repo) {
  throw new Error("Set SCOPEZERO_GITHUB_TOKEN, SCOPEZERO_GITHUB_OWNER, and SCOPEZERO_GITHUB_REPO before running this pilot.");
}

const client = new ScopeZeroClient({ baseUrl, apiKey: process.env.SCOPEZERO_API_KEY || "" });
const token = await client.devToken({
  tenant_id: "tenant_contoso",
  subject: "github-pilot@scopezero.local",
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

const agentId = `agent.github-pilot.${Date.now()}`;
await authed.registerAgent({
  tenant_id: "tenant_contoso",
  agent_id: agentId,
  name: "GitHub Pilot Agent",
  owner: "github-pilot@scopezero.local",
  allowed_tools: ["github.pr"]
});

const mission = await authed.createMission({
  tenant_id: "tenant_contoso",
  agent_id: agentId,
  delegated_by: "github-pilot@scopezero.local",
  objective: "Create one safe demo pull request in the ScopeZero GitHub sandbox repository.",
  allowed_tools: ["github.pr"],
  allowed_data_classes: ["public", "internal"],
  allowed_destinations: [`github.com/${owner}/${repo}`],
  action_contracts: [
    {
      id: "github.safe-demo-pr",
      tools: ["github.pr"],
      operations: ["write", "draft", "execute"],
      data_classes: ["public", "internal"],
      destinations: [`github.com/${owner}/${repo}`],
      max_delegation_depth: 0,
      effect: "allow"
    }
  ],
  runtime_risk_budget: 80,
  ttl_minutes: 30
});

const result = await authed.mcp({
  jsonrpc: "2.0",
  id: 1,
  method: "tools/call",
  params: {
    name: "github.pr",
    arguments: {
      tenant_id: "tenant_contoso",
      agent_id: agentId,
      mission_id: mission.capsule.id,
      action: "Create a safe GitHub demo pull request",
      operation: "write",
      payload: {
        classification: "internal",
        title: "ScopeZero governed demo change",
        body: "This draft pull request was created only after ScopeZero authorized the agent action.",
        files: [
          {
            path: "scopezero-demo.md",
            content: [
              "# ScopeZero GitHub Connector Demo",
              "",
              "This change was created by the ScopeZero GitHub connector.",
              "",
              "Before GitHub was called, ScopeZero checked:",
              "",
              "- agent identity",
              "- signed mission contract",
              "- tool allowlist",
              "- operation",
              "- data class",
              "- destination",
              "- prompt influence",
              "- risk budget",
              "",
              `Created at: ${new Date().toISOString()}`
            ].join("\n")
          }
        ]
      },
      destination: {
        type: "github",
        address: `github.com/${owner}/${repo}`,
        external: true
      },
      context: {
        mission_aligned: true
      }
    }
  }
});

const structured = result.result?.structuredContent || {};
if (result.result?.isError || structured.executed === false) {
  throw new Error(result.result?.content?.[0]?.text || structured.error || "GitHub pilot failed.");
}

console.log("ScopeZero GitHub connector pilot passed.");
console.log({
  decision: structured.scopezero_decision,
  repository: structured.repository,
  branch: structured.branch,
  pull_request_url: structured.pull_request_url,
  authorization_id: structured.scopezero_authorization_id,
  evidence_hash: structured.scopezero_evidence_hash
});
