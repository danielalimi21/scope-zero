import { ScopeZeroClient } from "../sdk/scopezero-sdk.js";

const baseUrl = process.env.SCOPEZERO_URL || "http://127.0.0.1:8788";
const client = new ScopeZeroClient({ baseUrl, apiKey: process.env.SCOPEZERO_API_KEY || "" });

const health = await client.health();
assert(health.status === "ok", "health check failed");

const token = await client.devToken({
  tenant_id: "tenant_contoso",
  subject: "security@contoso.example",
  roles: ["tenant_admin"]
});
assert(token.access_token, "dev token was not issued");

const authed = new ScopeZeroClient({ baseUrl });
authed.apiKey = "";
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

const connectors = await authed.connectors();
assert(connectors.connectors.some((connector) => connector.name === "slack.draft"), "connector registry missing slack.draft");

const policyVersions = await authed.request("GET", "/v1/policy/versions?tenant_id=tenant_contoso");
assert(Array.isArray(policyVersions.versions), "policy versions endpoint missing versions array");

const proposal = await authed.request("POST", "/v1/policy/proposals", {
  tenant_id: "tenant_contoso",
  policy: {
    runtime_risk_budget: 95
  }
});
assert(proposal.proposal?.status === "pending_approval", "policy proposal was not created");

const reviewedPolicy = await authed.request("POST", `/v1/policy/proposals/${proposal.proposal.id}/approve`, {
  tenant_id: "tenant_contoso"
});
assert(reviewedPolicy.proposal?.status === "active", "policy proposal was not approved");

await authed.registerAgent({
  tenant_id: "tenant_contoso",
  agent_id: "agent.smoke.001",
  name: "Smoke Test Agent",
  owner: "security@contoso.example",
  allowed_tools: ["slack.draft"]
});

const mission = await authed.createMission({
  tenant_id: "tenant_contoso",
  agent_id: "agent.smoke.001",
  delegated_by: "security@contoso.example",
  objective: "Draft a safe internal security summary.",
  allowed_tools: ["slack.draft"],
  // The mission's approved Slack channel must be in the contract (allowed_destinations)
  // AND declared a public sink — external egress is sealed to review by default, so a
  // mission both contracts the destination and opts that lane out of the seal.
  allowed_destinations: ["security-team"],
  public_egress_destinations: ["security-team"],
  ttl_minutes: 15
});

const mcpList = await authed.mcp({
  jsonrpc: "2.0",
  id: 1,
  method: "tools/list",
  params: {}
});
assert(mcpList.result.tools.length > 0, "MCP tools/list returned no tools");

const mcpCall = await authed.mcp({
  jsonrpc: "2.0",
  id: 2,
  method: "tools/call",
  params: {
    name: "slack.draft",
    arguments: {
      tenant_id: "tenant_contoso",
      agent_id: "agent.smoke.001",
      mission_id: mission.capsule.id,
      action: "Draft safe summary",
      payload: {
        classification: "internal",
        body: "Security summary with no sensitive fields."
      },
      destination: {
        type: "slack",
        external: false,
        address: "security-team"
      },
      context: {
        mission_aligned: true
      }
    }
  }
});
assert(mcpCall.result.structuredContent.scopezero_decision === "allow", "MCP tool call was not allowed");
assert(mcpCall.result.structuredContent.scopezero_authorization_id, "MCP response missing authorization id");

const authorization = await authed.authorizeAction({
  tenant_id: "tenant_contoso",
  agent_id: "agent.smoke.001",
  mission_id: mission.capsule.id,
  tool: "slack.draft",
  action: "Draft another safe summary",
  operation: "draft",
  payload: {
    classification: "internal",
    body: "Second summary with no sensitive fields."
  },
  destination: {
    type: "slack",
    external: false,
    address: "security-team"
  },
  context: {
    mission_aligned: true
  }
});
assert(authorization.authorization_id, "action authorization endpoint missing authorization id");
assert(authorization.verdict.matched_contract_id, "action was not tied to a mission contract");

const siem = await authed.siemEvents({ format: "json", limit: 10 });
assert(Array.isArray(siem.events), "SIEM JSON export missing events array");

console.log("ScopeZero enterprise smoke test passed.");
console.log({
  health: health.status,
  token: Boolean(token.access_token),
  connectors: connectors.connectors.length,
  policyVersion: reviewedPolicy.proposal.version,
  mcpDecision: mcpCall.result.structuredContent.scopezero_decision,
  actionAuthorization: authorization.decision,
  siemEvents: siem.events.length
});

function assert(condition, message) {
  if (!condition) {
    throw new Error(message);
  }
}
