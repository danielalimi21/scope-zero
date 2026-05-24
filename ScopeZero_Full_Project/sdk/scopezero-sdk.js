export class ScopeZeroClient {
  constructor({ baseUrl = "http://localhost:8788", apiKey = "" } = {}) {
    this.baseUrl = baseUrl.replace(/\/$/, "");
    this.apiKey = apiKey;
  }

  health() {
    return this.request("GET", "/v1/health");
  }

  state() {
    return this.request("GET", "/v1/state");
  }

  devToken({ tenant_id = "tenant_contoso", subject = "developer@scopezero.local", roles = ["tenant_admin"] } = {}) {
    return this.request("POST", "/v1/auth/dev-token", { tenant_id, subject, roles });
  }

  connectors() {
    return this.request("GET", "/v1/connectors");
  }

  siemEvents({ format = "json", limit = 100 } = {}) {
    return this.request("GET", `/v1/siem/events?format=${encodeURIComponent(format)}&limit=${encodeURIComponent(limit)}`);
  }

  mcp(message) {
    return this.request("POST", "/mcp", message);
  }

  registerAgent(agent) {
    return this.request("POST", "/v1/agents", agent);
  }

  createMission(mission) {
    return this.request("POST", "/v1/missions", mission);
  }

  requestToolCall(toolCall) {
    return this.request("POST", "/v1/tool-calls", toolCall);
  }

  authorizeAction(actionRequest) {
    return this.request("POST", "/v1/action-authorizations", actionRequest);
  }

  approve(approvalId, actor) {
    return this.request("POST", `/v1/approvals/${approvalId}/approve`, { actor });
  }

  deny(approvalId, actor) {
    return this.request("POST", `/v1/approvals/${approvalId}/deny`, { actor });
  }

  async request(method, path, body) {
    const headers = {
      "content-type": "application/json"
    };
    if (this.apiKey) {
      headers.authorization = `Bearer ${this.apiKey}`;
    }

    const response = await fetch(`${this.baseUrl}${path}`, {
      method,
      headers,
      body: body ? JSON.stringify(body) : undefined
    });
    const payload = response.status === 204 ? null : await response.json();
    if (!response.ok) {
      const error = new Error(payload?.error?.message || `ScopeZero request failed with ${response.status}`);
      error.status = response.status;
      error.payload = payload;
      throw error;
    }
    return payload;
  }
}
