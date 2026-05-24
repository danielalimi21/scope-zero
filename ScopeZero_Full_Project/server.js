import http from "node:http";
import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { AuthService, auditPrincipal } from "./src/auth.js";
import { ConnectorRegistry } from "./src/connectors.js";
import { handleMcpRequest } from "./src/mcp.js";
import { OAuthBroker } from "./src/oauth.js";
import { createRuntime } from "./src/runtime.js";
import { SecretManager } from "./src/secrets.js";
import { contentTypeForSiem, exportEvents } from "./src/siem.js";
import { Telemetry } from "./src/telemetry.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const portArg = process.argv.find((arg) => arg.startsWith("--port="));
const PORT = Number(process.env.PORT || portArg?.split("=")[1] || 8788);
const SIGNING_SECRET = process.env.SCOPEZERO_SIGNING_SECRET || "dev-scopezero-signing-secret-change-me";
const API_KEY = process.env.SCOPEZERO_API_KEY || "";
const AUTH_SECRET = process.env.SCOPEZERO_AUTH_SECRET || SIGNING_SECRET;
const REQUIRE_AUTH = process.env.SCOPEZERO_REQUIRE_AUTH === "true";
const ALLOW_DEV_TOKEN = process.env.SCOPEZERO_ALLOW_DEV_TOKEN !== "false";
const CORS_ORIGIN = process.env.SCOPEZERO_CORS_ORIGIN || "*";
const OIDC_ISSUER = process.env.SCOPEZERO_OIDC_ISSUER || "";
const OIDC_AUDIENCE = process.env.SCOPEZERO_OIDC_AUDIENCE || "";
const OIDC_JWKS_URL = process.env.SCOPEZERO_OIDC_JWKS_URL || "";
const RATE_LIMIT_PER_MINUTE = Number(process.env.SCOPEZERO_RATE_LIMIT_PER_MINUTE || 600);
const PUBLIC_BASE_URL = process.env.SCOPEZERO_PUBLIC_BASE_URL || `http://localhost:${PORT}`;
const STORE_PROVIDER = process.env.SCOPEZERO_STORE || "sqlite";
const OTEL_EXPORTER_OTLP_ENDPOINT = process.env.OTEL_EXPORTER_OTLP_ENDPOINT || "";
const SECRETS_PROVIDER = process.env.SCOPEZERO_SECRETS_PROVIDER || "local";

const runtime = await createRuntime({
  rootDir: __dirname,
  signingSecret: SIGNING_SECRET
});
const registry = new ConnectorRegistry();
const oauth = new OAuthBroker({ secret: AUTH_SECRET, redirectBaseUrl: PUBLIC_BASE_URL });
const telemetry = new Telemetry({
  serviceName: process.env.OTEL_SERVICE_NAME || "scopezero-gateway",
  endpoint: OTEL_EXPORTER_OTLP_ENDPOINT,
  headers: process.env.OTEL_EXPORTER_OTLP_HEADERS || ""
});
const secrets = new SecretManager({
  rootDir: __dirname,
  masterKey: process.env.SCOPEZERO_SECRETS_MASTER_KEY || SIGNING_SECRET,
  provider: SECRETS_PROVIDER
});
const auth = new AuthService({
  secret: AUTH_SECRET,
  apiKey: API_KEY,
  requireAuth: REQUIRE_AUTH,
  oidcIssuer: OIDC_ISSUER,
  oidcAudience: OIDC_AUDIENCE,
  jwksUrl: OIDC_JWKS_URL
});
const rateLimiter = new Map();

const server = http.createServer(async (req, res) => {
  const spanAttributes = {
    "http.request.method": req.method,
    "url.path": req.url.split("?")[0]
  };
  try {
    setCors(res);
    enforceRateLimit(req, res);
    if (req.method === "OPTIONS") {
      return sendJson(res, 204, {});
    }

    const url = new URL(req.url, `http://${req.headers.host}`);

    if (url.pathname === "/.well-known/jwks.json") {
      return telemetry.trace("http.jwks", spanAttributes, () => sendJson(res, 200, auth.publicJwks()));
    }

    if (url.pathname === "/metrics") {
      return telemetry.trace("http.metrics", spanAttributes, () => handleMetrics(req, res));
    }

    if (url.pathname === "/mcp" || url.pathname === "/v1/mcp") {
      return telemetry.trace("http.mcp", spanAttributes, () => handleMcpHttp(req, res));
    }

    if (url.pathname.startsWith("/v1/")) {
      return telemetry.trace("http.api", spanAttributes, () => handleApi(req, res, url));
    }

    return telemetry.trace("http.static", spanAttributes, () => serveStatic(res, url.pathname));
  } catch (error) {
    return sendJson(res, error.status || 500, {
      error: {
        code: error.code || "internal_error",
        message: error.message || "Unexpected error"
      }
    });
  }
});

server.listen(PORT, () => {
  console.log(`ScopeZero Gateway listening on http://localhost:${PORT}`);
});

async function handleApi(req, res, url) {
  if (req.method === "GET" && url.pathname === "/v1/health") {
    return sendJson(res, 200, {
      status: "ok",
      product: "ScopeZero Gateway",
      category: "vendor-neutral agent action authorization",
      protocol: "AATP-0.2"
    });
  }

  if (req.method === "GET" && url.pathname === "/v1/ready") {
    return sendJson(res, 200, {
      ready: true,
      database: Boolean(runtime.store.db || runtime.store.pool),
      ledger: true,
      auth_required: REQUIRE_AUTH,
      oidc_configured: Boolean(OIDC_JWKS_URL),
      store_provider: STORE_PROVIDER,
      postgres_configured: STORE_PROVIDER === "postgres" && Boolean(process.env.DATABASE_URL),
      otel_configured: Boolean(OTEL_EXPORTER_OTLP_ENDPOINT),
      secrets_provider: SECRETS_PROVIDER,
      timestamp: new Date().toISOString()
    });
  }

  if (req.method === "POST" && url.pathname === "/v1/auth/dev-token") {
    if (REQUIRE_AUTH && !ALLOW_DEV_TOKEN) {
      return sendJson(res, 403, { error: { code: "dev_token_disabled", message: "Dev token issuing is disabled." } });
    }
    const body = await readJson(req);
    return sendJson(res, 201, {
      token_type: "Bearer",
      access_token: auth.issueToken({
        subject: body.subject || "developer@scopezero.local",
        tenant_id: body.tenant_id || "tenant_contoso",
        roles: body.roles || ["tenant_admin"],
        ttl_seconds: body.ttl_seconds || 3600
      })
    });
  }

  if (req.method === "GET" && url.pathname === "/v1/connectors/oauth/callback") {
    return sendJson(res, 200, oauth.callback({
      code: url.searchParams.get("code"),
      state: url.searchParams.get("state")
    }));
  }

  const principal = await auth.authenticate(req);

  if (req.method === "GET" && url.pathname === "/v1/state") {
    const tenantId = url.searchParams.get("tenant_id") || principal.tenant_id || "tenant_contoso";
    auth.authorize(principal, "tenant:read", tenantId);
    return sendJson(res, 200, filterStateForTenant(await runtime.state(), principal, tenantId));
  }

  if (req.method === "GET" && url.pathname === "/v1/ledger") {
    const tenantId = url.searchParams.get("tenant_id") || principal.tenant_id || "tenant_contoso";
    auth.authorize(principal, "ledger:read", tenantId);
    const state = await runtime.state();
    return sendJson(res, 200, { events: filterEventsForTenant(state.recent_events, principal, tenantId) });
  }

  if (req.method === "GET" && url.pathname === "/v1/ledger/verify") {
    const tenantId = url.searchParams.get("tenant_id") || principal.tenant_id || "tenant_contoso";
    auth.authorize(principal, "ledger:read", tenantId);
    return sendJson(res, 200, await runtime.verifyLedger());
  }

  if (req.method === "GET" && url.pathname === "/v1/siem/events") {
    const tenantId = url.searchParams.get("tenant_id") || principal.tenant_id || "tenant_contoso";
    const format = url.searchParams.get("format") || "json";
    const limit = Number(url.searchParams.get("limit") || 100);
    auth.authorize(principal, "siem:read", tenantId);
    const state = await runtime.state({ limit });
    const events = filterEventsForTenant(state.recent_events, principal, tenantId);
    const payload = exportEvents(events, format);
    if (typeof payload === "string") {
      res.writeHead(200, { "content-type": contentTypeForSiem(format) });
      return res.end(payload);
    }
    return sendJson(res, 200, payload);
  }

  if (req.method === "GET" && url.pathname === "/v1/siem/otlp") {
    const tenantId = url.searchParams.get("tenant_id") || principal.tenant_id || "tenant_contoso";
    auth.authorize(principal, "siem:read", tenantId);
    const state = await runtime.state({ limit: Number(url.searchParams.get("limit") || 100) });
    return sendJson(res, 200, exportEvents(filterEventsForTenant(state.recent_events, principal, tenantId), "otlp"));
  }

  if (req.method === "GET" && url.pathname === "/v1/policy") {
    const tenantId = url.searchParams.get("tenant_id") || "tenant_contoso";
    auth.authorize(principal, "tenant:read", tenantId);
    return sendJson(res, 200, runtime.store.getPolicy(tenantId));
  }

  if (req.method === "GET" && url.pathname === "/v1/policy/versions") {
    const tenantId = url.searchParams.get("tenant_id") || principal.tenant_id || "tenant_contoso";
    auth.authorize(principal, "tenant:read", tenantId);
    return sendJson(res, 200, { versions: runtime.store.listPolicyVersions(tenantId) });
  }

  if (req.method === "POST" && url.pathname === "/v1/policy/proposals") {
    const body = await readJson(req);
    const tenantId = body.tenant_id || principal.tenant_id || "tenant_contoso";
    auth.authorize(principal, "policy:write", tenantId);
    return sendJson(res, 201, await runtime.proposePolicy({
      tenant_id: tenantId,
      policy: body.policy || body.patch || {},
      proposed_by: principal.subject
    }));
  }

  const policyReviewMatch = url.pathname.match(/^\/v1\/policy\/proposals\/([^/]+)\/(approve|deny)$/);
  if (req.method === "POST" && policyReviewMatch) {
    const body = await readJson(req);
    const tenantId = body.tenant_id || principal.tenant_id || "tenant_contoso";
    auth.authorize(principal, "policy:write", tenantId);
    return sendJson(res, 200, await runtime.reviewPolicyProposal({
      proposal_id: policyReviewMatch[1],
      decision: policyReviewMatch[2],
      reviewer: principal.subject,
      tenant_id: tenantId
    }));
  }

  if (req.method === "GET" && url.pathname === "/v1/secrets") {
    const tenantId = url.searchParams.get("tenant_id") || principal.tenant_id || "tenant_contoso";
    auth.authorize(principal, "policy:write", tenantId);
    return sendJson(res, 200, { secrets: await secrets.list(tenantId) });
  }

  if (req.method === "POST" && url.pathname === "/v1/secrets") {
    const body = await readJson(req);
    const tenantId = body.tenant_id || principal.tenant_id || "tenant_contoso";
    auth.authorize(principal, "policy:write", tenantId);
    return sendJson(res, 201, {
      secret: await secrets.put({
        tenant_id: tenantId,
        name: body.name,
        value: body.value,
        created_by: principal.subject
      })
    });
  }

  if (req.method === "GET" && url.pathname === "/v1/telemetry/traces") {
    const tenantId = url.searchParams.get("tenant_id") || principal.tenant_id || "tenant_contoso";
    auth.authorize(principal, "siem:read", tenantId);
    return sendJson(res, 200, { traces: telemetry.snapshot({ limit: Number(url.searchParams.get("limit") || 50) }) });
  }

  if (req.method === "GET" && url.pathname === "/v1/compliance/controls") {
    const tenantId = url.searchParams.get("tenant_id") || principal.tenant_id || "tenant_contoso";
    auth.authorize(principal, "ledger:read", tenantId);
    return sendJson(res, 200, complianceControls({ tenantId }));
  }

  if (req.method === "GET" && url.pathname === "/v1/connectors") {
    const tenantId = url.searchParams.get("tenant_id") || principal.tenant_id || "tenant_contoso";
    auth.authorize(principal, "tenant:read", tenantId);
    return sendJson(res, 200, { connectors: registry.list() });
  }

  if (req.method === "POST" && url.pathname === "/v1/connectors/oauth/start") {
    const body = await readJson(req);
    const tenantId = body.tenant_id || principal.tenant_id || "tenant_contoso";
    auth.authorize(principal, "policy:write", tenantId);
    return sendJson(res, 201, oauth.start({
      provider: body.provider,
      tenant_id: tenantId,
      subject: principal.subject
    }));
  }

  if (req.method === "PUT" && url.pathname === "/v1/policy") {
    const body = await readJson(req);
    const tenantId = body.tenant_id || "tenant_contoso";
    auth.authorize(principal, "policy:write", tenantId);
    return sendJson(res, 200, await runtime.store.setPolicy(tenantId, body.policy || body));
  }

  if (req.method === "POST" && url.pathname === "/v1/agents") {
    const body = await readJson(req);
    auth.authorize(principal, "agent:write", body.tenant_id);
    return sendJson(res, 201, await runtime.registerAgent(body));
  }

  if (req.method === "POST" && url.pathname === "/v1/missions") {
    const body = await readJson(req);
    auth.authorize(principal, "mission:write", body.tenant_id);
    return sendJson(res, 201, await runtime.createMission({ ...body, requested_by: auditPrincipal(principal) }));
  }

  if (req.method === "POST" && (url.pathname === "/v1/tool-calls" || url.pathname === "/v1/action-authorizations")) {
    const body = await readJson(req);
    auth.authorize(principal, "tool:evaluate", body.tenant_id);
    return sendJson(res, 200, await runtime.evaluateToolCall({ ...body, requested_by: auditPrincipal(principal) }));
  }

  const approvalMatch = url.pathname.match(/^\/v1\/approvals\/([^/]+)\/(approve|deny)$/);
  if (req.method === "POST" && approvalMatch) {
    const body = await readJson(req);
    const tenantId = body.tenant_id || principal.tenant_id || "tenant_contoso";
    auth.authorize(principal, "approval:write", tenantId);
    return sendJson(res, 200, await runtime.updateApproval(approvalMatch[1], approvalMatch[2], body.actor || principal.subject, tenantId));
  }

  return sendJson(res, 404, { error: { code: "not_found", message: "Endpoint not found." } });
}

async function handleMcpHttp(req, res) {
  if (req.method !== "POST") {
    return sendJson(res, 405, { error: { code: "method_not_allowed", message: "MCP endpoint expects POST." } });
  }
  const principal = await auth.authenticate(req);
  const body = await readJson(req);
  const response = await handleMcpRequest({ body, runtime, registry, auth, principal });
  if (response === null) {
    return sendJson(res, 202, {});
  }
  return sendJson(res, response.error ? 400 : 200, response);
}

async function handleMetrics(req, res) {
  if (REQUIRE_AUTH) {
    await auth.authenticate(req);
  }
  const state = await runtime.state({ limit: 1 });
  const metrics = state.metrics || {};
  const lines = [
    "# HELP scopezero_runtime_decisions_total Total runtime decisions evaluated.",
    "# TYPE scopezero_runtime_decisions_total counter",
    `scopezero_runtime_decisions_total ${metrics.runtime_decisions || 0}`,
    "# HELP scopezero_blocked_actions_total Total blocked agent actions.",
    "# TYPE scopezero_blocked_actions_total counter",
    `scopezero_blocked_actions_total ${metrics.blocked_actions || 0}`,
    "# HELP scopezero_approvals_required_total Total human approvals required.",
    "# TYPE scopezero_approvals_required_total counter",
    `scopezero_approvals_required_total ${metrics.approvals_required || 0}`,
    "# HELP scopezero_evidence_capsules_total Total evidence capsules sealed.",
    "# TYPE scopezero_evidence_capsules_total counter",
    `scopezero_evidence_capsules_total ${metrics.evidence_capsules || 0}`,
    "# HELP scopezero_agents_registered Current registered agents.",
    "# TYPE scopezero_agents_registered gauge",
    `scopezero_agents_registered ${state.agents?.length || 0}`,
    "# HELP scopezero_missions_issued Current issued missions.",
    "# TYPE scopezero_missions_issued gauge",
    `scopezero_missions_issued ${state.missions?.length || 0}`
  ];
  res.writeHead(200, { "content-type": "text/plain; version=0.0.4; charset=utf-8" });
  res.end(lines.join("\n") + "\n");
}

async function serveStatic(res, requestPath) {
  const normalized = requestPath === "/" ? "/index.html" : requestPath;
  const resolved = path.resolve(__dirname, `.${decodeURIComponent(normalized)}`);
  if (!resolved.startsWith(__dirname)) {
    return sendText(res, 403, "Forbidden");
  }

  try {
    const content = await fs.readFile(resolved);
    res.writeHead(200, {
      "content-type": contentType(resolved),
      "cache-control": "no-store"
    });
    res.end(content);
  } catch {
    sendText(res, 404, "Not found");
  }
}

async function readJson(req) {
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > 2_000_000) {
      const error = new Error("Request body too large.");
      error.status = 413;
      error.code = "payload_too_large";
      throw error;
    }
    chunks.push(chunk);
  }
  const raw = Buffer.concat(chunks).toString("utf8");
  return raw ? JSON.parse(raw) : {};
}

function sendJson(res, status, payload) {
  res.writeHead(status, {
    "content-type": "application/json",
    "x-content-type-options": "nosniff",
    "referrer-policy": "no-referrer",
    "x-frame-options": "DENY"
  });
  res.end(status === 204 ? "" : JSON.stringify(payload, null, 2));
}

function sendText(res, status, text) {
  res.writeHead(status, { "content-type": "text/plain" });
  res.end(text);
}

function setCors(res) {
  res.setHeader("access-control-allow-origin", CORS_ORIGIN);
  res.setHeader("access-control-allow-methods", "GET,POST,PUT,OPTIONS");
  res.setHeader("access-control-allow-headers", "content-type,authorization");
}

function enforceRateLimit(req, res) {
  if (!RATE_LIMIT_PER_MINUTE || RATE_LIMIT_PER_MINUTE <= 0) {
    return;
  }
  const now = Date.now();
  const windowMs = 60_000;
  const remote = req.socket.remoteAddress || "unknown";
  const key = `${remote}:${req.url.split("?")[0]}`;
  const bucket = rateLimiter.get(key) || { count: 0, resetAt: now + windowMs };
  if (now > bucket.resetAt) {
    bucket.count = 0;
    bucket.resetAt = now + windowMs;
  }
  bucket.count += 1;
  rateLimiter.set(key, bucket);
  res.setHeader("x-ratelimit-limit", String(RATE_LIMIT_PER_MINUTE));
  res.setHeader("x-ratelimit-remaining", String(Math.max(0, RATE_LIMIT_PER_MINUTE - bucket.count)));
  res.setHeader("x-ratelimit-reset", String(Math.ceil(bucket.resetAt / 1000)));
  if (bucket.count > RATE_LIMIT_PER_MINUTE) {
    const error = new Error("Rate limit exceeded.");
    error.status = 429;
    error.code = "rate_limited";
    throw error;
  }
}

function filterStateForTenant(state, principal, tenantId) {
  if (principal.tenants.includes("*")) {
    return state;
  }
  return {
    ...state,
    tenants: state.tenants.filter((tenant) => tenant.tenant_id === tenantId),
    agents: state.agents.filter((agent) => agent.tenant_id === tenantId),
    missions: state.missions.filter((mission) => mission.tenant_id === tenantId),
    approvals: state.approvals.filter((approval) => approval.tenant_id === tenantId),
    policies: { [tenantId]: state.policies[tenantId] },
    sessions: Object.fromEntries(Object.entries(state.sessions).filter(([key, value]) => key.startsWith(`${tenantId}:`) || value.tenant_id === tenantId)),
    recent_events: filterEventsForTenant(state.recent_events, principal, tenantId)
  };
}

function filterEventsForTenant(events, principal, tenantId) {
  if (principal.tenants.includes("*")) {
    return events;
  }
  return events.filter((event) => {
    const record = event.record || {};
    return record.tenant_id === tenantId || record.agent?.tenant_id === tenantId || record.mission?.tenant_id === tenantId || record.approval?.tenant_id === tenantId;
  });
}

function contentType(filePath) {
  const ext = path.extname(filePath).toLowerCase();
  return {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".json": "application/json; charset=utf-8",
    ".yaml": "application/yaml; charset=utf-8",
    ".yml": "application/yaml; charset=utf-8",
    ".md": "text/markdown; charset=utf-8"
  }[ext] || "application/octet-stream";
}

function complianceControls({ tenantId }) {
  return {
    tenant_id: tenantId,
    framework: "SOC2-oriented runtime control map",
    controls: [
      { id: "CC6.1", name: "Logical access", evidence: ["OIDC/JWKS auth", "RBAC authorization", "tenant-scoped filtering"] },
      { id: "CC6.6", name: "Change management", evidence: ["policy proposals", "policy approvals", "hash-linked evidence ledger"] },
      { id: "CC7.2", name: "Security monitoring", evidence: ["SIEM JSON/CEF/LEEF/OTLP exports", "OpenTelemetry spans", "Prometheus metrics"] },
      { id: "CC7.4", name: "Incident investigation", evidence: ["forensic capsules", "ledger verification", "approval outcome records"] },
      { id: "CC8.1", name: "Production change control", evidence: ["Kubernetes manifests", "readiness probes", "config/secret split"] },
      { id: "C1.2", name: "Confidential information protection", evidence: ["sensitive data classifier", "egress guard", "encrypted secret references"] }
    ]
  };
}
