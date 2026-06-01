import { nowIso } from "./crypto.js";

// Trust signals — computed from time-based decay and external CVE data.
const REVIEW_OVERDUE_DAYS = 180;   // verified servers not re-reviewed this long drop a tier
const STALENESS_DAYS = 90;         // server not refreshed this long gets a stale flag
const OSV_API = "https://api.osv.dev/v1/query";

export function computeTrustDecay(server, now = new Date()) {
  if (!server) return null;
  const reviewAnchor = server.last_reviewed_at || server.verified_at || server.added_at;
  const daysSinceReview = reviewAnchor
    ? (now.getTime() - new Date(reviewAnchor).getTime()) / (24 * 60 * 60 * 1000)
    : Infinity;
  const refreshAnchor = server.last_refreshed_at || server.added_at;
  const staleness_days = refreshAnchor
    ? Math.floor((now.getTime() - new Date(refreshAnchor).getTime()) / (24 * 60 * 60 * 1000))
    : Infinity;

  const review_overdue = server.trust_level === "verified" && daysSinceReview > REVIEW_OVERDUE_DAYS;
  const stale = staleness_days > STALENESS_DAYS;

  let effective_trust_level = server.trust_level;
  if (review_overdue && effective_trust_level === "verified") {
    effective_trust_level = "community"; // auto-demote
  }

  return {
    review_overdue,
    days_since_review: Math.floor(daysSinceReview),
    staleness_days,
    stale,
    effective_trust_level,
    demoted: effective_trust_level !== server.trust_level
  };
}

// Queries the OSV (Open Source Vulnerabilities) database for known CVEs.
// fetchFn is injectable for testing — defaults to global fetch.
export async function queryOsvVulnerabilities(packageName, ecosystem = "npm", fetchFn = fetch) {
  if (!packageName) return { vulns: [], error: null };
  try {
    const resp = await fetchFn(OSV_API, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ package: { name: packageName, ecosystem } })
    });
    if (!resp.ok) return { vulns: [], error: `OSV API returned ${resp.status}` };
    const data = await resp.json();
    const vulns = (data.vulns || []).map(v => ({
      id: v.id,
      summary: v.summary || "",
      severity: v.database_specific?.severity || null,
      published: v.published || null
    }));
    return { vulns, error: null };
  } catch (err) {
    return { vulns: [], error: err.message };
  }
}

// Merge decay and CVE findings into server.trust_signals.
export function applyTrustSignals(server, decay, osvResult, now = new Date()) {
  const known_cves = osvResult?.vulns?.length || 0;
  const cve_ids = (osvResult?.vulns || []).map(v => v.id);

  let signal_summary = "clean";
  if (known_cves > 0) signal_summary = "cve_found";
  else if (decay?.review_overdue) signal_summary = "review_overdue";
  else if (decay?.stale) signal_summary = "stale";

  server.trust_signals = {
    last_refreshed_at: now.toISOString(),
    review_overdue: decay?.review_overdue ?? false,
    days_since_review: decay?.days_since_review ?? null,
    staleness_days: decay?.staleness_days ?? null,
    stale: decay?.stale ?? false,
    effective_trust_level: decay?.effective_trust_level ?? server.trust_level,
    demoted: decay?.demoted ?? false,
    known_cves,
    cve_ids,
    cve_error: osvResult?.error || null,
    signal_summary
  };
  server.last_refreshed_at = now.toISOString();

  // Apply demotion to stored trust level if overdue
  if (decay?.demoted) {
    server.trust_level = decay.effective_trust_level;
  }

  return server;
}

export const TRUST_LEVELS = {
  verified:   { risk_delta: 0,   block: false },
  community:  { risk_delta: 5,   block: false },
  unverified: { risk_delta: 20,  block: false },
  blocked:    { risk_delta: 100, block: true  }
};

const VALID_TRUST_LEVELS = new Set(Object.keys(TRUST_LEVELS));

export function isValidTrustLevel(level) {
  return VALID_TRUST_LEVELS.has(level);
}

export function evaluateMcpServerTrust(server) {
  const level = server?.trust_level || "unverified";
  const config = TRUST_LEVELS[level] || TRUST_LEVELS.unverified;
  return { trust_level: level, ...config };
}

export function resolveMcpToolRisk(server, toolName) {
  const tool = (server?.tools || []).find(t => t.name === toolName);
  return tool?.risk_level || (server ? "medium" : "high");
}

// Returns trust verdict and whether the unverified server should escalate to approval.
export function assessMcpCall({ server, toolName, currentDecision }) {
  const trust = evaluateMcpServerTrust(server);
  const toolRisk = resolveMcpToolRisk(server, toolName);

  if (trust.block) {
    return {
      trust,
      toolRisk,
      escalate: false,
      block: true,
      reason: {
        code: "mcp-server-blocked",
        message: `MCP server "${server?.server_id || "unknown"}" is in the blocked list.`,
        source: "mcp_trust"
      }
    };
  }

  // Unverified servers escalate allow → approval regardless of tool risk
  const escalate = trust.risk_delta >= 20 && currentDecision === "allow";

  const reason = trust.risk_delta > 0
    ? {
        code: `mcp-trust-${trust.trust_level}`,
        message: `MCP server "${server?.server_id || "unknown"}" has trust level "${trust.trust_level}" (+${trust.risk_delta} risk).`,
        source: "mcp_trust"
      }
    : null;

  return { trust, toolRisk, escalate, block: false, reason };
}

export function buildMcpServerRecord({ server_id, name, url, publisher, trust_level = "unverified", tools = [], tenant_id = null, package_name = null, package_ecosystem = "npm", verified_at = null, last_reviewed_at = null, added_at = null }) {
  const level = VALID_TRUST_LEVELS.has(trust_level) ? trust_level : "unverified";
  const now = nowIso();
  return {
    server_id,
    name: name || server_id,
    url: url || null,
    publisher: publisher || null,
    trust_level: level,
    package_name: package_name || null,
    package_ecosystem: package_ecosystem || "npm",
    tools: tools.map(normalizeMcpTool),
    tenant_id,
    verified_at: verified_at || (level === "verified" ? now : null),
    verified_by: null,
    last_reviewed_at: last_reviewed_at || now,
    last_reviewed_by: null,
    added_at: added_at || now
  };
}

function normalizeMcpTool(tool) {
  return {
    name: tool.name || "unknown",
    description: tool.description || "",
    risk_level: ["high", "medium", "low"].includes(tool.risk_level) ? tool.risk_level : "medium",
    operations: tool.operations || [],
    external_capable: Boolean(tool.external_capable),
    mutating: Boolean(tool.mutating),
    irreversible: Boolean(tool.irreversible)
  };
}

// Well-known MCP servers — pre-seeded in the registry
export const WELL_KNOWN_MCP_SERVERS = [
  {
    server_id: "github.com/github/github-mcp-server",
    name: "GitHub MCP Server",
    url: "https://github.com/github/github-mcp-server",
    publisher: "github.com",
    trust_level: "verified",
    package_name: "@github/mcp-server",
    package_ecosystem: "npm",
    tenant_id: null,
    tools: [
      { name: "create_pull_request",    risk_level: "high",   operations: ["write"],  external_capable: false, mutating: true,  irreversible: false },
      { name: "push_files",             risk_level: "high",   operations: ["write"],  external_capable: false, mutating: true,  irreversible: false },
      { name: "search_repositories",   risk_level: "low",    operations: ["read"],   external_capable: false, mutating: false, irreversible: false },
      { name: "get_file_contents",      risk_level: "low",    operations: ["read"],   external_capable: false, mutating: false, irreversible: false },
      { name: "create_issue",           risk_level: "medium", operations: ["write"],  external_capable: false, mutating: true,  irreversible: false },
      { name: "delete_branch",          risk_level: "high",   operations: ["write"],  external_capable: false, mutating: true,  irreversible: true  }
    ]
  },
  {
    server_id: "github.com/modelcontextprotocol/servers/filesystem",
    name: "MCP Filesystem Server",
    url: "https://github.com/modelcontextprotocol/servers/tree/main/src/filesystem",
    publisher: "modelcontextprotocol",
    trust_level: "community",
    package_name: "@modelcontextprotocol/server-filesystem",
    package_ecosystem: "npm",
    tenant_id: null,
    tools: [
      { name: "read_file",    risk_level: "low",  operations: ["read"],  external_capable: false, mutating: false, irreversible: false },
      { name: "write_file",   risk_level: "high", operations: ["write"], external_capable: false, mutating: true,  irreversible: false },
      { name: "delete_file",  risk_level: "high", operations: ["write"], external_capable: false, mutating: true,  irreversible: true  },
      { name: "list_dir",     risk_level: "low",  operations: ["read"],  external_capable: false, mutating: false, irreversible: false }
    ]
  },
  {
    server_id: "github.com/modelcontextprotocol/servers/postgres",
    name: "MCP PostgreSQL Server",
    url: "https://github.com/modelcontextprotocol/servers/tree/main/src/postgres",
    publisher: "modelcontextprotocol",
    trust_level: "community",
    tenant_id: null,
    tools: [
      { name: "query",       risk_level: "medium", operations: ["read"],  external_capable: false, mutating: false, irreversible: false },
      { name: "execute",     risk_level: "high",   operations: ["write"], external_capable: false, mutating: true,  irreversible: true  }
    ]
  },
  {
    server_id: "github.com/modelcontextprotocol/servers/slack",
    name: "MCP Slack Server",
    url: "https://github.com/modelcontextprotocol/servers/tree/main/src/slack",
    publisher: "modelcontextprotocol",
    trust_level: "community",
    tenant_id: null,
    tools: [
      { name: "post_message",     risk_level: "medium", operations: ["external_send"], external_capable: true, mutating: true,  irreversible: false },
      { name: "list_channels",    risk_level: "low",    operations: ["read"],          external_capable: false, mutating: false, irreversible: false }
    ]
  }
];
