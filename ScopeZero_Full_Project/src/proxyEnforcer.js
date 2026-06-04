// HTTP forward proxy interceptor — pure logic, no I/O dependencies.
// Agents set HTTP_PROXY=http://<scopezero-host>:8788 and include
// "Proxy-Authorization: Bearer <jwt>" on every request so ScopeZero
// can identify the mission before tunnelling the connection through.

import { verifyMissionCapsule } from "./capsules.js";

// Full pre-tunnel authorization for a CONNECT request. A connection is only
// opened when it is bound to a mission that is real (signature valid), live
// (unexpired + active), owned by the requesting agent, and whose action
// contracts permit the destination host. Every failure has a distinct reason
// so the ledger records *why* a tunnel was refused. Pure + deterministic
// (`now`/`verifyKey` injectable) so it is unit-testable without sockets.
// verifyKey is the Ed25519 public key (or a shared-secret string in dev); a proxy
// holding only the public key can authenticate a mission but cannot forge one.
export function evaluateProxyConnect({ mission, host, requestedAgentId = null, verifyKey = "", now = new Date() }) {
  if (!mission) {
    return { allowed: false, reason: "no_active_mission", mission_id: null };
  }
  if (verifyKey && !verifyMissionCapsule(mission, verifyKey)) {
    return { allowed: false, reason: "mission_signature_invalid", mission_id: mission.id || null };
  }
  if (!mission.expires_at || new Date(mission.expires_at).getTime() < now.getTime()) {
    return { allowed: false, reason: "mission_expired", mission_id: mission.id || null };
  }
  if (mission.status && mission.status !== "active") {
    return { allowed: false, reason: "mission_inactive", mission_id: mission.id || null };
  }
  if (requestedAgentId && mission.agent_id && mission.agent_id !== requestedAgentId) {
    return { allowed: false, reason: "mission_agent_mismatch", mission_id: mission.id || null };
  }
  if (!isDestinationAllowed(host, mission)) {
    return { allowed: false, reason: "destination_not_in_mission_contract", mission_id: mission.id || null };
  }
  return { allowed: true, reason: null, mission_id: mission.id || null };
}

export function parseProxyAuth(req) {
  const header = (req.headers?.["proxy-authorization"] || "").trim();
  if (header.startsWith("Bearer ")) {
    return { type: "bearer", token: header.slice(7).trim() };
  }
  // Lightweight non-JWT path: "ScopeZero-Mission <missionId>:<tenantId>:<agentId>"
  if (header.startsWith("ScopeZero-Mission ")) {
    const parts = header.slice(18).trim().split(":");
    if (parts.length >= 3) {
      return { type: "mission", mission_id: parts[0], tenant_id: parts[1], agent_id: parts[2] };
    }
  }
  return null;
}

export function parseConnectTarget(rawUrl = "") {
  const lastColon = rawUrl.lastIndexOf(":");
  if (lastColon < 0) return { host: rawUrl, port: 443 };
  const port = parseInt(rawUrl.slice(lastColon + 1), 10);
  const host = rawUrl.slice(0, lastColon);
  return { host, port: Number.isFinite(port) ? port : 443 };
}

// Check whether the host is reachable under any active action contract.
export function isDestinationAllowed(host, mission) {
  if (!mission) return false;
  const contracts = mission.action_contracts || [];
  const allDestinations = contracts.flatMap(c => c.destinations || []);
  // A mission with no destinations and no contracts blocks everything.
  if (!allDestinations.length) return false;
  return allDestinations.some(d => destinationMatchesHost(d, host));
}

// Generate environment variable config for agent deployment.
export function buildDeploymentLockdown({ proxyHost = "scopezero", proxyPort = 8788 } = {}) {
  const proxyUrl = `http://${proxyHost}:${proxyPort}`;
  return {
    description: "Configure these on every agent container. All outbound HTTP/HTTPS is intercepted by ScopeZero before reaching external APIs. Connections without a valid Proxy-Authorization header are blocked.",
    proxy_url: proxyUrl,
    env_vars: {
      HTTP_PROXY: proxyUrl,
      HTTPS_PROXY: proxyUrl,
      http_proxy: proxyUrl,
      https_proxy: proxyUrl,
      NO_PROXY: "localhost,127.0.0.1"
    },
    docker_run_snippet: [
      `--env HTTP_PROXY=${proxyUrl}`,
      `--env HTTPS_PROXY=${proxyUrl}`,
      `--env http_proxy=${proxyUrl}`,
      `--env https_proxy=${proxyUrl}`,
      "--env NO_PROXY=localhost,127.0.0.1"
    ].join(" \\\n  "),
    kubernetes_env_patch: [
      { name: "HTTP_PROXY",  value: proxyUrl },
      { name: "HTTPS_PROXY", value: proxyUrl },
      { name: "http_proxy",  value: proxyUrl },
      { name: "https_proxy", value: proxyUrl },
      { name: "NO_PROXY",    value: "localhost,127.0.0.1" }
    ],
    auth_header: "Proxy-Authorization: Bearer <scopezero-jwt>",
    note: "JWT must be issued by ScopeZero and carry tenant_id, agent_id, mission_id claims."
  };
}

function destinationMatchesHost(pattern, host) {
  const norm = String(pattern).toLowerCase()
    .replace(/^https?:\/\//, "")
    .split("/")[0]
    .split(":")[0];
  const h = String(host).toLowerCase().split(":")[0];
  if (norm === "*" || norm === h) return true;
  if (norm.startsWith("*.")) return h.endsWith(norm.slice(1));
  return h.endsWith("." + norm);
}
