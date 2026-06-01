import test from "node:test";
import assert from "node:assert/strict";
import {
  parseProxyAuth,
  parseConnectTarget,
  isDestinationAllowed,
  buildDeploymentLockdown
} from "../src/proxyEnforcer.js";

// parseProxyAuth

test("parseProxyAuth extracts bearer token", () => {
  const req = { headers: { "proxy-authorization": "Bearer abc123" } };
  const result = parseProxyAuth(req);
  assert.equal(result.type, "bearer");
  assert.equal(result.token, "abc123");
});

test("parseProxyAuth extracts ScopeZero-Mission header", () => {
  const req = { headers: { "proxy-authorization": "ScopeZero-Mission mission_abc:tenant_x:agent_y" } };
  const result = parseProxyAuth(req);
  assert.equal(result.type, "mission");
  assert.equal(result.mission_id, "mission_abc");
  assert.equal(result.tenant_id, "tenant_x");
  assert.equal(result.agent_id, "agent_y");
});

test("parseProxyAuth returns null when header absent", () => {
  assert.equal(parseProxyAuth({ headers: {} }), null);
});

test("parseProxyAuth returns null for malformed ScopeZero-Mission header", () => {
  const req = { headers: { "proxy-authorization": "ScopeZero-Mission only_one_part" } };
  assert.equal(parseProxyAuth(req), null);
});

// parseConnectTarget

test("parseConnectTarget splits host and port", () => {
  const result = parseConnectTarget("api.github.com:443");
  assert.equal(result.host, "api.github.com");
  assert.equal(result.port, 443);
});

test("parseConnectTarget defaults port to 443 when missing", () => {
  const result = parseConnectTarget("api.github.com");
  assert.equal(result.host, "api.github.com");
  assert.equal(result.port, 443);
});

test("parseConnectTarget handles non-standard ports", () => {
  const result = parseConnectTarget("internal.api.example.com:8080");
  assert.equal(result.host, "internal.api.example.com");
  assert.equal(result.port, 8080);
});

// isDestinationAllowed

const mission = {
  action_contracts: [
    {
      tools: ["drive.search"],
      destinations: ["diligence-room.contoso.example", "*.googleapis.com"]
    }
  ]
};

test("isDestinationAllowed allows exact match", () => {
  assert.equal(isDestinationAllowed("diligence-room.contoso.example", mission), true);
});

test("isDestinationAllowed allows wildcard subdomain", () => {
  assert.equal(isDestinationAllowed("www.googleapis.com", mission), true);
});

test("isDestinationAllowed blocks unlisted host", () => {
  assert.equal(isDestinationAllowed("evil.example.com", mission), false);
});

test("isDestinationAllowed blocks when mission is null", () => {
  assert.equal(isDestinationAllowed("api.github.com", null), false);
});

test("isDestinationAllowed blocks when no contracts have destinations", () => {
  const emptyMission = { action_contracts: [{ tools: ["x"], destinations: [] }] };
  assert.equal(isDestinationAllowed("api.github.com", emptyMission), false);
});

// buildDeploymentLockdown

test("buildDeploymentLockdown includes all proxy env vars", () => {
  const config = buildDeploymentLockdown({ proxyHost: "scopezero", proxyPort: 8788 });
  assert.equal(config.env_vars.HTTP_PROXY, "http://scopezero:8788");
  assert.equal(config.env_vars.HTTPS_PROXY, "http://scopezero:8788");
  assert.equal(config.env_vars.http_proxy, "http://scopezero:8788");
  assert.equal(config.env_vars.https_proxy, "http://scopezero:8788");
});

test("buildDeploymentLockdown includes kubernetes env patch array", () => {
  const config = buildDeploymentLockdown({ proxyHost: "10.0.0.1", proxyPort: 9000 });
  assert.ok(Array.isArray(config.kubernetes_env_patch));
  assert.ok(config.kubernetes_env_patch.some(e => e.name === "HTTPS_PROXY" && e.value === "http://10.0.0.1:9000"));
});

test("buildDeploymentLockdown includes docker run snippet", () => {
  const config = buildDeploymentLockdown({ proxyHost: "gateway", proxyPort: 8788 });
  assert.ok(config.docker_run_snippet.includes("--env HTTP_PROXY=http://gateway:8788"));
});
