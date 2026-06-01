import test from "node:test";
import assert from "node:assert/strict";
import {
  assessMcpCall,
  evaluateMcpServerTrust,
  buildMcpServerRecord,
  TRUST_LEVELS,
  WELL_KNOWN_MCP_SERVERS
} from "../src/mcpTrustRegistry.js";

// Helpers
function makeServer(overrides = {}) {
  return buildMcpServerRecord({
    server_id: "example.com/test-server",
    name: "Test Server",
    trust_level: "community",
    tools: [
      { name: "get_data", risk_level: "low", operations: ["read"], mutating: false, irreversible: false },
      { name: "delete_record", risk_level: "high", operations: ["write"], mutating: true, irreversible: true }
    ],
    ...overrides
  });
}

// evaluateMcpServerTrust

test("verified server returns zero risk delta and no block", () => {
  const result = evaluateMcpServerTrust(makeServer({ trust_level: "verified" }));
  assert.equal(result.trust_level, "verified");
  assert.equal(result.risk_delta, 0);
  assert.equal(result.block, false);
});

test("community server returns low risk delta and no block", () => {
  const result = evaluateMcpServerTrust(makeServer({ trust_level: "community" }));
  assert.equal(result.risk_delta, TRUST_LEVELS.community.risk_delta);
  assert.equal(result.block, false);
});

test("unverified server returns elevated risk delta and no block", () => {
  const result = evaluateMcpServerTrust(makeServer({ trust_level: "unverified" }));
  assert.equal(result.risk_delta, TRUST_LEVELS.unverified.risk_delta);
  assert.equal(result.block, false);
});

test("blocked server returns block=true", () => {
  const result = evaluateMcpServerTrust(makeServer({ trust_level: "blocked" }));
  assert.equal(result.block, true);
});

test("null server defaults to unverified risk delta", () => {
  const result = evaluateMcpServerTrust(null);
  assert.equal(result.trust_level, "unverified");
  assert.equal(result.risk_delta, TRUST_LEVELS.unverified.risk_delta);
});

// assessMcpCall

test("blocked server assessment returns block=true with reason", () => {
  const server = makeServer({ trust_level: "blocked" });
  const result = assessMcpCall({ server, toolName: "get_data", currentDecision: "allow" });
  assert.equal(result.block, true);
  assert.ok(result.reason.code === "mcp-server-blocked");
});

test("unverified server with allow decision triggers escalation", () => {
  const server = makeServer({ trust_level: "unverified" });
  const result = assessMcpCall({ server, toolName: "get_data", currentDecision: "allow" });
  assert.equal(result.block, false);
  assert.equal(result.escalate, true);
  assert.ok(result.reason.code.includes("unverified"));
});

test("unverified server with already-blocked decision does not escalate", () => {
  const server = makeServer({ trust_level: "unverified" });
  const result = assessMcpCall({ server, toolName: "get_data", currentDecision: "block" });
  assert.equal(result.block, false);
  assert.equal(result.escalate, false);
});

test("community server does not escalate allow decision", () => {
  const server = makeServer({ trust_level: "community" });
  const result = assessMcpCall({ server, toolName: "get_data", currentDecision: "allow" });
  assert.equal(result.block, false);
  assert.equal(result.escalate, false);
  assert.ok(result.reason !== null);
});

test("verified server produces no reason annotation", () => {
  const server = makeServer({ trust_level: "verified" });
  const result = assessMcpCall({ server, toolName: "get_data", currentDecision: "allow" });
  assert.equal(result.block, false);
  assert.equal(result.escalate, false);
  assert.equal(result.reason, null);
});

// buildMcpServerRecord

test("buildMcpServerRecord normalizes invalid trust level to unverified", () => {
  const server = buildMcpServerRecord({ server_id: "x", trust_level: "unknown_level" });
  assert.equal(server.trust_level, "unverified");
});

test("verified server record has verified_at set", () => {
  const server = buildMcpServerRecord({ server_id: "x", trust_level: "verified" });
  assert.ok(server.verified_at !== null);
});

test("unverified server record has null verified_at", () => {
  const server = buildMcpServerRecord({ server_id: "x", trust_level: "unverified" });
  assert.equal(server.verified_at, null);
});

// Well-known server seed

test("well-known servers include github and mcp reference servers", () => {
  const ids = WELL_KNOWN_MCP_SERVERS.map(s => s.server_id);
  assert.ok(ids.includes("github.com/github/github-mcp-server"));
  assert.ok(ids.includes("github.com/modelcontextprotocol/servers/filesystem"));
});

test("github server is trust level verified", () => {
  const github = WELL_KNOWN_MCP_SERVERS.find(s => s.server_id === "github.com/github/github-mcp-server");
  assert.equal(github.trust_level, "verified");
});

test("github server has high-risk irreversible delete_branch tool", () => {
  const github = WELL_KNOWN_MCP_SERVERS.find(s => s.server_id === "github.com/github/github-mcp-server");
  const del = github.tools.find(t => t.name === "delete_branch");
  assert.ok(del);
  assert.equal(del.risk_level, "high");
  assert.equal(del.irreversible, true);
});
