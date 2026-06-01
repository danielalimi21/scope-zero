import test from "node:test";
import assert from "node:assert/strict";
import {
  computeTrustDecay,
  queryOsvVulnerabilities,
  applyTrustSignals,
  buildMcpServerRecord
} from "../src/mcpTrustRegistry.js";

function makeVerifiedServer(overrides = {}) {
  return buildMcpServerRecord({
    server_id: "github.com/test/server",
    trust_level: "verified",
    package_name: "@test/mcp-server",
    ...overrides
  });
}

// computeTrustDecay

test("fresh verified server is not overdue", () => {
  const server = makeVerifiedServer({ last_reviewed_at: new Date().toISOString() });
  const decay = computeTrustDecay(server, new Date());
  assert.equal(decay.review_overdue, false);
  assert.equal(decay.demoted, false);
  assert.equal(decay.effective_trust_level, "verified");
});

test("verified server not reviewed in 181 days is overdue and demoted to community", () => {
  const longAgo = new Date(Date.now() - 181 * 24 * 60 * 60 * 1000).toISOString();
  const server = makeVerifiedServer({ last_reviewed_at: longAgo });
  const decay = computeTrustDecay(server, new Date());
  assert.equal(decay.review_overdue, true);
  assert.equal(decay.demoted, true);
  assert.equal(decay.effective_trust_level, "community");
});

test("community server never triggers overdue demotion", () => {
  const longAgo = new Date(Date.now() - 365 * 24 * 60 * 60 * 1000).toISOString();
  const server = buildMcpServerRecord({ server_id: "x", trust_level: "community", last_reviewed_at: longAgo });
  const decay = computeTrustDecay(server, new Date());
  assert.equal(decay.review_overdue, false);
  assert.equal(decay.demoted, false);
});

test("server with no refresh after 91 days is stale", () => {
  const longAgo = new Date(Date.now() - 91 * 24 * 60 * 60 * 1000).toISOString();
  const server = makeVerifiedServer({ last_reviewed_at: new Date().toISOString(), added_at: longAgo });
  const decay = computeTrustDecay(server, new Date());
  assert.equal(decay.stale, true);
});

test("recently added server is not stale", () => {
  const server = makeVerifiedServer({ added_at: new Date().toISOString(), last_reviewed_at: new Date().toISOString() });
  const decay = computeTrustDecay(server, new Date());
  assert.equal(decay.stale, false);
});

test("null server returns null", () => {
  assert.equal(computeTrustDecay(null), null);
});

// queryOsvVulnerabilities with mock fetch

test("queryOsvVulnerabilities returns parsed vulns from OSV response", async () => {
  const mockFetch = async () => ({
    ok: true,
    json: async () => ({
      vulns: [
        { id: "CVE-2024-0001", summary: "Remote code execution", published: "2024-01-01T00:00:00Z" },
        { id: "CVE-2024-0002", summary: "XSS vulnerability", published: "2024-02-01T00:00:00Z" }
      ]
    })
  });
  const result = await queryOsvVulnerabilities("some-package", "npm", mockFetch);
  assert.equal(result.vulns.length, 2);
  assert.equal(result.vulns[0].id, "CVE-2024-0001");
  assert.equal(result.error, null);
});

test("queryOsvVulnerabilities returns empty array on OSV 404", async () => {
  const mockFetch = async () => ({ ok: false, status: 404 });
  const result = await queryOsvVulnerabilities("no-package", "npm", mockFetch);
  assert.equal(result.vulns.length, 0);
  assert.ok(result.error);
});

test("queryOsvVulnerabilities returns empty array on network error", async () => {
  const mockFetch = async () => { throw new Error("ECONNREFUSED"); };
  const result = await queryOsvVulnerabilities("pkg", "npm", mockFetch);
  assert.equal(result.vulns.length, 0);
  assert.ok(result.error.includes("ECONNREFUSED"));
});

test("queryOsvVulnerabilities skips call when package name is null", async () => {
  let called = false;
  const mockFetch = async () => { called = true; };
  const result = await queryOsvVulnerabilities(null, "npm", mockFetch);
  assert.equal(called, false);
  assert.equal(result.vulns.length, 0);
});

// applyTrustSignals

test("applyTrustSignals sets signal_summary to cve_found when CVEs present", () => {
  const server = makeVerifiedServer({ last_reviewed_at: new Date().toISOString() });
  const decay = computeTrustDecay(server, new Date());
  const osvResult = { vulns: [{ id: "CVE-2024-0001", summary: "RCE" }], error: null };
  applyTrustSignals(server, decay, osvResult, new Date());
  assert.equal(server.trust_signals.signal_summary, "cve_found");
  assert.equal(server.trust_signals.known_cves, 1);
  assert.deepEqual(server.trust_signals.cve_ids, ["CVE-2024-0001"]);
});

test("applyTrustSignals sets signal_summary to review_overdue when no CVEs", () => {
  const longAgo = new Date(Date.now() - 181 * 24 * 60 * 60 * 1000).toISOString();
  const server = makeVerifiedServer({ last_reviewed_at: longAgo });
  const decay = computeTrustDecay(server, new Date());
  applyTrustSignals(server, decay, { vulns: [], error: null }, new Date());
  assert.equal(server.trust_signals.signal_summary, "review_overdue");
  assert.equal(server.trust_signals.known_cves, 0);
});

test("applyTrustSignals sets signal_summary to clean when no issues", () => {
  const server = makeVerifiedServer({ last_reviewed_at: new Date().toISOString() });
  const decay = computeTrustDecay(server, new Date());
  applyTrustSignals(server, decay, { vulns: [], error: null }, new Date());
  assert.equal(server.trust_signals.signal_summary, "clean");
});

test("applyTrustSignals demotes server trust_level when overdue", () => {
  const longAgo = new Date(Date.now() - 181 * 24 * 60 * 60 * 1000).toISOString();
  const server = makeVerifiedServer({ last_reviewed_at: longAgo });
  const decay = computeTrustDecay(server, new Date());
  applyTrustSignals(server, decay, { vulns: [], error: null }, new Date());
  assert.equal(server.trust_level, "community");
  assert.equal(server.trust_signals.demoted, true);
});
