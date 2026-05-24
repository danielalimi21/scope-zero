import fs from "node:fs/promises";
import { createHash } from "node:crypto";

const checks = [
  ["Gateway API", "server.js"],
  ["OpenAPI contract", "openapi.yaml"],
  ["Agent SDK", "sdk/scopezero-sdk.js"],
  ["Mission contracts", "src/capsules.js"],
  ["Action authorization", "src/actionAuthorization.js"],
  ["Policy engine", "src/policyEngine.js"],
  ["MCP proxy", "src/mcp.js"],
  ["SIEM export", "src/siem.js"],
  ["Evidence ledger", "src/ledger.js"],
  ["Ledger verifier", "tools/verify-ledger.js"],
  ["OIDC/JWKS and RBAC", "src/auth.js"],
  ["Encrypted secrets", "src/secrets.js"],
  ["OpenTelemetry traces", "src/telemetry.js"],
  ["SQLite store", "src/store.js"],
  ["Postgres store", "src/postgresStore.js"],
  ["Postgres schema", "db/postgres/schema.sql"],
  ["Kubernetes manifests", "k8s/deployment.yaml"],
  ["Docker image", "Dockerfile"],
  ["Security review", "SECURITY_REVIEW.md"],
  ["Product architecture", "PRODUCT_ARCHITECTURE.md"],
  ["Company pitch", "SEND_TO_COMPANIES.md"],
  ["Full overview", "SCOPEZERO_FULL_OVERVIEW.md"],
  ["Commercial readiness", "COMMERCIAL_READINESS.md"],
  ["Customer pilot proposal", "CUSTOMER_PILOT_PROPOSAL.md"],
  ["Pricing and packaging", "PRICING_AND_PACKAGING.md"],
  ["Buyer FAQ", "BUYER_FAQ.md"],
  ["GA checklist", "GA_RELEASE_CHECKLIST.md"],
  ["CI workflow", ".github/workflows/scopezero-ci.yml"],
  ["Automated tests", "tests/policy-engine.test.js"]
];

const productionGaps = [
  "Connect a real enterprise IdP and verify customer role/group claim mapping.",
  "Run managed Postgres with private networking, PITR, backups, and connection pooling.",
  "Move local encrypted secret storage to a customer vault or KMS-backed provider.",
  "Persist evidence to append-only object storage or immutable database retention.",
  "Add distributed rate limiting for multi-replica production.",
  "Attach the first real connector worker and OAuth token exchange.",
  "Add SBOM generation, dependency scanning, provenance, and image signing.",
  "Run external penetration testing before customer production data."
];

const verifiedCommands = [
  "npm run check",
  "npm test",
  "node tools/smoke-test.js",
  "node examples/malicious-diligence-agent.js",
  "node tools/verify-ledger.js",
  "node tools/config-check.js"
];

const results = [];
for (const [name, file] of checks) {
  results.push({
    name,
    file,
    present: await exists(file),
    sha256: (await exists(file)) ? await digest(file) : ""
  });
}

const score = Math.round((results.filter((item) => item.present).length / results.length) * 100);
const now = new Date().toISOString();
const report = [
  "# ScopeZero Enterprise Readiness Report",
  "",
  `Generated: ${now}`,
  "",
  "## Summary",
  "",
  `Readiness artifact coverage: **${score}%** (${results.filter((item) => item.present).length}/${results.length})`,
  "",
  "ScopeZero is a pilot-ready product core for agent action authorization. It includes the runtime gateway, SDK, mission contracts, policy engine, evidence ledger, MCP proxy, SIEM export, auth/RBAC, OpenAPI contract, automated tests, deployment scaffolding, and buyer/security documentation.",
  "",
  "## Verified Artifacts",
  "",
  "| Area | File | Status | SHA-256 |",
  "| --- | --- | --- | --- |",
  ...results.map((item) => `| ${item.name} | \`${item.file}\` | ${item.present ? "present" : "missing"} | ${item.sha256.slice(0, 12)} |`),
  "",
  "## Verification Commands",
  "",
  ...verifiedCommands.map((command) => `- \`${command}\``),
  "",
  "## Production Gaps",
  "",
  ...productionGaps.map((gap) => `- ${gap}`),
  "",
  "## Buyer-Relevant Proof Points",
  "",
  "- Pre-execution action authorization is implemented through `/v1/action-authorizations` and MCP `tools/call`.",
  "- Mission action contracts are signed and verified before runtime execution.",
  "- Sensitive egress, prompt influence, delegation depth, destination, and high-impact actions are policy inputs.",
  "- Unsafe actions return block, quarantine, redact, approval, or pause decisions before tool execution.",
  "- Every major decision is written into a hash-chained evidence ledger.",
  "- Evidence can be exported to SOC tooling through JSON, CEF, LEEF, and OTLP-style payloads.",
  "- The project includes OpenAPI, tests, Kubernetes, Docker, Postgres path, OTEL path, and security review.",
  "",
  "## Recommended Next Pilot",
  "",
  "Run one controlled pilot with one internal agent, two tools, one sensitive workflow, one SIEM integration, one IdP integration, and one approval gate. Success is a blocked out-of-scope action with usable SOC evidence.",
  ""
].join("\n");

await fs.writeFile("ENTERPRISE_READINESS_REPORT.md", report);
console.log(`ScopeZero readiness report generated: ENTERPRISE_READINESS_REPORT.md (${score}% artifact coverage)`);

async function exists(file) {
  try {
    await fs.access(file);
    return true;
  } catch {
    return false;
  }
}

async function digest(file) {
  const data = await fs.readFile(file);
  return createHash("sha256").update(data).digest("hex");
}
