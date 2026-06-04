// ScopeZero — exfiltration-to-an-allowed-host walkthrough.
//
// The hard case for any egress control: the agent doesn't tunnel to pastebin.
// It posts your data to a host that IS in the mission contract — api.github.com —
// but to an attacker-controlled gist. A host-only proxy sees an allowed CONNECT
// and waves it through; TLS hides the payload. The network layer cannot catch
// this. The ACTION layer can, because it sees the payload before it leaves.
//
// This demo proves the split:
//   - declared, public-classed egress flows automatically (manifested tool);
//   - opaque content with no established data class, leaving through an
//     unmanifested tool to the SAME allowed host, is held for human review;
//   - the proxy, asked about that same host, allows it — which is exactly why
//     the action layer has to be the one that catches the leak.
//
//   node examples/exfil-to-allowed-host-demo.js
//
// Exit code is non-zero if any step fails to hold, so this is an executable proof.

import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { createRuntime } from "../src/runtime.js";
import { evaluateProxyConnect } from "../src/proxyEnforcer.js";

const SECRET = "demo-signing-secret";
const TENANT = "tenant_contoso";
const AGENT = "agent.repo-sync.4c1a";
const ALLOWED_HOST = "api.github.com";

const GREEN = "\x1b[32m";
const RED = "\x1b[31m";
const DIM = "\x1b[2m";
const BOLD = "\x1b[1m";
const RESET = "\x1b[0m";

let failures = 0;

function step(title) {
  console.log(`\n${BOLD}${title}${RESET}`);
}

function check(label, ok, detail) {
  if (ok) {
    console.log(`  ${GREEN}✓${RESET} ${label}`);
  } else {
    failures += 1;
    console.log(`  ${RED}✗ FAILED${RESET} ${label}`);
  }
  if (detail) console.log(`    ${DIM}${detail}${RESET}`);
}

// A tool whose manifest declares it only ever emits public data. Egress through
// it is trusted. The exfil tool (github.gist) has no manifest, so its output
// class is genuinely unknown.
const manifests = {
  "github.sync": {
    tool_id: "github.sync",
    operation: "write",
    action_type: "write",
    data_out_classes: ["public"],
    mutating: true
  }
};

async function main() {
  const rootDir = await fs.mkdtemp(path.join(os.tmpdir(), "scopezero-exfil-"));
  const runtime = await createRuntime({
    rootDir,
    signingSecret: SECRET,
    toolManifestResolver: (tool) => manifests[tool] || null
  });

  console.log(`${BOLD}ScopeZero — exfiltration to an in-contract host${RESET}`);
  console.log(`${DIM}The agent never leaves ${ALLOWED_HOST}. The leak is in the payload, not the destination.${RESET}`);

  // ── Mission ───────────────────────────────────────────────────────────────
  step("1. The mission permits writes to api.github.com");
  await runtime.registerAgent({
    tenant_id: TENANT,
    agent_id: AGENT,
    owner: "eng.lead@contoso.example",
    allowed_tools: ["github.sync", "github.gist"]
  });
  const { capsule } = await runtime.createMission({
    tenant_id: TENANT,
    agent_id: AGENT,
    delegated_by: "eng.lead@contoso.example",
    objective: "Export GitHub issue summaries and write public status updates to the gist API at api.github.com.",
    allowed_tools: ["github.sync", "github.gist"],
    allowed_data_classes: ["public", "internal"],
    allowed_destinations: [ALLOWED_HOST]
  });
  console.log(`  ${DIM}mission ${capsule.id} — github writes to ${ALLOWED_HOST}, public/internal only${RESET}`);

  // ── Legit: manifested, declared-public egress flows ─────────────────────────
  step("2. A declared-public sync flows automatically");
  const legit = await runtime.evaluateToolCall({
    tenant_id: TENANT, agent_id: AGENT, mission_id: capsule.id,
    tool: "github.sync", action: "Write public build status", operation: "write",
    payload: { summary: "Nightly issue sync complete." },
    destination: { type: "url", address: ALLOWED_HOST }
  });
  check(
    "manifested tool with a declared public output class → allow",
    legit.decision === "allow",
    `decision=${legit.decision}`
  );

  // ── Attack: opaque content to the SAME allowed host via an unmanifested tool ─
  step("3. Injected agent dumps opaque data to the same allowed host (attacker's gist)");
  const exfil = await runtime.evaluateToolCall({
    tenant_id: TENANT, agent_id: AGENT, mission_id: capsule.id,
    tool: "github.gist", action: "Create a gist", operation: "write",
    // Real customer rows — but no keyword a classifier could match. "public" here
    // would be an absence of evidence, not evidence of absence.
    payload: { content: "account,balance\n4012-8888,182240.55\n4012-9001,93517.10\n4012-7777,540883.00" },
    destination: { type: "url", address: ALLOWED_HOST }
  });
  const heldForReview = exfil.decision !== "allow";
  const rightReason = (exfil.verdict?.reasons || []).some((r) => r.code === "unverified-egress-class");
  check(
    "opaque, unclassifiable egress to an in-contract host is held for review — not auto-allowed",
    heldForReview && rightReason,
    `decision=${exfil.decision}; reasons: ${(exfil.verdict?.reasons || []).map((r) => r.code).join(", ")}`
  );

  // ── Contrast: the network layer cannot see this ─────────────────────────────
  step("4. The proxy, asked about the same host, allows it — TLS hides the payload");
  const proxy = evaluateProxyConnect({
    mission: runtime.store.getMission(capsule.id, TENANT),
    host: ALLOWED_HOST,
    requestedAgentId: AGENT,
    verifyKey: SECRET
  });
  check(
    "host-only proxy allows the CONNECT (host is in contract) — proving the action layer is what catches the leak",
    proxy.allowed === true,
    `proxy decision: ${proxy.allowed ? "allowed" : "blocked"} → the network layer is blind to payload by design`
  );

  // ── Proof ───────────────────────────────────────────────────────────────────
  step("5. The record holds the evidence");
  const verify = await runtime.verifyLedger();
  check(
    "tamper-evident ledger verifies clean (keyed hash chain)",
    verify.valid === true,
    `${verify.entries} entries, chain_root ${String(verify.chain_root).slice(0, 24)}…`
  );

  await fs.rm(rootDir, { recursive: true, force: true });

  console.log("");
  if (failures === 0) {
    console.log(`${GREEN}${BOLD}The leak was caught where the bytes are visible, not where the host is checked.${RESET}`);
    process.exit(0);
  } else {
    console.log(`${RED}${BOLD}${failures} step(s) failed.${RESET}`);
    process.exit(1);
  }
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
