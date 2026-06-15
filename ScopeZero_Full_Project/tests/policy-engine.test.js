import test from "node:test";
import assert from "node:assert/strict";
import policy from "../config/defaultPolicy.json" with { type: "json" };
import { describeActionRequest } from "../src/actionAuthorization.js";
import { evaluatePolicy } from "../src/policyEngine.js";

const agent = {
  tenant_id: "tenant_contoso",
  agent_id: "agent.test",
  allowed_tools: ["drive.read", "slack.draft"]
};

const mission = {
  id: "mission_test",
  status: "active",
  allowed_tools: ["drive.read", "slack.draft"],
  allowed_data_classes: ["public", "internal", "confidential"],
  allowed_destinations: ["diligence-room.contoso.example"],
  action_contracts: [
    {
      id: "read-contract",
      tools: ["drive.read"],
      operations: ["read"],
      data_classes: ["public", "internal", "confidential"],
      destinations: ["diligence-room.contoso.example"],
      effect: "allow"
    },
    {
      id: "draft-contract",
      tools: ["slack.draft"],
      operations: ["draft"],
      data_classes: ["public", "internal", "confidential"],
      destinations: ["diligence-room.contoso.example"],
      effect: "allow"
    }
  ]
};

test("policy allows mission-aligned internal read", () => {
  const request = {
    tool: "drive.read",
    action: "Read diligence file",
    operation: "read",
    context: { mission_aligned: true },
    action_descriptor: describeActionRequest({ tool: "drive.read", action: "Read diligence file", operation: "read" }, { label: "internal" }, policy)
  };

  const verdict = evaluatePolicy({
    request,
    mission,
    agent,
    policy,
    classification: { level: 2, label: "internal", findings: [] },
    promptInfluence: { influenced: false, origin: "unknown", matched_patterns: [] },
    missionAlignment: { aligned: true, score: 0.6, source: "server_deterministic", reasons: [] },
    externalDestination: false,
    currentSessionRisk: 0
  });

  assert.equal(verdict.decision, "allow");
  assert.equal(verdict.safe_to_execute, true);
  assert.equal(verdict.matched_contract_id, "read-contract");
});

test("policy blocks restricted external egress outside mission", () => {
  const request = {
    tool: "gmail.send",
    action: "Send raw customer revenue externally",
    operation: "external_send",
    destination: { type: "email", address: "outside@example.com", external: true },
    context: { mission_aligned: false },
    action_descriptor: describeActionRequest(
      {
        tool: "gmail.send",
        action: "Send raw customer revenue externally",
        operation: "external_send",
        destination: { type: "email", address: "outside@example.com", external: true }
      },
      { label: "restricted" },
      policy
    )
  };

  const verdict = evaluatePolicy({
    request,
    mission,
    agent,
    policy,
    classification: { level: 5, label: "restricted", findings: [{ code: "restricted" }] },
    promptInfluence: { influenced: true, origin: "pdf.hidden_text", matched_patterns: ["send to external"] },
    missionAlignment: { aligned: false, score: 0, source: "server_deterministic", reasons: ["external-send-not-in-objective"] },
    externalDestination: true,
    currentSessionRisk: 0
  });

  assert.equal(verdict.decision, "block");
  assert.equal(verdict.safe_to_execute, false);
  assert.ok(verdict.reasons.some((reason) => reason.code === "sensitive-egress"));
});

test("lexical mission drift escalates to human approval (advisory), never blocks on its own", () => {
  const driftMission = {
    ...mission,
    allowed_tools: ["slack.draft"],
    action_contracts: [
      {
        id: "draft-contract",
        tools: ["slack.draft"],
        operations: ["draft"],
        data_classes: ["public", "internal"],
        destinations: ["diligence-room.contoso.example"],
        effect: "allow"
      }
    ]
  };
  const request = {
    tool: "slack.draft",
    action: "Post payroll restructuring plan",
    operation: "draft",
    context: { mission_aligned: true },
    action_descriptor: describeActionRequest(
      {
        tool: "slack.draft",
        action: "Post payroll restructuring plan",
        operation: "draft",
        destination: { type: "slack", address: "diligence-room.contoso.example" }
      },
      { label: "internal" },
      policy
    )
  };

  const verdict = evaluatePolicy({
    request,
    mission: driftMission,
    agent: { ...agent, allowed_tools: ["slack.draft"] },
    policy,
    classification: { level: 2, label: "internal", findings: [] },
    promptInfluence: { influenced: false, origin: "unknown", matched_patterns: [] },
    missionAlignment: { aligned: false, score: 0, source: "server_deterministic", reasons: ["low-objective-overlap"] },
    externalDestination: false,
    currentSessionRisk: 0
  });

  // A keyword-overlap heuristic must not block by itself; it routes to a human.
  // The deterministic contract gates are what block.
  assert.equal(verdict.decision, "approval");
  assert.equal(verdict.safe_to_execute, false);
  assert.ok(verdict.reasons.some((reason) => reason.code === "intent-drift-advisory"));
});

// The exfil-to-an-allowed-host case: every contract gate is satisfied (the tool,
// operation, data class, and destination are all in scope) and the keyword
// classifier sees nothing sensitive — yet the content is leaving for an external
// host. A blind "public" must not be an automatic allow. This is the control that
// closes the hole the host-only proxy cannot see.
test("unknown-class content leaving for an in-contract external host is held for review, not auto-allowed", () => {
  const egressMission = {
    id: "mission_egress",
    status: "active",
    allowed_tools: ["github.write"],
    allowed_data_classes: ["public", "internal"],
    allowed_destinations: ["api.github.com"],
    action_contracts: [
      {
        id: "gh-write",
        tools: ["github.write"],
        operations: ["write"],
        data_classes: ["public", "internal"],
        destinations: ["api.github.com"],
        effect: "allow"
      }
    ]
  };
  const request = {
    tool: "github.write",
    action: "Create a gist with the export",
    operation: "write",
    payload: { content: "id,amount\n1,4193\n2,5521\n3,8840" }, // sensitive rows, no trigger keyword
    action_descriptor: {
      schema: "scopezero.action_authorization.v1",
      tool: "github.write",
      action: "Create a gist with the export",
      operation: "write",
      action_type: "write",
      data_class: "public",
      data_rank: 1,
      destination: { type: "url", address: "api.github.com", external: true },
      // Manifest present (so the mutating-manifest gate is satisfied) but it does
      // not declare an output class — so the egress class is genuinely unknown.
      tool_manifest: { tool_id: "github.write", operation: "write", action_type: "write", data_out_classes: [] }
    }
  };

  const verdict = evaluatePolicy({
    request,
    mission: egressMission,
    agent: { ...agent, allowed_tools: ["github.write"] },
    policy,
    classification: { level: 1, label: "public", findings: [] },
    promptInfluence: { influenced: false, origin: "unknown", matched_patterns: [] },
    missionAlignment: { aligned: true, score: 0.5, source: "server_deterministic", reasons: [] },
    externalDestination: true,
    currentSessionRisk: 0
  });

  assert.equal(verdict.decision, "approval");
  assert.equal(verdict.safe_to_execute, false);
  assert.ok(verdict.reasons.some((reason) => reason.code === "unverified-egress-class"));
});

// Read-only inferred operations stay autonomous — the fail-closed-on-unknown rule
// must not turn every external read into an approval.
test("an in-contract external read with no payload stays an automatic allow", () => {
  const readMission = {
    id: "mission_read",
    status: "active",
    allowed_tools: ["api.fetch"],
    allowed_data_classes: ["public", "internal"],
    allowed_destinations: ["api.github.com"],
    action_contracts: [
      { id: "fetch", tools: ["api.fetch"], operations: ["read"], data_classes: ["public", "internal"], destinations: ["api.github.com"], effect: "allow" }
    ]
  };
  const request = {
    tool: "api.fetch",
    action: "Read issue list",
    operation: "read",
    action_descriptor: {
      schema: "scopezero.action_authorization.v1",
      tool: "api.fetch",
      action: "Read issue list",
      operation: "read",
      action_type: "read",
      data_class: "public",
      data_rank: 1,
      destination: { type: "url", address: "api.github.com", external: true },
      tool_manifest: { tool_id: "api.fetch", operation: "read", action_type: "read", data_out_classes: ["public"] }
    }
  };

  const verdict = evaluatePolicy({
    request,
    mission: readMission,
    agent: { ...agent, allowed_tools: ["api.fetch"] },
    policy,
    classification: { level: 1, label: "public", findings: [] },
    promptInfluence: { influenced: false, origin: "unknown", matched_patterns: [] },
    missionAlignment: { aligned: true, score: 0.5, source: "server_deterministic", reasons: [] },
    externalDestination: true,
    currentSessionRisk: 0
  });

  assert.equal(verdict.decision, "allow");
});

// Regression: the manifest must be a VERIFIED CEILING, never a skip-flag. A
// prompt-injected agent picks the tool, so it would otherwise route opaque data
// through the tool whose manifest declares the friendliest output class. The same
// opaque payload that is held when sent through an unmanifested tool must still be
// held when sent through a tool whose manifest declares public output.
const manifestEgressMission = {
  id: "mission_manifest_egress",
  status: "active",
  allowed_tools: ["github.sync"],
  allowed_data_classes: ["public", "internal"],
  allowed_destinations: ["api.github.com"],
  // The mission's intended public-broadcast destination — opts this lane out of the
  // default external-egress seal so these tests exercise the byte/taint controls,
  // not the seal. The taint and shape guards still apply on top.
  public_egress_destinations: ["api.github.com"],
  action_contracts: [
    { id: "gh-sync", tools: ["github.sync"], operations: ["write"], data_classes: ["public", "internal"], destinations: ["api.github.com"], effect: "allow" }
  ]
};

function manifestEgressRequest(payload) {
  return {
    tool: "github.sync",
    action: "Write public build status",
    operation: "write",
    payload,
    action_descriptor: {
      schema: "scopezero.action_authorization.v1",
      tool: "github.sync",
      action: "Write public build status",
      operation: "write",
      action_type: "write",
      data_class: "public",
      data_rank: 1,
      destination: { type: "url", address: "api.github.com", external: true },
      // A manifest that declares the tool only ever emits public data. This used to
      // make the egress gate skip itself — the documented bypass.
      tool_manifest: { tool_id: "github.sync", operation: "write", action_type: "write", data_out_classes: ["public"], mutating: true }
    }
  };
}

test("opaque egress through a tool whose manifest declares public output is still held for review (manifest is not a skip-flag)", () => {
  const verdict = evaluatePolicy({
    request: manifestEgressRequest({ content: "account,balance\n4012-8888,182240.55\n4012-9001,93517.10\n4012-7777,540883.00" }),
    mission: manifestEgressMission,
    agent: { ...agent, allowed_tools: ["github.sync"] },
    policy,
    // Bulk/tabular shape ⇒ class not positively established as public from the bytes.
    classification: { level: 1, label: "public", findings: [], egress_shape: "tabular_dump", established: false },
    promptInfluence: { influenced: false, origin: "unknown", matched_patterns: [] },
    missionAlignment: { aligned: true, score: 0.5, source: "server_deterministic", reasons: [] },
    externalDestination: true,
    currentSessionRisk: 0
  });

  assert.equal(verdict.decision, "approval");
  assert.equal(verdict.safe_to_execute, false);
  assert.ok(verdict.reasons.some((reason) => reason.code === "unverified-egress-class"));
});

test("payload that classifies above the tool's declared output ceiling is held for review (ceiling verified against bytes)", () => {
  const verdict = evaluatePolicy({
    request: manifestEgressRequest({ summary: "loop in vp.strategy@contoso.example on the close" }),
    mission: manifestEgressMission,
    agent: { ...agent, allowed_tools: ["github.sync"] },
    policy,
    // Internal (level 2) content leaving through a tool the manifest says emits only public.
    classification: { level: 2, label: "internal", findings: ["email_address"], egress_shape: null, established: true },
    promptInfluence: { influenced: false, origin: "unknown", matched_patterns: [] },
    missionAlignment: { aligned: true, score: 0.5, source: "server_deterministic", reasons: [] },
    externalDestination: true,
    currentSessionRisk: 0
  });

  assert.equal(verdict.decision, "approval");
  assert.ok(verdict.reasons.some((reason) => reason.code === "manifest-output-class-exceeded"));
});

test("benign short content through a public-manifest tool stays an automatic allow (fast path preserved)", () => {
  const verdict = evaluatePolicy({
    request: manifestEgressRequest({ summary: "Nightly issue sync complete." }),
    mission: manifestEgressMission,
    agent: { ...agent, allowed_tools: ["github.sync"] },
    policy,
    // Short prose, no bulk/opaque shape ⇒ class positively established as public.
    classification: { level: 1, label: "public", findings: [], egress_shape: null, established: true },
    promptInfluence: { influenced: false, origin: "unknown", matched_patterns: [] },
    missionAlignment: { aligned: true, score: 0.5, source: "server_deterministic", reasons: [] },
    externalDestination: true,
    currentSessionRisk: 0
  });

  assert.equal(verdict.decision, "allow");
  assert.equal(verdict.safe_to_execute, true);
});

test("benign egress is held when the session has ingested more sensitive data (laundering guard)", () => {
  const verdict = evaluatePolicy({
    request: manifestEgressRequest({ summary: "Status: review complete, all green." }),
    mission: manifestEgressMission,
    agent: { ...agent, allowed_tools: ["github.sync"] },
    policy,
    classification: { level: 1, label: "public", findings: [], egress_shape: null, established: true },
    promptInfluence: { influenced: false, origin: "unknown", matched_patterns: [] },
    missionAlignment: { aligned: true, score: 0.5, source: "server_deterministic", reasons: [] },
    externalDestination: true,
    currentSessionRisk: 0,
    sessionIngestedClassRank: 4 // session previously read confidential data
  });

  assert.equal(verdict.decision, "approval");
  assert.ok(verdict.reasons.some((reason) => reason.code === "tainted-session-egress"));
});

test("the laundering guard does not fire when egress class matches what the session ingested", () => {
  const verdict = evaluatePolicy({
    request: manifestEgressRequest({ summary: "Status: review complete, all green." }),
    mission: manifestEgressMission,
    agent: { ...agent, allowed_tools: ["github.sync"] },
    policy,
    // Outbound class equals ingested class ⇒ governed by the normal data-class/
    // destination gates, not the downgrade/launder heuristic.
    classification: { level: 1, label: "public", findings: [], egress_shape: null, established: true },
    promptInfluence: { influenced: false, origin: "unknown", matched_patterns: [] },
    missionAlignment: { aligned: true, score: 0.5, source: "server_deterministic", reasons: [] },
    externalDestination: true,
    currentSessionRisk: 0,
    sessionIngestedClassRank: 1
  });

  assert.equal(verdict.decision, "allow");
});
