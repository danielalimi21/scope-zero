"use strict";

const scenarios = {
  github: {
    surface: "GitHub",
    title: "Create a safe pull request",
    agent: "devops-remediate",
    tool: "github.pr",
    operation: "write",
    data: "internal",
    destination: "company repository",
    intent: "Open a documentation-only pull request in the approved repository.",
    decision: "allow",
    result: "ScopeZero allows the pull request because the agent, tool, operation, data class, and destination all match the signed mission contract.",
    checks: [
      ["Agent identity", "Registered agent identity found.", "pass"],
      ["Mission contract", "Mission permits github.pr write actions for documentation changes.", "pass"],
      ["Data boundary", "Payload is internal and does not contain secrets or restricted records.", "pass"],
      ["Destination", "Target repository is inside the approved GitHub boundary.", "pass"],
      ["Execution", "Tool call may proceed and evidence is sealed.", "pass"]
    ]
  },
  slack: {
    surface: "Slack",
    title: "Send customer revenue externally",
    agent: "ma-diligence",
    tool: "slack.draft",
    operation: "external_send",
    data: "restricted",
    destination: "external channel",
    intent: "Post raw customer revenue rows after reading a document that contains hidden instructions.",
    decision: "block",
    result: "ScopeZero blocks the message before Slack execution because restricted data is leaving the approved workspace under prompt-influenced context.",
    checks: [
      ["Agent identity", "Registered diligence agent found.", "pass"],
      ["Mission contract", "Mission allows safe summaries, not raw restricted exports.", "fail"],
      ["Prompt influence", "Untrusted document instructions attempted to redirect the agent.", "warn"],
      ["Data boundary", "Payload contains restricted customer revenue.", "fail"],
      ["Execution", "Slack call is denied before posting.", "fail"]
    ]
  },
  aws: {
    surface: "AWS IAM",
    title: "Attach AdministratorAccess",
    agent: "cloud-remediate",
    tool: "aws.iam.attachPolicy",
    operation: "privilege_change",
    data: "restricted",
    destination: "production AWS account",
    intent: "Grant broad admin privileges so the agent can complete remediation faster.",
    decision: "block",
    result: "ScopeZero blocks the privilege escalation before AWS is mutated. The mission allows remediation work, not autonomous admin expansion.",
    checks: [
      ["Agent identity", "Registered cloud agent found.", "pass"],
      ["Mission contract", "Mission does not permit admin privilege escalation.", "fail"],
      ["Privilege impact", "Requested action grants administrative authority.", "fail"],
      ["Approval gate", "Admin changes require explicit human authorization.", "warn"],
      ["Execution", "AWS mutation is denied before execution.", "fail"]
    ]
  },
  finance: {
    surface: "Finance",
    title: "Prepare high-value payment",
    agent: "finance-ops",
    tool: "bank.transfer",
    operation: "payment",
    data: "confidential",
    destination: "vendor bank account",
    intent: "Prepare a payment after detecting that the vendor bank account changed recently.",
    decision: "approval",
    result: "ScopeZero routes the action to human approval because the payment is high value and the destination changed recently.",
    checks: [
      ["Agent identity", "Registered finance agent found.", "pass"],
      ["Mission contract", "Mission allows reconciliation and payment preparation.", "pass"],
      ["Financial impact", "Payment amount exceeds autonomous threshold.", "warn"],
      ["Destination risk", "Vendor bank details changed recently.", "warn"],
      ["Execution", "Payment waits for controller approval.", "warn"]
    ]
  }
};

const decisionRank = {
  allow: "safe to execute",
  block: "denied before execution",
  approval: "human approval required"
};

const state = {
  activeScenario: "github",
  lastEvidence: null
};

const els = {};

document.addEventListener("DOMContentLoaded", () => {
  collectElements();
  bindEvents();
  renderScenario();
  renderEvidence(buildEvidence(scenarios.github, "not_run"));
});

function collectElements() {
  Object.assign(els, {
    tabs: document.querySelectorAll(".scenario-tab"),
    runButton: document.getElementById("runWalkthrough"),
    requestTitle: document.getElementById("requestTitle"),
    surfacePill: document.getElementById("surfacePill"),
    agentValue: document.getElementById("agentValue"),
    toolValue: document.getElementById("toolValue"),
    operationValue: document.getElementById("operationValue"),
    dataValue: document.getElementById("dataValue"),
    destinationValue: document.getElementById("destinationValue"),
    intentValue: document.getElementById("intentValue"),
    decisionTitle: document.getElementById("decisionTitle"),
    decisionPill: document.getElementById("decisionPill"),
    checklist: document.getElementById("checklist"),
    resultBox: document.getElementById("resultBox"),
    evidenceRecord: document.getElementById("evidenceRecord")
  });
}

function bindEvents() {
  els.tabs.forEach((tab) => {
    tab.addEventListener("click", () => {
      state.activeScenario = tab.dataset.scenario;
      els.tabs.forEach((candidate) => candidate.classList.toggle("active", candidate === tab));
      renderScenario();
    });
  });

  els.runButton.addEventListener("click", runWalkthrough);
}

function renderScenario() {
  const scenario = scenarios[state.activeScenario];
  els.requestTitle.textContent = scenario.title;
  els.surfacePill.textContent = scenario.surface;
  els.agentValue.textContent = scenario.agent;
  els.toolValue.textContent = scenario.tool;
  els.operationValue.textContent = scenario.operation;
  els.dataValue.textContent = scenario.data;
  els.destinationValue.textContent = scenario.destination;
  els.intentValue.textContent = scenario.intent;
  els.decisionTitle.textContent = "Ready to evaluate";
  els.decisionPill.textContent = "idle";
  els.decisionPill.className = "decision-pill neutral";
  els.resultBox.textContent = "ScopeZero has not evaluated this action yet.";
  els.checklist.innerHTML = scenario.checks.map(([label, detail]) => `
    <div class="check-row waiting">
      <span></span>
      <strong>${escapeHtml(label)}</strong>
      <p>${escapeHtml(detail)}</p>
    </div>
  `).join("");
  renderEvidence(buildEvidence(scenario, "not_run"));
}

async function runWalkthrough() {
  const scenario = scenarios[state.activeScenario];
  els.runButton.disabled = true;
  els.runButton.textContent = "Checking...";
  els.decisionTitle.textContent = "Evaluating action";
  els.decisionPill.textContent = "checking";
  els.decisionPill.className = "decision-pill neutral";
  els.resultBox.textContent = "ScopeZero is normalizing the request and applying policy before the tool executes.";

  const rows = Array.from(els.checklist.querySelectorAll(".check-row"));
  rows.forEach((row) => {
    row.className = "check-row waiting";
  });

  for (let index = 0; index < rows.length; index += 1) {
    await wait(420);
    rows[index].className = `check-row ${scenario.checks[index][2]}`;
  }

  await wait(260);
  els.decisionTitle.textContent = decisionRank[scenario.decision];
  els.decisionPill.textContent = scenario.decision;
  els.decisionPill.className = `decision-pill ${scenario.decision}`;
  els.resultBox.textContent = scenario.result;

  const evidence = buildEvidence(scenario, scenario.decision);
  state.lastEvidence = evidence;
  renderEvidence(evidence);

  els.runButton.disabled = false;
  els.runButton.textContent = "Run ScopeZero Check";
}

function buildEvidence(scenario, decision) {
  const reasonCodes = scenario.checks
    .filter(([, , status]) => status !== "pass")
    .map(([label]) => label.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, ""));

  const payload = {
    evidence_schema: "scopezero.action_authorization.v1",
    agent: scenario.agent,
    tool: scenario.tool,
    operation: scenario.operation,
    data_class: scenario.data,
    destination: scenario.destination,
    decision,
    safe_to_execute: decision === "allow",
    required_action: {
      allow: "execute_tool_call",
      block: "deny_before_execution",
      approval: "route_to_human_approver",
      not_run: "await_authorization_request"
    }[decision],
    reasons: reasonCodes.length ? reasonCodes : ["mission-contract-match"],
    evidence_hash: shortHash(`${scenario.agent}:${scenario.tool}:${scenario.operation}:${decision}:${scenario.destination}`)
  };

  return payload;
}

function renderEvidence(record) {
  els.evidenceRecord.textContent = JSON.stringify(record, null, 2);
}

function shortHash(value) {
  let hash = 2166136261;
  for (let index = 0; index < value.length; index += 1) {
    hash ^= value.charCodeAt(index);
    hash = Math.imul(hash, 16777619);
  }
  return Math.abs(hash >>> 0).toString(16).padStart(8, "0");
}

function wait(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function escapeHtml(value) {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}
