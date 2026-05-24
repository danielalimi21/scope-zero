import { dataClassAllowed, destinationAllowed, evaluateActionContract } from "./actionAuthorization.js";

export function evaluatePolicy({ request, mission, agent, policy, classification, promptInfluence, externalDestination, currentSessionRisk }) {
  const reasons = [];
  const controls = [];
  let decision = "allow";
  let risk = Number(request.base_risk || 8);
  const action = request.action_descriptor;
  let matchedContract = null;

  addRisk(classification.level * 3, "data-classification", `${classification.label} payload detected.`);

  if (!agent) {
    addRisk(45, "unknown-agent", "No registered agent identity was found.");
    decision = "block";
  }

  if (!mission) {
    addRisk(55, "missing-mission", "Tool call did not include a valid mission capsule.");
    decision = "block";
  }

  if (mission?.status !== "active") {
    addRisk(38, "inactive-mission", "Mission capsule is not active.");
    decision = "block";
  }

  if (mission && !mission.allowed_tools.includes(request.tool)) {
    addRisk(26, "tool-outside-scope", `Tool ${request.tool} is outside the mission allowlist.`);
    decision = stronger(decision, "approval");
  }

  if (policy.action_contracts_required && mission && action) {
    const contractResult = evaluateActionContract({ mission, action, externalDestination });
    if (!contractResult.ok) {
      addRisk(40, contractResult.code, contractResult.message);
      decision = "block";
    } else {
      matchedContract = contractResult.contract;
      controls.push("action-contract-match");
    }
  }

  if (policy.strict_data_class_enforcement && mission?.allowed_data_classes?.length && !dataClassAllowed(mission.allowed_data_classes, classification.label)) {
    addRisk(36, "mission-data-class-boundary", `Data class ${classification.label} exceeds the mission-approved data classes.`);
    decision = "block";
  }

  if (
    policy.strict_destination_enforcement &&
    mission?.allowed_destinations?.length &&
    action?.destination?.address &&
    !destinationAllowed(mission.allowed_destinations, action.destination.address, externalDestination)
  ) {
    addRisk(42, "mission-destination-boundary", `Destination ${action.destination.address} is outside the mission-approved boundary.`);
    decision = "block";
  }

  if ((policy.blocked_action_types || []).includes(action?.action_type)) {
    addRisk(60, "blocked-action-type", `Action type ${action.action_type} is explicitly blocked by tenant policy.`);
    decision = "block";
  }

  if (policy.mission_lock && request.context?.mission_aligned === false) {
    addRisk(42, "intent-drift", "Requested action no longer matches the approved mission.");
    decision = "block";
  }

  if (policy.prompt_injection_shield && promptInfluence.influenced) {
    addRisk(34, "prompt-influence", `Instruction influence detected from ${promptInfluence.origin}.`);
    if (decision !== "block") {
      decision = request.context?.mission_aligned === false ? "block" : "quarantine_context";
    }
  }

  if (policy.sensitive_egress_guard && externalDestination && classification.level >= policy.sensitive_data_block_level) {
    addRisk(44, "sensitive-egress", "Sensitive data attempted to cross an external boundary.");
    decision = "block";
  }

  if (Number(request.delegation_depth || 0) > Number(policy.max_delegation_depth || 0)) {
    addRisk(28, "delegation-depth", "Agent attempted to delegate beyond the allowed chain depth.");
    decision = "block";
  }

  if (policy.approval_gates && Number(request.money?.amount || 0) > Number(policy.financial_approval_threshold || 0)) {
    addRisk(22, "financial-impact", "Financial impact exceeds autonomous approval threshold.");
    decision = stronger(decision, "approval");
  }

  if (policy.approval_gates && (policy.high_impact_action_types || []).includes(action?.action_type) && decision !== "block") {
    addRisk(18, "high-impact-action", `Action type ${action.action_type} requires explicit authorization or human approval.`);
    decision = stronger(decision, matchedContract?.effect === "allow" ? "allow" : "approval");
  }

  if (policy.admin_privilege_requires_approval && request.privilege?.admin === true) {
    addRisk(28, "admin-privilege", "Administrative privilege changes require human approval.");
    decision = stronger(decision, "approval");
  }

  if (policy.redact_sensitive_outputs && decision === "allow" && classification.level >= 4 && request.output_channel === "summary") {
    addRisk(10, "redaction-required", "Sensitive output can continue only after redaction.");
    decision = "redact";
  }

  const projectedRisk = Number(currentSessionRisk || 0) + contributionFor(decision, risk);
  if (projectedRisk > Number(policy.runtime_risk_budget || 100) && decision === "allow") {
    addRisk(18, "risk-budget", "Session risk budget would be exceeded.");
    decision = "approval";
  }

  if (!reasons.length) {
    controls.push("mission_scope", "tool_allowlist", "data_boundary", "risk_budget");
    reasons.push({
      code: "mission-aligned",
      message: "Action is aligned with the mission capsule, tool scope, data boundary, and risk budget."
    });
  }

  return {
    decision,
    severity: severityFor(risk, decision),
    risk_score: Math.min(100, risk),
    risk_contribution: contributionFor(decision, risk),
    action_descriptor: action || null,
    matched_contract_id: matchedContract?.id || null,
    reasons,
    controls,
    required_action: requiredActionFor(decision),
    safe_to_execute: decision === "allow" || decision === "redact"
  };

  function addRisk(points, code, message) {
    risk += points;
    controls.push(code);
    reasons.push({ code, message });
  }
}

function stronger(current, candidate) {
  const rank = {
    allow: 0,
    redact: 1,
    quarantine_context: 2,
    approval: 3,
    pause_session: 4,
    block: 5
  };
  return rank[candidate] > rank[current] ? candidate : current;
}

function contributionFor(decision, risk) {
  if (decision === "block") {
    return Math.max(3, Math.round(risk / 12));
  }
  if (decision === "approval" || decision === "quarantine_context") {
    return Math.max(3, Math.round(risk / 4));
  }
  return Math.max(3, Math.round(risk / 3));
}

function severityFor(risk, decision) {
  if (decision === "block" || risk >= 85) {
    return "critical";
  }
  if (decision === "approval" || risk >= 60) {
    return "high";
  }
  if (decision === "quarantine_context" || risk >= 35) {
    return "medium";
  }
  return "low";
}

function requiredActionFor(decision) {
  return {
    allow: "execute_tool_call",
    redact: "redact_sensitive_fields_then_execute",
    quarantine_context: "isolate_untrusted_context_and_replan",
    approval: "route_to_human_approver",
    pause_session: "pause_agent_session",
    block: "deny_before_execution"
  }[decision];
}
