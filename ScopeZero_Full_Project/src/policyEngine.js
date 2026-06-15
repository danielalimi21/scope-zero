import { dataClassAllowed, dataClassRank, destinationAllowed, evaluateActionContract } from "./actionAuthorization.js";

export function evaluatePolicy({ request, mission, agent, policy, classification, promptInfluence, missionAlignment, externalDestination, currentSessionRisk, sessionIngestedClassRank = 0 }) {
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

  // Lexical mission-alignment is an ADVISORY heuristic (keyword overlap), not a
  // sound control: it can be gamed by padding the action with objective terms and
  // it can false-positive. A drift signal therefore routes to a human approver —
  // it never silently blocks on its own. The deterministic contract gates above
  // (tool / operation / data-class / destination) are what actually block.
  if (policy.mission_lock && missionAlignment?.aligned === false) {
    addRisk(20, "intent-drift-advisory", `Lexical mission-alignment flagged possible drift (advisory): ${missionAlignment.reasons.join(", ")}.`);
    decision = stronger(decision, "approval");
  } else if (policy.mission_lock && !missionAlignment && request.context?.mission_aligned === false) {
    addRisk(20, "intent-drift-self-reported", "Agent self-reported mission drift (advisory); routing to human approver.");
    decision = stronger(decision, "approval");
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

  // Egress is checked against the BYTES, not the tool's self-declared manifest. A
  // manifest's data_out_classes is a CEILING that must hold against the actual
  // payload — never a flag that skips the check. This closes exfiltration to an
  // in-contract host through ANY tool, manifested or not, because a prompt-injected
  // agent picks the tool and would otherwise just pick the one with the friendliest
  // manifest.
  if (policy.unknown_egress_requires_approval && externalDestination && hasMeaningfulPayload(request)) {
    const manifestOutRank = manifestMaxOutRank(action);

    // (1) Ceiling violation: the payload classified HIGHER than the tool's declared
    // output class. The manifest's promise is contradicted by the bytes, so the tool
    // is either mis-declared or being abused as an exfil channel — route to a human.
    if (manifestOutRank !== null && classification.level > manifestOutRank && decision !== "block") {
      addRisk(30, "manifest-output-class-exceeded", `Outbound ${classification.label} content exceeds the declared output ceiling (${rankLabel(manifestOutRank)}) for ${action.tool}; the manifest is contradicted by the payload.`);
      decision = stronger(decision, "approval");
    }

    // (2) Unknown/opaque egress: the data class could not be POSITIVELY established
    // as public from the bytes (keyword classifier found nothing AND the payload has
    // a bulk/tabular/encoded/large shape). A manifest declaring "public" does not
    // override opaque bytes. Treat a missing `established` flag as not-established
    // (fail closed). Route to a human rather than trusting it as public.
    else if (classification.level <= 1 && classification.established !== true && decision === "allow") {
      const shape = classification.egress_shape ? ` (payload shape: ${classification.egress_shape})` : "";
      addRisk(16, "unverified-egress-class", `Outbound content has no positively established data class (keyword classifier found nothing; class not established from the bytes)${shape}. Routing to human review rather than trusting it as public.`);
      decision = "approval";
    }
  }

  // Ingest-taint / laundering guard. You cannot inspect laundered bytes — content
  // read as confidential and rewritten by the model into benign-looking prose
  // leaves looking benign. So judge egress by what the SESSION has been exposed to,
  // not just the outbound bytes: when the session has ingested data at or above the
  // taint block level and is now sending lower-classed content to an external
  // destination (a possible downgrade/launder), route to a human. Egress at or
  // above the ingested class is already governed by the data-class/destination
  // gates, so this fires only on the downgrade case.
  if (
    policy.sensitive_ingest_egress_guard &&
    externalDestination &&
    hasMeaningfulPayload(request) &&
    Number(sessionIngestedClassRank || 0) >= Number(policy.ingest_taint_block_level || 4) &&
    classification.level < Number(sessionIngestedClassRank || 0) &&
    decision === "allow"
  ) {
    addRisk(24, "tainted-session-egress", `Session has ingested ${rankLabel(sessionIngestedClassRank)} data; outbound ${classification.label} content to an external destination could be laundered. Routing to human review.`);
    decision = "approval";
  }

  // Sensitive-mission egress seal (opt-in, posture-based). Taint and shape only
  // catch laundering the gateway can SEE — the ingest crossed ScopeZero, or the
  // bytes carry a dump shape. Neither catches a low-volume secret the model read
  // out-of-band and rewrote into benign prose: those bytes classify as
  // "established public", so establishment cannot be the all-clear here. When a
  // mission is explicitly cleared to handle confidential/restricted data, this
  // seals ALL of its meaningful external egress to human review — the only sound
  // posture once we accept that benign-looking bytes may be laundered. The
  // mission's data clearance is the trigger, so it closes the "gateway never saw
  // the read" gap at the cost of an approval on each external post. Off by default;
  // turned on per-tenant for high-assurance missions. A contract may still mark a
  // specific destination as a public-broadcast sink to keep that lane autonomous.
  if (
    policy.seal_sensitive_mission_egress &&
    externalDestination &&
    hasMeaningfulPayload(request) &&
    missionHandlesSensitiveData(mission) &&
    !destinationIsPublicSink(mission, action) &&
    decision === "allow"
  ) {
    addRisk(22, "sensitive-mission-egress-sealed", `Mission is cleared for ${rankLabel(maxMissionClassRank(mission))} data; external egress is sealed to human review (benign-looking bytes may be laundered confidential content). Mark a destination as a public-broadcast sink in the contract to keep it autonomous.`);
    decision = "approval";
  }

  // Fail-closed egress, decoupled from the mission's data clearance (default ON).
  // The byte classifier and ingest-taint only catch what the gateway can SEE; a
  // secret read out-of-band and laundered into benign prose is invisible to both —
  // those bytes classify as "established public". A mission scoped to public/internal
  // can still launder out-of-band material, so clearance is NOT a safe trigger:
  // narrowing a mission must not REDUCE its egress protection. So by default every
  // meaningful external egress that is not to a contract-declared public-broadcast
  // sink is held for human review. This is the honest containment posture — autonomy
  // on an external lane is an explicit, auditable opt-in (public_egress_ok in the
  // contract, or the mission's public_egress_destinations), not the default.
  if (
    policy.seal_external_egress &&
    externalDestination &&
    hasMeaningfulPayload(request) &&
    !destinationIsPublicSink(mission, action) &&
    decision === "allow"
  ) {
    addRisk(22, "external-egress-sealed", `External egress to ${action?.destination?.address || "an external destination"} is sealed to human review by default. Declare it a public-broadcast sink (public_egress_ok in the mission contract, or public_egress_destinations) to keep this lane autonomous.`);
    decision = "approval";
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

  // No authoritative tool manifest means the operation/action_type for this tool
  // was inferred from the agent's self-declared input — not ground truth. For a
  // high-impact action that's not safe to take on the agent's word, so escalate
  // rather than silently trust it.
  if (
    policy.require_manifest_for_high_impact &&
    action &&
    !action.tool_manifest &&
    (policy.high_impact_action_types || []).includes(action.action_type) &&
    decision !== "block"
  ) {
    addRisk(20, "unmanifested-high-impact", `No authoritative manifest for ${action.tool}; high-impact action is inferred from self-declared input.`);
    decision = stronger(decision, "approval");
  }

  // Same principle, widened to any MUTATING operation (write/create/update/delete/
  // deploy). Without an authoritative manifest the operation is whatever the agent
  // said it was, so a state-changing call on the agent's own word escalates rather
  // than executing silently. Read-only inferred operations stay autonomous.
  if (
    policy.require_manifest_for_mutating &&
    action &&
    !action.tool_manifest &&
    (policy.mutating_operations || []).includes(action.operation) &&
    !(policy.high_impact_action_types || []).includes(action.action_type) &&
    decision !== "block"
  ) {
    addRisk(14, "unmanifested-mutation", `No authoritative manifest for ${action.tool}; mutating operation "${action.operation}" is inferred from self-declared input.`);
    decision = stronger(decision, "approval");
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

// Highest data class the tool's manifest declares it ever emits, as a numeric
// rank, or null when the tool has no manifest-declared output class. Used as the
// egress ceiling the actual payload is checked against.
function manifestMaxOutRank(action) {
  const classes = action?.tool_manifest?.data_out_classes;
  if (!Array.isArray(classes) || !classes.length) {
    return null;
  }
  return Math.max(...classes.map(dataClassRank));
}

// Highest data class the mission is cleared to handle, as a numeric rank.
function maxMissionClassRank(mission) {
  const classes = mission?.allowed_data_classes;
  if (!Array.isArray(classes) || !classes.length) {
    return 0;
  }
  return Math.max(...classes.map(dataClassRank));
}

// A mission cleared for confidential (rank 4) or higher data.
function missionHandlesSensitiveData(mission) {
  return maxMissionClassRank(mission) >= 4;
}

// An action contract may flag a destination as an intentional public-broadcast
// sink (public_egress_ok / public_sink: true) — e.g. a status page the mission is
// explicitly meant to post to. Egress to such a destination stays autonomous even
// under the seal; everything else on a sensitive mission is held for review.
function destinationIsPublicSink(mission, action) {
  const address = action?.destination?.address;
  if (!address) {
    return false;
  }
  const addr = String(address).toLowerCase();
  const matches = (d) => {
    const norm = String(d).toLowerCase();
    return norm === "*" || norm === addr || addr.endsWith(norm);
  };
  // Mission-level declaration: a flat list of destinations the mission may post to
  // autonomously. Ergonomic alternative to flagging each contract.
  const missionSinks = mission?.public_egress_destinations || [];
  if (missionSinks.some(matches)) {
    return true;
  }
  const contracts = mission?.action_contracts || [];
  return contracts.some((contract) => {
    if (contract.public_egress_ok !== true && contract.public_sink !== true) {
      return false;
    }
    return (contract.destinations || []).some(matches);
  });
}

function rankLabel(rank) {
  if (rank >= 5) return "restricted";
  if (rank >= 4) return "confidential";
  if (rank >= 2) return "internal";
  return "public";
}

// Does the request carry outbound content worth classifying? Used so the
// unknown-egress control fires on real payloads, not on empty/metadata-only calls.
function hasMeaningfulPayload(request) {
  const payload = request?.payload;
  if (!payload) {
    return false;
  }
  if (typeof payload === "string") {
    return payload.trim().length > 0;
  }
  const contentFields = ["text", "summary", "title", "query", "body", "content", "data", "file", "rows", "records", "attachments"];
  return contentFields.some((field) => {
    const value = payload[field];
    if (value == null) {
      return false;
    }
    if (typeof value === "string") {
      return value.trim().length > 0;
    }
    if (Array.isArray(value)) {
      return value.length > 0;
    }
    return true;
  });
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
