import { resolveToolManifest } from "./toolManifest.js";

const DATA_CLASS_RANK = {
  public: 1,
  internal: 2,
  confidential: 4,
  restricted: 5
};

const OPERATION_HINTS = [
  ["external_send", /\b(send|email|post|publish|share|transmit|forward)\b/i],
  ["export", /\b(export|download|extract|dump|archive)\b/i],
  ["privilege_change", /\b(admin|administrator|iam|role|policy|permission|privilege|attachpolicy)\b/i],
  ["payment", /\b(pay|payment|transfer|wire|invoice|bank)\b/i],
  ["delegate", /\b(spawn|delegate|sub-agent|subagent|handoff)\b/i],
  ["write", /\b(write|update|modify|create|delete|merge|commit|deploy)\b/i],
  ["draft", /\b(draft|summarize|summary|prepare)\b/i],
  ["read", /\b(read|search|scan|find|retrieve|list)\b/i]
];

const HIGH_IMPACT_TYPES = new Set(["external_send", "export", "privilege_change", "payment", "delegate"]);

export function buildDefaultActionContracts(input = {}) {
  const allowedTools = input.allowed_tools || [];
  const allowedDataClasses = input.allowed_data_classes || ["public", "internal"];
  const allowedDestinations = input.allowed_destinations || [];
  return allowedTools.map((tool) => {
    const manifest = resolveToolManifest(tool, input.tool_manifests);
    const operation = manifest?.operation || inferOperation({ tool, action: tool });
    return {
      id: `contract.${tool.replace(/[^a-z0-9]+/gi, ".").replace(/^\.+|\.+$/g, "")}`,
      tools: [tool],
      operations: operationsForTool(tool, operation, manifest),
      data_classes: allowedDataClasses,
      destinations: allowedDestinations.length ? allowedDestinations : manifest?.destinations || [],
      max_delegation_depth: Number(input.max_delegation_depth ?? 1),
      effect: manifest?.requires_approval_default || HIGH_IMPACT_TYPES.has(operation) ? "approval" : "allow",
      tool_manifest_id: manifest?.tool_id || null
    };
  });
}

export function describeActionRequest(request = {}, classification = { label: "public" }, policy = {}, manifestSource = null) {
  const tool = String(request.tool || "unknown.tool");
  const action = String(request.action || request.operation || "unspecified action");
  const destination = normalizeDestination(request.destination || {});
  const toolManifest = resolveToolManifest(tool, manifestSource, request.tool_manifest, policy.tool_manifests);
  const operation = String(toolManifest?.operation || request.operation || inferOperation({ tool, action })).toLowerCase();
  const actionType = String(toolManifest?.action_type || request.action_type || classifyActionType({ operation, tool, action, destination, manifest: toolManifest })).toLowerCase();
  const dataClass = String(request.data_class || classification.label || "public").toLowerCase();

  return {
    schema: policy.evidence_schema || "scopezero.action_authorization.v1",
    tool,
    action,
    operation,
    operation_source: toolManifest ? "tool_manifest" : (request.operation ? "request" : "fallback_inference"),
    claimed_operation: request.operation ? String(request.operation).toLowerCase() : null,
    action_type: actionType,
    vendor: tool.includes(".") ? tool.split(".")[0] : "custom",
    resource: request.resource || request.payload?.file || request.payload?.query || request.payload?.id || null,
    data_class: dataClass,
    data_rank: dataClassRank(dataClass),
    destination,
    delegation_depth: Number(request.delegation_depth || 0),
    money: request.money || null,
    privilege: request.privilege || null,
    tool_manifest: toolManifest ? {
      tool_id: toolManifest.tool_id,
      operation: toolManifest.operation,
      action_type: toolManifest.action_type,
      data_in_classes: toolManifest.data_in_classes,
      data_out_classes: toolManifest.data_out_classes,
      external_capable: toolManifest.external_capable,
      mutating: toolManifest.mutating,
      irreversible: toolManifest.irreversible,
      requires_approval_default: toolManifest.requires_approval_default
    } : null
  };
}

export function evaluateActionContract({ mission, action, externalDestination }) {
  const contracts = mission?.action_contracts || [];
  if (!contracts.length) {
    return {
      ok: false,
      code: "missing-action-contract",
      message: "Mission capsule does not include vendor-neutral action contracts."
    };
  }

  const toolCandidates = contracts.filter((contract) => listMatches(contract.tools, action.tool));
  if (!toolCandidates.length) {
    return {
      ok: false,
      code: "tool-not-contracted",
      message: `Tool ${action.tool} has no mission action contract.`
    };
  }

  const operationCandidates = toolCandidates.filter((contract) => listMatches(contract.operations, action.operation));
  if (!operationCandidates.length) {
    return {
      ok: false,
      code: "operation-not-contracted",
      message: `Operation ${action.operation} is not allowed for ${action.tool}.`
    };
  }

  const dataCandidates = operationCandidates.filter((contract) => dataClassAllowed(contract.data_classes, action.data_class));
  if (!dataCandidates.length) {
    return {
      ok: false,
      code: "data-class-not-contracted",
      message: `Data class ${action.data_class} is outside the action contract.`
    };
  }

  const destinationCandidates = dataCandidates.filter((contract) => {
    if (!action.destination.address) {
      return true;
    }
    return destinationAllowed(contract.destinations, action.destination.address, externalDestination);
  });

  if (!destinationCandidates.length) {
    return {
      ok: false,
      code: "destination-not-contracted",
      message: `Destination ${action.destination.address} is outside the action contract.`
    };
  }

  const contract = destinationCandidates[0];
  return {
    ok: true,
    code: "action-contract-match",
    message: `Action matched ${contract.id}.`,
    contract
  };
}

export function dataClassAllowed(allowed = [], requested = "public") {
  if (!allowed.length) {
    return true;
  }
  const maxAllowed = Math.max(...allowed.map(dataClassRank));
  return dataClassRank(requested) <= maxAllowed;
}

export function destinationAllowed(allowed = [], address = "", externalDestination = false) {
  if (!address) {
    return true;
  }
  if (!allowed.length) {
    return !externalDestination;
  }
  return allowed.some((candidate) => destinationMatches(candidate, address));
}

export function dataClassRank(label = "public") {
  return DATA_CLASS_RANK[String(label).toLowerCase()] || 1;
}

function inferOperation({ tool = "", action = "" }) {
  const text = `${tool} ${action}`;
  const matched = OPERATION_HINTS.find(([, pattern]) => pattern.test(text));
  return matched ? matched[0] : "execute";
}

function classifyActionType({ operation, tool, action, destination, manifest }) {
  if (operation === "external_send" || destination.external) {
    return "external_send";
  }
  if (operation === "export") {
    return "export";
  }
  if (operation === "privilege_change") {
    return "privilege_change";
  }
  if (operation === "payment") {
    return "payment";
  }
  if (operation === "delegate") {
    return "delegate";
  }
  if (manifest?.irreversible && manifest?.mutating) {
    return "privilege_change";
  }
  if (/\b(secret|token|key|credential)\b/i.test(`${tool} ${action}`)) {
    return "credential_access";
  }
  return operation;
}

function operationsForTool(tool, inferred, manifest = null) {
  if (manifest) {
    return [...new Set([manifest.operation, manifest.action_type, "execute"])];
  }
  if (/search|scan|read|list/i.test(tool)) {
    return ["read", "search", "execute"];
  }
  if (/draft|summary|slack|case/i.test(tool)) {
    return ["draft", "write", "execute"];
  }
  if (/pr|pull|github/i.test(tool)) {
    return ["write", "draft", "execute"];
  }
  if (/export/i.test(tool)) {
    return ["export"];
  }
  return [...new Set([inferred, "execute"])];
}

function normalizeDestination(destination = {}) {
  const address = String(destination.address || destination.url || destination.host || destination.name || "").toLowerCase();
  return {
    type: destination.type || (address.includes("@") ? "email" : destination.url ? "url" : "resource"),
    address,
    external: Boolean(destination.external)
  };
}

function listMatches(values = [], requested = "") {
  if (!values.length) {
    return true;
  }
  return values.some((value) => wildcardMatches(String(value).toLowerCase(), String(requested).toLowerCase()));
}

function destinationMatches(candidate, address) {
  const normalizedCandidate = String(candidate).toLowerCase();
  const normalizedAddress = String(address).toLowerCase();
  return wildcardMatches(normalizedCandidate, normalizedAddress) || normalizedAddress.endsWith(normalizedCandidate);
}

function wildcardMatches(pattern, value) {
  if (pattern === "*" || pattern === value) {
    return true;
  }
  if (!pattern.includes("*")) {
    return false;
  }
  const escaped = pattern.replace(/[.+?^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*");
  return new RegExp(`^${escaped}$`).test(value);
}
