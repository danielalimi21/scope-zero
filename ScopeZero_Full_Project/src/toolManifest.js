const VALID_OPERATIONS = new Set([
  "read",
  "search",
  "draft",
  "write",
  "external_send",
  "export",
  "privilege_change",
  "payment",
  "delegate",
  "execute"
]);

const VALID_DATA_CLASSES = new Set(["public", "internal", "confidential", "restricted"]);

export const BUILTIN_TOOL_MANIFESTS = [
  {
    tool_id: "drive.search",
    operation: "search",
    action_type: "read",
    data_in_classes: ["public", "internal", "confidential"],
    data_out_classes: ["public", "internal", "confidential"],
    external_capable: false,
    mutating: false,
    irreversible: false,
    requires_approval_default: false
  },
  {
    tool_id: "drive.read",
    operation: "read",
    action_type: "read",
    data_in_classes: ["public", "internal", "confidential"],
    data_out_classes: ["public", "internal", "confidential"],
    external_capable: false,
    mutating: false,
    irreversible: false,
    requires_approval_default: false
  },
  {
    tool_id: "sheets.export",
    operation: "export",
    action_type: "export",
    data_in_classes: ["public", "internal", "confidential", "restricted"],
    data_out_classes: ["public", "internal", "confidential", "restricted"],
    external_capable: true,
    mutating: false,
    irreversible: false,
    requires_approval_default: true
  },
  {
    tool_id: "gmail.send",
    operation: "external_send",
    action_type: "external_send",
    data_in_classes: ["public", "internal", "confidential", "restricted"],
    data_out_classes: ["public", "internal", "confidential", "restricted"],
    external_capable: true,
    mutating: true,
    irreversible: true,
    requires_approval_default: true
  },
  {
    tool_id: "servicenow.case",
    operation: "write",
    action_type: "write",
    data_in_classes: ["public", "internal", "confidential"],
    data_out_classes: ["public", "internal", "confidential"],
    external_capable: false,
    mutating: true,
    irreversible: false,
    requires_approval_default: false
  },
  {
    tool_id: "slack.draft",
    operation: "draft",
    action_type: "draft",
    data_in_classes: ["public", "internal", "confidential"],
    data_out_classes: ["public", "internal", "confidential"],
    external_capable: false,
    mutating: true,
    irreversible: false,
    requires_approval_default: false
  },
  {
    tool_id: "github.pr",
    operation: "write",
    action_type: "write",
    data_in_classes: ["public", "internal", "confidential"],
    data_out_classes: ["public", "internal", "confidential"],
    external_capable: false,
    mutating: true,
    irreversible: false,
    requires_approval_default: false
  },
  {
    tool_id: "aws.iam.attachPolicy",
    operation: "privilege_change",
    action_type: "privilege_change",
    data_in_classes: ["public", "internal", "confidential", "restricted"],
    data_out_classes: ["internal", "confidential", "restricted"],
    external_capable: false,
    mutating: true,
    irreversible: true,
    requires_approval_default: true
  }
].map(normalizeToolManifest);

export function builtInToolManifestMap() {
  return new Map(BUILTIN_TOOL_MANIFESTS.map((manifest) => [manifest.tool_id, manifest]));
}

export function normalizeToolManifest(input = {}) {
  const toolId = String(input.tool_id || input.name || "").trim();
  if (!toolId) {
    throw new Error("Tool manifest requires tool_id.");
  }

  const operation = normalizeOperation(input.operation || "execute");
  const actionType = normalizeOperation(input.action_type || operation);
  return Object.freeze({
    schema: input.schema || "scopezero.tool_manifest.v1",
    tool_id: toolId,
    operation,
    action_type: actionType,
    data_in_classes: normalizeDataClasses(input.data_in_classes || ["public", "internal"]),
    data_out_classes: normalizeDataClasses(input.data_out_classes || input.data_in_classes || ["public", "internal"]),
    external_capable: Boolean(input.external_capable),
    mutating: Boolean(input.mutating),
    irreversible: Boolean(input.irreversible),
    requires_approval_default: Boolean(input.requires_approval_default),
    destinations: Array.isArray(input.destinations) ? input.destinations.map((value) => String(value).toLowerCase()) : []
  });
}

export function resolveToolManifest(tool, ...sources) {
  const toolId = String(tool || "");
  for (const source of sources) {
    if (!source) {
      continue;
    }
    const manifest = resolveFromSource(toolId, source);
    if (manifest) {
      return normalizeToolManifest(manifest);
    }
  }
  return builtInToolManifestMap().get(toolId) || null;
}

function resolveFromSource(toolId, source) {
  if (source instanceof Map) {
    return source.get(toolId);
  }
  if (Array.isArray(source)) {
    return source.find((manifest) => manifest?.tool_id === toolId || manifest?.name === toolId);
  }
  if (typeof source === "object") {
    if (source.tool_id || source.name) {
      return source.tool_id === toolId || source.name === toolId ? source : null;
    }
    return source[toolId] || null;
  }
  return null;
}

function normalizeOperation(value) {
  const operation = String(value || "").trim().toLowerCase();
  if (!VALID_OPERATIONS.has(operation)) {
    throw new Error(`Unsupported tool manifest operation: ${operation || "(empty)"}.`);
  }
  return operation;
}

function normalizeDataClasses(values) {
  const normalized = values.map((value) => String(value).trim().toLowerCase()).filter(Boolean);
  const invalid = normalized.find((value) => !VALID_DATA_CLASSES.has(value));
  if (invalid) {
    throw new Error(`Unsupported tool manifest data class: ${invalid}.`);
  }
  return [...new Set(normalized)];
}
