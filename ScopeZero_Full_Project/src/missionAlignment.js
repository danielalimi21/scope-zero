const HIGH_IMPACT_OPERATIONS = new Set(["external_send", "export", "privilege_change", "payment", "delegate"]);
const EXTERNAL_INTENT_TERMS = new Set(["send", "share", "email", "external", "publish", "forward", "notify", "slack", "message"]);
const EXPORT_INTENT_TERMS = new Set(["export", "download", "extract", "archive", "dump"]);
const PRIVILEGE_INTENT_TERMS = new Set(["admin", "iam", "role", "policy", "permission", "privilege", "access"]);

const STOP_WORDS = new Set([
  "a",
  "an",
  "and",
  "are",
  "as",
  "at",
  "be",
  "by",
  "for",
  "from",
  "in",
  "into",
  "is",
  "of",
  "on",
  "or",
  "the",
  "to",
  "with"
]);

export function evaluateMissionAlignment({ mission = {}, action = {}, request = {} } = {}) {
  const objective = String(mission.objective || "");
  if (!objective.trim()) {
    return {
      aligned: true,
      score: 1,
      source: "server_deterministic",
      reasons: ["mission-objective-missing"]
    };
  }

  const objectiveTokens = tokenize(objective);
  const actionText = [
    action.action,
    action.tool,
    action.operation,
    action.action_type,
    action.resource,
    action.destination?.address,
    request.payload?.title,
    request.payload?.summary,
    request.payload?.text,
    request.payload?.query
  ].filter(Boolean).join(" ");
  const actionTokens = tokenize(actionText);
  const overlap = intersectionCount(objectiveTokens, actionTokens);
  const score = objectiveTokens.size ? overlap / objectiveTokens.size : 1;
  const reasons = [];

  if (action.destination?.external && !hasAny(objectiveTokens, EXTERNAL_INTENT_TERMS)) {
    reasons.push("external-destination-not-in-objective");
  }
  if (action.operation === "external_send" && !hasAny(objectiveTokens, EXTERNAL_INTENT_TERMS)) {
    reasons.push("external-send-not-in-objective");
  }
  if (action.operation === "export" && !hasAny(objectiveTokens, EXPORT_INTENT_TERMS)) {
    reasons.push("export-not-in-objective");
  }
  if (action.operation === "privilege_change" && !hasAny(objectiveTokens, PRIVILEGE_INTENT_TERMS)) {
    reasons.push("privilege-change-not-in-objective");
  }
  if (HIGH_IMPACT_OPERATIONS.has(action.operation) && score < 0.12) {
    reasons.push("high-impact-low-objective-overlap");
  }
  if (!HIGH_IMPACT_OPERATIONS.has(action.operation) && score < 0.08 && objectiveTokens.size >= 4) {
    reasons.push("low-objective-overlap");
  }

  return {
    aligned: reasons.length === 0,
    score: Number(score.toFixed(3)),
    source: "server_deterministic",
    reasons,
    objective_terms: [...objectiveTokens].sort(),
    action_terms: [...actionTokens].sort().slice(0, 30)
  };
}

function tokenize(value) {
  return new Set(
    String(value)
      .toLowerCase()
      .replace(/[^a-z0-9._-]+/g, " ")
      .split(/\s+/)
      .map((token) => token.trim())
      .filter((token) => token.length >= 3 && !STOP_WORDS.has(token))
  );
}

function intersectionCount(left, right) {
  let count = 0;
  for (const item of left) {
    if (right.has(item)) {
      count += 1;
    }
  }
  return count;
}

function hasAny(tokens, candidates) {
  for (const candidate of candidates) {
    if (tokens.has(candidate)) {
      return true;
    }
  }
  return false;
}
