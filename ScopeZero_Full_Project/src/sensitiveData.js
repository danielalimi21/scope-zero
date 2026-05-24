const LEVELS = {
  public: 1,
  internal: 2,
  confidential: 4,
  restricted: 5
};

const FINDERS = [
  { code: "api_secret", level: 5, pattern: /\b(api[_-]?key|secret|token|private[_-]?key)\b/i },
  { code: "payment_or_bank", level: 5, pattern: /\b(iban|swift|routing number|bank account|credit card)\b/i },
  { code: "payroll", level: 5, pattern: /\b(payroll|salary|compensation|bonus)\b/i },
  { code: "customer_revenue", level: 5, pattern: /\b(customer revenue|revenue by customer|arr|mrr|invoice total)\b/i },
  { code: "confidential_marker", level: 4, pattern: /\b(confidential|restricted|privileged|attorney-client)\b/i },
  { code: "personal_data", level: 4, pattern: /\b(ssn|passport|date of birth|medical record|patient)\b/i },
  { code: "email_address", level: 2, pattern: /[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/i }
];

export function classifyPayload(payload = {}) {
  const text = typeof payload === "string" ? payload : JSON.stringify(payload);
  const explicit = String(payload.classification || payload.data_classification || "").toLowerCase();
  let level = LEVELS[explicit] || 1;
  const findings = [];

  for (const finder of FINDERS) {
    if (finder.pattern.test(text)) {
      findings.push(finder.code);
      level = Math.max(level, finder.level);
    }
  }

  return {
    level,
    label: labelForLevel(level),
    findings: [...new Set(findings)]
  };
}

export function detectPromptInfluence(context = {}, policy = {}) {
  const fragments = [
    context.prompt,
    context.source_text,
    context.tool_output,
    context.document_text,
    context.instruction
  ]
    .filter(Boolean)
    .join("\n")
    .toLowerCase();

  const patterns = policy.blocked_prompt_patterns || [];
  const matched = patterns.filter((pattern) => fragments.includes(String(pattern).toLowerCase()));

  return {
    influenced: Boolean(context.prompt_influenced || matched.length),
    origin: context.influence_origin || context.origin || "unknown",
    matched_patterns: matched
  };
}

export function isExternalDestination(destination = {}, policy = {}) {
  if (typeof destination.external === "boolean") {
    return destination.external;
  }

  const target = String(destination.address || destination.url || destination.host || "").toLowerCase();
  if (!target) {
    return false;
  }

  return !(policy.trusted_destinations || []).some((trusted) => target.endsWith(String(trusted).toLowerCase()));
}

function labelForLevel(level) {
  if (level >= 5) {
    return "restricted";
  }
  if (level >= 4) {
    return "confidential";
  }
  if (level >= 2) {
    return "internal";
  }
  return "public";
}
