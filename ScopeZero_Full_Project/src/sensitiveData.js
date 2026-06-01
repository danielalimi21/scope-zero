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

const PROMPT_INFLUENCE_SIGNALS = [
  { code: "instruction_override", weight: 38, pattern: /\b(ignore|forget|disregard|override)\b.{0,40}\b(previous|prior|above|system|developer|policy|instructions?)\b/i },
  { code: "policy_bypass", weight: 42, pattern: /\b(bypass|disable|turn off|remove|ignore)\b.{0,40}\b(policy|guardrails?|safety|authorization|approval|scopezero)\b/i },
  { code: "secret_exfiltration", weight: 45, pattern: /\b(reveal|print|show|send|exfiltrate|leak)\b.{0,50}\b(system prompt|secret|token|api key|credential|private key)\b/i },
  { code: "external_exfiltration", weight: 40, pattern: /\b(send|forward|post|upload|transmit|share)\b.{0,60}\b(external|outside|personal email|gmail|pastebin|webhook|telegram|slack)\b/i },
  { code: "concealment", weight: 40, pattern: /\b(do not|don't|never)\b.{0,40}\b(tell|log|audit|record|report|mention)\b/i },
  { code: "roleplay_authority", weight: 20, pattern: /\b(system administrator|security admin|developer mode|root user|authorized auditor)\b/i }
];

const LEETSPEAK = new Map([
  ["0", "o"],
  ["1", "i"],
  ["3", "e"],
  ["4", "a"],
  ["5", "s"],
  ["7", "t"],
  ["@", "a"],
  ["$", "s"]
]);

// Cyrillic/Greek lookalikes folded to their Latin twin so homoglyph attacks
// ("іgnоrе prеvіоus" with Cyrillic chars) normalize to the same text a regex
// sees for plain ASCII. Keys are lowercase (folding runs after toLowerCase).
const HOMOGLYPHS = new Map([
  // Cyrillic
  ["а", "a"], ["в", "b"], ["с", "c"], ["е", "e"], ["н", "h"], ["і", "i"], ["ј", "j"],
  ["к", "k"], ["м", "m"], ["о", "o"], ["р", "p"], ["ѕ", "s"], ["т", "t"], ["у", "y"],
  ["х", "x"], ["ԁ", "d"], ["ё", "e"],
  // Greek
  ["α", "a"], ["ε", "e"], ["ι", "i"], ["κ", "k"], ["μ", "m"], ["ν", "v"], ["ο", "o"],
  ["ρ", "p"], ["σ", "o"], ["τ", "t"], ["υ", "u"], ["χ", "x"]
]);
const HOMOGLYPH_RE = new RegExp(`[${[...HOMOGLYPHS.keys()].join("")}]`, "g");

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
  const rawFragments = [
    context.prompt,
    context.source_text,
    context.tool_output,
    context.document_text,
    context.instruction
  ]
    .filter(Boolean)
    .join("\n");
  const baseCandidates = [normalizePromptText(rawFragments), ...decodeLikelyBase64(rawFragments).map(normalizePromptText)].filter(Boolean);
  // depunct: in-word separators removed but word spaces kept ("ig.no.re all" →
  // "ignore all"), so boundary-anchored signals still fire on punctuation-split
  // text. dense: all separators removed, for the configured phrase list against
  // fully spaced/punctuated obfuscation.
  const depunctCandidates = baseCandidates.map(depunctForm);
  const denseCandidates = baseCandidates.map(denseForm);
  const candidates = [...baseCandidates, ...depunctCandidates];

  const patterns = policy.blocked_prompt_patterns || [];
  const matched = [];
  let score = context.prompt_influenced ? 50 : 0;

  for (const pattern of patterns) {
    const normalized = normalizePromptText(String(pattern));
    const dense = denseForm(normalized);
    const hit =
      candidates.some((candidate) => candidate.includes(normalized)) ||
      (dense && denseCandidates.some((candidate) => candidate.includes(dense)));
    if (hit) {
      matched.push({
        code: "configured_pattern",
        pattern,
        weight: 40
      });
      score += 40;
    }
  }

  for (const signal of PROMPT_INFLUENCE_SIGNALS) {
    if (candidates.some((candidate) => signal.pattern.test(candidate))) {
      matched.push({
        code: signal.code,
        pattern: signal.pattern.source,
        weight: signal.weight
      });
      score += signal.weight;
    }
  }

  const uniqueMatched = dedupeMatches(matched);
  const threshold = Number(policy.prompt_influence_threshold || 40);

  return {
    influenced: score >= threshold,
    origin: context.influence_origin || context.origin || "unknown",
    matched_patterns: uniqueMatched.map((match) => match.pattern),
    signals: uniqueMatched.map(({ code, weight }) => ({ code, weight })),
    score: Math.min(100, score),
    threshold,
    classifier: "deterministic_prompt_influence_v2"
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

function normalizePromptText(value) {
  const base = String(value || "")
    .toLowerCase()
    .replace(HOMOGLYPH_RE, (char) => HOMOGLYPHS.get(char) || char)
    .replace(/[013457@$]/g, (char) => LEETSPEAK.get(char) || char)
    .replace(/[\u200b-\u200f\u202a-\u202e]/g, "")
    .replace(/[^a-z0-9._/@$-]+/g, " ")
    .replace(/\s+/g, " ")
    .trim();
  return collapseSpacedLetters(base);
}

// Rejoin a run of single characters split by separators ("i g n o r e",
// "i.g.n.o.r.e") back into one token, while leaving real multi-letter words
// untouched. Requires 3+ separated singles, so normal prose isn't affected.
function collapseSpacedLetters(value) {
  return value.replace(/\b(?:[a-z0-9][ ._/-]){2,}[a-z0-9]\b/g, (match) => match.replace(/[ ._/-]/g, ""));
}

function depunctForm(value) {
  return String(value || "").replace(/[._/-]+/g, "");
}

function denseForm(value) {
  return String(value || "").replace(/[^a-z0-9]+/g, "");
}

function decodeLikelyBase64(value) {
  const tokens = String(value || "").match(/[A-Za-z0-9+/=]{16,}/g) || [];
  const decoded = [];
  for (const token of tokens.slice(0, 12)) {
    try {
      const text = Buffer.from(token, "base64").toString("utf8");
      if (/[\x09\x0a\x0d\x20-\x7e]{8,}/.test(text)) {
        decoded.push(text);
      }
    } catch {
      // Ignore malformed base64-looking fragments.
    }
  }
  return decoded;
}

function dedupeMatches(matches) {
  const seen = new Set();
  const deduped = [];
  for (const match of matches) {
    const key = `${match.code}:${match.pattern}`;
    if (!seen.has(key)) {
      seen.add(key);
      deduped.push(match);
    }
  }
  return deduped;
}
