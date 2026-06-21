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

// Value-shape detectors: fire on the STRUCTURE of a sensitive value, with no
// topic keyword nearby. This is what closes "a card number / secret / SSN dropped
// into otherwise-benign prose" — the keyword classifier above is blind to it.
// High-signal credential shapes, chosen for a low false-positive rate (each has a
// distinctive prefix/structure that does not collide with ordinary identifiers).
// We deliberately do NOT match a bare 9-digit run as an SSN: every order number,
// account id, and phone-without-formatting is 9 digits, so it would flag constant
// benign traffic. Keyword-near SSN and the dashed value pattern cover the real case;
// semantic/contextual SSN detection is the external classifier's job.
const SECRET_PREFIX_PATTERNS = [
  /\bAKIA[0-9A-Z]{16}\b/,                                   // AWS access key id
  /\bASIA[0-9A-Z]{16}\b/,                                   // AWS temporary access key id
  /\bghp_[A-Za-z0-9]{36}\b/,                                // GitHub personal access token
  /\bgho_[A-Za-z0-9]{36}\b/,                                // GitHub OAuth token
  /\bghs_[A-Za-z0-9]{36}\b/,                                // GitHub server-to-server token
  /\bgithub_pat_[A-Za-z0-9_]{22,}\b/,                       // GitHub fine-grained PAT
  /\bglpat-[A-Za-z0-9_-]{20,}\b/,                           // GitLab personal access token
  /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/,                       // Slack token
  /\bsk-[A-Za-z0-9]{20,}\b/,                                // OpenAI-style secret key
  /\bsk_live_[A-Za-z0-9]{16,}\b/,                           // Stripe live secret key
  /\brk_live_[A-Za-z0-9]{16,}\b/,                           // Stripe live restricted key
  /\bAIza[0-9A-Za-z_-]{35}\b/,                              // Google API key
  /\bya29\.[0-9A-Za-z_-]{20,}\b/,                           // Google OAuth access token
  /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/, // JWT (header.payload.sig)
  /-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----/               // PEM private key
];

const VALUE_FINDERS = [
  { code: "api_secret", level: 5, detect: (text) => SECRET_PREFIX_PATTERNS.some((re) => re.test(text)) || hasHighEntropyToken(text) },
  { code: "payment_or_bank", level: 5, detect: (text) => hasLuhnCardNumber(text) || /\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b/.test(text) },
  { code: "personal_data", level: 4, detect: (text) => /\b\d{3}-\d{2}-\d{4}\b/.test(text) }
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
  const raw = typeof payload === "string" ? payload : JSON.stringify(payload);
  // Scan the raw bytes AND anything trivially decoded out of them. A base64- or
  // hex-wrapped credential (e.g. an AWS key encoded to dodge the keyword/prefix
  // finders) classifies as opaque "public" otherwise: the prompt-influence path
  // already decodes, so the DLP path must too or the two disagree on the same bytes.
  const decoded = decodeEmbeddedPayloads(raw);
  const text = decoded.length ? `${raw}\n${decoded.join("\n")}` : raw;
  const explicit = String(payload.classification || payload.data_classification || "").toLowerCase();
  let level = LEVELS[explicit] || 1;
  const findings = [];

  for (const finder of FINDERS) {
    if (finder.pattern.test(text)) {
      findings.push(finder.code);
      level = Math.max(level, finder.level);
    }
  }

  // Value-shape detectors run after the keyword finders so a keyword-free secret,
  // card number, or SSN is still classified by its structure alone.
  for (const finder of VALUE_FINDERS) {
    if (finder.detect(text)) {
      findings.push(finder.code);
      level = Math.max(level, finder.level);
    }
  }

  // Whether the data class was POSITIVELY established, not merely "no keyword
  // matched". A keyword hit (level >= 2) positively establishes sensitivity. At
  // level 1 the class is established as public ONLY when the payload also has no
  // bulk/tabular/encoded/large shape — because opaque content carrying no trigger
  // term is an absence of evidence, not evidence of absence. `established` is what
  // the egress gate trusts; a tool manifest cannot override the bytes here.
  const egressShape = analyzeEgressShape(payload);
  const established = level >= 2 ? true : egressShape === null;

  return {
    level,
    label: labelForLevel(level),
    findings: [...new Set(findings)],
    egress_shape: egressShape,
    established
  };
}

// A 13–19 digit run whose digits may be split by ANY common separator — space,
// dash, dot, or non-breaking space ("4012.8888.8888.1881", "4012 8888 8888 1881").
// Luhn validation is the false-positive gate, so the separator set can be liberal
// without flagging ordinary numbers. Closes dot/space-separated card evasion.
function hasLuhnCardNumber(text) {
  const candidates = String(text).match(/\d(?:[ . -]?\d){12,18}/g) || [];
  return candidates.some((candidate) => {
    const digits = candidate.replace(/[ . -]/g, "");
    return digits.length >= 13 && digits.length <= 19 && luhnValid(digits);
  });
}

function luhnValid(digits) {
  let sum = 0;
  let double = false;
  for (let i = digits.length - 1; i >= 0; i -= 1) {
    let value = digits.charCodeAt(i) - 48;
    if (value < 0 || value > 9) {
      return false;
    }
    if (double) {
      value *= 2;
      if (value > 9) value -= 9;
    }
    sum += value;
    double = !double;
  }
  return sum % 10 === 0;
}

// A long, near-random token (high Shannon entropy) that is not a UUID. Catches
// opaque API keys / session tokens that carry no recognizable prefix. Conservative
// length + entropy thresholds keep UUIDs and ordinary identifiers from tripping it.
function hasHighEntropyToken(text) {
  const tokens = String(text).match(/[A-Za-z0-9+/_-]{40,}/g) || [];
  return tokens.some((token) => !/^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$/i.test(token) && shannonEntropy(token) >= 4.6);
}

function shannonEntropy(value) {
  const counts = new Map();
  for (const char of value) {
    counts.set(char, (counts.get(char) || 0) + 1);
  }
  let entropy = 0;
  for (const count of counts.values()) {
    const p = count / value.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

// Combine the deterministic classifier with an optional external classifier
// (embedding / model-graded / commercial DLP) plugged in via `classifierResolver`.
// The merge takes the higher class and unions findings; the external verdict can
// only RAISE establishment (positively classify), never lower it below what the
// bytes already established. This is the seam for non-English / semantic coverage
// the regex classifier can't reach.
export function mergeClassification(base, external) {
  if (!external || typeof external.level !== "number") {
    return base;
  }
  const level = Math.max(base.level, external.level);
  return {
    level,
    label: labelForLevel(level),
    findings: [...new Set([...(base.findings || []), ...(external.findings || [])])],
    egress_shape: base.egress_shape,
    established: base.established === true || external.established === true || external.level >= 2,
    classifier_sources: [...new Set(["deterministic", ...(external.source ? [external.source] : ["external"])])]
  };
}

// ── Outbound-shape analysis ──────────────────────────────────────────────────
// Shape detection, NOT DLP: it asks "could this be a data dump?", not "what
// classification is this?". The keyword classifier is blind to sensitive content
// that carries no trigger term (raw tables, source code, opaque dumps, encoded
// blobs). For egress we must know whether a "public" verdict is a positive
// establishment of the class or merely an absence of evidence — so content with a
// bulk/tabular/encoded/large shape is treated as class-not-established regardless
// of what a tool manifest declares the tool emits. Thresholds are deliberately
// conservative so short status strings and single records stay autonomous.
function analyzeEgressShape(payload) {
  if (payload == null) {
    return null;
  }
  const strings = typeof payload === "string" ? [payload] : collectStrings(payload);
  const joined = strings.join("\n");

  // Bulk array of records in the structured payload (e.g. { rows: [...] }).
  if (Array.isArray(payload)) {
    if (payload.length >= 5) return "bulk_records";
  } else if (typeof payload === "object") {
    for (const value of Object.values(payload)) {
      if (Array.isArray(value) && value.length >= 5) return "bulk_records";
    }
  }

  // Tabular dump: 3+ delimited rows with a uniform field count — columns, not prose.
  if (strings.some(isTabularDump)) {
    return "tabular_dump";
  }

  // Encoded/opaque blob: a long base64 or hex run with no whitespace.
  if (/[A-Za-z0-9+/]{120,}={0,2}/.test(joined) || /\b[0-9a-fA-F]{96,}\b/.test(joined)) {
    return "encoded_blob";
  }

  // Sheer volume: a large opaque body crossing a boundary is not "positively public".
  if (joined.length >= 4096) {
    return "large_body";
  }

  return null;
}

function collectStrings(value, out = []) {
  if (value == null) {
    return out;
  }
  if (typeof value === "string") {
    out.push(value);
  } else if (Array.isArray(value)) {
    value.forEach((item) => collectStrings(item, out));
  } else if (typeof value === "object") {
    Object.values(value).forEach((item) => collectStrings(item, out));
  } else {
    out.push(String(value));
  }
  return out;
}

function isTabularDump(text) {
  const lines = String(text).split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
  if (lines.length < 3) {
    return false;
  }
  const fieldCounts = lines
    .map((line) => Math.max((line.match(/,/g) || []).length, (line.match(/\t/g) || []).length, (line.match(/\|/g) || []).length))
    .filter((count) => count >= 1);
  if (fieldCounts.length < 3 || fieldCounts.length < Math.ceil(lines.length * 0.6)) {
    return false;
  }
  const sorted = [...fieldCounts].sort((a, b) => a - b);
  const mode = sorted[Math.floor(sorted.length / 2)];
  const uniform = fieldCounts.filter((count) => count === mode).length >= Math.ceil(fieldCounts.length * 0.8);
  return uniform;
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

// A caller may ASSERT external=true (raise sensitivity), but may NOT assert
// external=false to suppress the egress guards. "External" is established from the
// destination address against the policy's trusted list; a self-declared
// "internal" flag never overrides an address that isn't trusted. Otherwise a
// prompt-injected agent would just stamp { external: false } on a pastebin write
// to walk every egress control. Fail closed: unknown/unaddressed targets that
// aren't positively trusted are treated as external.
export function isExternalDestination(destination = {}, policy = {}) {
  if (destination.external === true) {
    return true;
  }

  const target = String(destination.address || destination.url || destination.host || "").toLowerCase();
  if (!target) {
    // No address. Trust an explicit internal assertion only when there is nothing
    // to check it against; any positive address is evaluated against the list.
    return false;
  }

  // A destination is internal only if it equals a trusted domain or is a
  // subdomain of one (label boundary). A bare endsWith would treat the
  // attacker-registerable "evil-contoso.example" as internal to "contoso.example"
  // and silently bypass the external-egress seal.
  return !(policy.trusted_destinations || []).some((trusted) => {
    const t = String(trusted).toLowerCase();
    return target === t || target.endsWith("." + t);
  });
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

// Decode base64/hex tokens embedded in the payload to printable text, so a
// credential wrapped in an encoding (under the bulk-blob shape threshold) is still
// scanned by the finders. Returns only decodings that look like text, capped to
// keep classification cheap. Used by the DLP classifier, mirroring the decode the
// prompt-influence path already does — the two must agree on the same bytes.
function decodeEmbeddedPayloads(value) {
  const out = [];
  const b64 = String(value || "").match(/[A-Za-z0-9+/=]{16,}/g) || [];
  for (const token of b64.slice(0, 16)) {
    try {
      const text = Buffer.from(token, "base64").toString("utf8");
      if (/[\x20-\x7e]{8,}/.test(text)) out.push(text);
    } catch {
      // Ignore malformed base64-looking fragments.
    }
  }
  const hex = String(value || "").match(/\b[0-9a-fA-F]{32,}\b/g) || [];
  for (const token of hex.slice(0, 16)) {
    if (token.length % 2 !== 0) continue;
    try {
      const text = Buffer.from(token, "hex").toString("utf8");
      if (/[\x20-\x7e]{8,}/.test(text)) out.push(text);
    } catch {
      // Ignore malformed hex-looking fragments.
    }
  }
  return out;
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
