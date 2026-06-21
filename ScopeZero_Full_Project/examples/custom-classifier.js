// Example: plug a custom data classifier into ScopeZero via the classifierResolver
// seam. The default classifier is regex + value-shape + decode; for domain-specific
// sensitivity (internal codenames, customer-specific PII, an embedding/commercial
// DLP) you supply a resolver. It is merged with mergeClassification, which takes
// the MAX level — so a custom classifier can only RAISE the class, never lower the
// deterministic floor. Use it to make autonomous public-sink lanes safe.
//
//   import { createRuntime } from "../src/runtime.js";
//   const runtime = await createRuntime({ rootDir, signingSecret, classifierResolver });
//
// The resolver receives { payload, context, tool } and returns
// { level, label?, findings?, established?, source? } (or null to abstain).
// level: 1 public, 2 internal, 4 confidential, 5 restricted.

const PROJECT_CODENAMES = [/\bproject[ _-]?(?:halcyon|nimbus|atlas)\b/i];

export function exampleClassifierResolver({ payload }) {
  const text = typeof payload === "string" ? payload : JSON.stringify(payload ?? {});
  if (PROJECT_CODENAMES.some((re) => re.test(text))) {
    return {
      level: 4, // confidential
      findings: ["internal_codename"],
      established: true,
      source: "example_codename_classifier"
    };
  }
  return null; // abstain — the deterministic classifier stands
}

// A stub for wiring a commercial/embedding DLP behind the same seam. Replace the
// body with a call to your DLP API; keep it returning the same shape.
export async function commercialDlpResolver({ payload }) {
  void payload;
  // const verdict = await fetch(DLP_URL, { ... }).then(r => r.json());
  // return { level: verdict.maxLevel, findings: verdict.labels, established: true, source: "vendor_dlp" };
  return null;
}
