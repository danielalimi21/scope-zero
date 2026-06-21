// Proves the classifierResolver seam: a custom classifier can RAISE the data class
// (and thereby tighten the decision), but the merge takes the max so it can never
// lower the deterministic floor.

import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { createRuntime } from "../src/runtime.js";
import { exampleClassifierResolver } from "../examples/custom-classifier.js";

const TENANT = "tenant_contoso";

async function runtimeWith(resolver) {
  const rootDir = await fs.mkdtemp(path.join(os.tmpdir(), "scopezero-clf-"));
  const runtime = await createRuntime({ rootDir, signingSecret: "s", classifierResolver: resolver });
  await runtime.registerAgent({ tenant_id: TENANT, agent_id: "a.clf", name: "n", owner: "o", allowed_tools: ["drive.read", "statuspage.update"] });
  const { capsule } = await runtime.createMission({
    tenant_id: TENANT, agent_id: "a.clf", delegated_by: "o", objective: "x",
    allowed_tools: ["drive.read", "statuspage.update"],
    allowed_data_classes: ["public", "internal", "confidential"],
    allowed_destinations: ["status.partner.example"],
    public_egress_destinations: ["status.partner.example"] // autonomous sink — only the classifier can catch codenames here
  });
  return { runtime, rootDir, mission: capsule.id };
}

test("a custom classifier raises the class and tightens the decision on an autonomous sink", async () => {
  // Content the default regex classifier sees as benign ("Project Halcyon update"),
  // posted to a declared public sink (otherwise autonomous).
  const call = (runtime, mission) => runtime.evaluateToolCall({
    tenant_id: TENANT, agent_id: "a.clf", mission_id: mission,
    tool: "statuspage.update", action: "post", operation: "write",
    payload: { summary: "Project Halcyon launch is on track." },
    destination: { type: "url", address: "status.partner.example", external: true }
  });

  // Without a resolver: the default classifier finds nothing sensitive; the sink is
  // declared public, so this can run autonomously.
  const without = await runtimeWith(null);
  const a = await call(without.runtime, without.mission);
  await fs.rm(without.rootDir, { recursive: true, force: true });

  // With the custom classifier: the codename raises the class to confidential, so
  // the same egress is no longer a clean autonomous post.
  const withClf = await runtimeWith(exampleClassifierResolver);
  const b = await call(withClf.runtime, withClf.mission);
  await fs.rm(withClf.rootDir, { recursive: true, force: true });

  // The custom classifier raises the codename content to confidential, which flips
  // the same external egress to a hard block (sensitive data crossing a boundary) —
  // strictly tighter than the baseline, and driven by a class-based reason that only
  // appears once the classifier has run.
  assert.notEqual(a.decision, "block", `baseline (no classifier) should not hard-block (got ${a.decision})`);
  assert.equal(b.decision, "block", `custom classifier must escalate the codename egress to block (got ${b.decision})`);
  assert.ok((b.verdict.reasons || []).some((r) => r.code === "sensitive-egress"), "block must be driven by the raised data class");
  assert.ok(!(a.verdict.reasons || []).some((r) => r.code === "sensitive-egress"), "baseline must not see sensitive-egress");
});
