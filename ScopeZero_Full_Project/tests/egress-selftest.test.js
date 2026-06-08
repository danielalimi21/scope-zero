import test from "node:test";
import assert from "node:assert/strict";
import { shouldFailOnOpen, selftestExitCode } from "../src/egressSelftest.js";

// The historical bug this guards: OPEN egress exited 0 unconditionally, so the
// self-test could never gate CI or a deploy. OPEN must fail whenever containment
// is expected.

test("open egress in pure dev (no lockdown declared) is observational — exit 0", () => {
  assert.equal(selftestExitCode({ egress: "open" }, { lockdown: "none", production: false }), 0);
});

test("open egress fails when a lockdown is declared", () => {
  assert.equal(selftestExitCode({ egress: "open" }, { lockdown: "k8s" }), 1);
  assert.equal(selftestExitCode({ egress: "open" }, { lockdown: "docker" }), 1);
});

test("open egress fails in production even with no lockdown declared", () => {
  assert.equal(selftestExitCode({ egress: "open" }, { lockdown: "none", production: true }), 1);
});

test("--expect-contained forces failure on open egress", () => {
  assert.equal(selftestExitCode({ egress: "open" }, { expectContained: true }), 1);
});

test("--allow-open overrides every expectation (mid-rollout)", () => {
  assert.equal(shouldFailOnOpen({ allowOpen: true, lockdown: "k8s", production: true, expectContained: true }), false);
  assert.equal(selftestExitCode({ egress: "open" }, { allowOpen: true, lockdown: "k8s" }), 0);
});

test("contained egress always passes", () => {
  assert.equal(selftestExitCode({ egress: "blocked", how: "timeout" }, { lockdown: "k8s", production: true }), 0);
});
