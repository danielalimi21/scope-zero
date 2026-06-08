// Pure decision logic for the egress-lockdown self-test, split out so the
// exit-code policy is unit-testable without opening real sockets.
//
// The historical bug: the self-test exited 0 even when it reported EGRESS OPEN,
// so it could never gate CI or a deploy. The rule now: an OPEN result is a
// FAILURE whenever containment was expected — i.e. a lockdown is declared
// (k8s|docker), we are in production, or the caller passed --expect-contained.
// Only a pure dev run with no lockdown declared treats OPEN as observational
// (exit 0), and --allow-open forces that even when a lockdown is declared (for
// the operator who is mid-rollout and knows the block is not in place yet).

export function shouldFailOnOpen({ expectContained = false, allowOpen = false, lockdown = "none", production = false } = {}) {
  if (allowOpen) {
    return false;
  }
  if (expectContained) {
    return true;
  }
  const declared = ["k8s", "docker"].includes(String(lockdown).toLowerCase());
  return declared || production === true;
}

// Final process exit code given the probe result and the run context.
export function selftestExitCode(result, context = {}) {
  if (result?.egress === "open") {
    return shouldFailOnOpen(context) ? 1 : 0;
  }
  return 0;
}
