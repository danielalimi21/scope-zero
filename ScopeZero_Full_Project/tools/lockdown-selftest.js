// Egress-lockdown self-test. Opens a RAW socket straight to an external host,
// deliberately bypassing HTTP_PROXY — exactly what an injected agent would do to
// skip the gateway. If the kernel egress lockdown (K8s NetworkPolicy / Docker
// internal network) is in place, the connection is dropped and the agent is
// contained. If it connects, egress is OPEN and the bare-SDK tier is honor-system.
//
//   node tools/lockdown-selftest.js [host] [port]
//   node tools/lockdown-selftest.js --expect-contained   # exit 1 if egress is open
//   node tools/lockdown-selftest.js --allow-open          # never fail (mid-rollout)
//
// Exit code: OPEN egress is a FAILURE whenever containment is expected — a
// lockdown is declared (SCOPEZERO_EGRESS_LOCKDOWN=k8s|docker), NODE_ENV=production,
// or --expect-contained was passed. A pure dev run with no lockdown declared
// treats OPEN as observational (exit 0). This is what makes it a real CI/deploy
// gate instead of an always-green check.
//
// Turns "did you deploy the lockdown correctly?" into a check you can run inside
// the agent's network namespace (e.g. `kubectl exec <agent-pod> -- node ...`).

import net from "node:net";
import { selftestExitCode } from "../src/egressSelftest.js";

const args = process.argv.slice(2).filter((a) => !a.startsWith("--"));
const host = args[0] || "1.1.1.1";
const port = Number(args[1] || 443);
const expectContained = process.argv.includes("--expect-contained");
const allowOpen = process.argv.includes("--allow-open");
const TIMEOUT_MS = 4000;

function attempt() {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    let settled = false;
    const done = (result) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve(result);
    };
    socket.setTimeout(TIMEOUT_MS);
    socket.once("connect", () => done({ egress: "open" }));
    socket.once("timeout", () => done({ egress: "blocked", how: "timeout" }));
    socket.once("error", (err) => done({ egress: "blocked", how: err.code || "error" }));
    socket.connect(port, host);
  });
}

const result = await attempt();
const lockdown = String(process.env.SCOPEZERO_EGRESS_LOCKDOWN || "none").toLowerCase();
const production = process.env.NODE_ENV === "production";
const exitCode = selftestExitCode(result, { expectContained, allowOpen, lockdown, production });

if (result.egress === "open") {
  console.log(`✗ EGRESS OPEN — raw socket to ${host}:${port} connected, bypassing the proxy.`);
  console.log(`  Declared lockdown: ${lockdown}. No kernel egress block is containing this network namespace.`);
  console.log(`  An agent that ignores HTTP_PROXY can reach the internet directly. Apply the lockdown (see /v1/deployment/lockdown).`);
  if (exitCode !== 0) {
    console.log(`  FAIL: containment was expected here (lockdown declared / production / --expect-contained) but egress is open.`);
  }
  process.exit(exitCode);
} else {
  console.log(`✓ EGRESS CONTAINED — raw socket to ${host}:${port} was dropped (${result.how}).`);
  console.log(`  The only outbound path is the ScopeZero proxy. Bare-SDK bypass is contained at the kernel.`);
  process.exit(0);
}
