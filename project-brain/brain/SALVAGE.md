# ScopeZero — Salvage

The point of this brain: after taintgate, is there a *second* extractable sliver still
buried here? Each candidate is judged on the taintgate bar — **defensible, uncovered,
embeddable, honestly bounded.** Verdicts are blunt on purpose; a dressed-up "maybe" wastes
a future session.

## Already Extracted

- **Session-taint egress / anti-laundering** → **taintgate.** The one clear win. Read
  confidential → model rewrites to benign prose → post to an allowed host; caught by
  session/mission taint (RED_TEAM #7/#8/#14). Done; don't re-mine.

## The Once-Promising Candidate — Downgraded by Hostile Review

**Egress-containment prover — "prove containment or fail closed."**
`tools/lockdown-selftest.js` + `src/egressSelftest.js` (exit-code policy) + the boot
canary in `server.js:66-94`: on boot in production, open a raw TCP socket to one canary
(`1.1.1.1:443`) from inside the workload netns and confirm the kernel egress block is
actually applied — if it connects, refuse to start.

Initially flagged the best second-taintgate candidate. A taintgate-style hostile review
(Session #2, code read end-to-end) knocked it down. The *framing* is right — prove
containment, fail closed, from inside the agent's own namespace — but the **mechanism
proves far less than it claims**:

- **Single-destination probe ≠ egress proof.** Tests one host:port. A per-destination
  allowlist that blocks `1.1.1.1` but permits a CDN passes green while egress is open. A
  blocked canary is absence of evidence sold as proof — and here it's load-bearing, not a
  footnote.
- **Can't distinguish kernel-drop from host-down.** `socket error → "blocked"` fires for
  ENETUNREACH / ECONNREFUSED / DNS blip / dead canary alike. A transient failure reports
  CONTAINED when nothing was proven — real fail-open, no attacker needed.
- **TCP only.** UDP (DNS-tunnel, ScopeZero's own admitted gap), QUIC/HTTP3 (UDP 443),
  ICMP all unprobed. Block TCP, leave UDP open → passes.
- **Point-in-time.** Proves containment at boot; k8s policies are dynamic and can change
  after. No runtime re-probe.

- **Uncovered? No.** Unlike taintgate (no shipping equivalent), k8s NetworkPolicy
  conformance testing is populated — **netassert, Cilium connectivity tests, np-viewer**.
  Only differentiation is "runs inside the workload + halts at boot" — thin, not empty.

- **Verdict:** **not a clean second taintgate.** Weaker on both legs that made taintgate
  real (mechanism correctness + uncovered-ness). Best home for the sharpened idea is a
  **companion essay to taintgate** ("your egress lockdown is a lie until you prove it —
  and a one-shot canary isn't proof"), carrying reputation value at zero build risk. If
  ever built, scope it honestly as an *agent egress conformance check* — only after a
  multi-destination / multi-protocol / calibrated drop-vs-unreachable / continuous-reprobe
  redesign, eyes open about netassert.

## Worth-A-Look, But Weaker

- **MCP trust registry with CVE-decay** (`src/mcpTrustRegistry.js`,
  `src/mcpRefreshScheduler.js`). Trust levels per MCP server, 180-day decay to
  `community`, OSV CVE polling, background refresh. **Timely** — the MCP ecosystem is
  exploding in 2026. But its defensibility is the *curated data / network*, not the code
  (anyone can poll OSV and store trust levels). Better as a community/service play with a
  real dataset than as a code sliver. Flag it; don't build blind.

## Sharp Ideas, But Patterns Not Products

Good writeup / blog / talk material — the kind of thing that builds reputation on its own
— but not standalone shippable tech:

- **Manifest-as-verified-ceiling** — a tool's self-declared output data-class is a
  *ceiling checked against the actual bytes*, never a skip-flag; declaring "public output"
  can't launder a confidential payload. A crisp security principle.
- **Operation-floor** — an action's operation is floored to the more impactful of declared
  vs. tool-name-inferred; mislabeling `wire` as `read` escalates instead of dodging.
- **Irreversible → mandatory co-sign, non-overridable, fail-closed** — maker-checker
  applied to agent actions.
- **Vendor-neutral action-type taxonomy** (`payment` / `privilege_change` / `export` /
  `external_send` / `delegate` + `irreversible`/`mutating` + `money`/`privilege`). A
  candidate *spec*, but specs need adoption, not code.

These are strongest bundled as one honest essay: *"patterns for bounding an
action-taking agent"* — carrying the same reputation value as a shipped sliver, at lower
cost.

## Commodity — Don't Bother

- **Signed capability / authority grant** — macaroons / biscuit / capability tokens.
  Solved.
- **Hash-chained / HMAC verifiable ledger** — transparency logs / Certificate
  Transparency / sigstore rekor. Solved. The multi-replica sequencer engineering is nice,
  but it's a re-implementation of a known category, not a new one.
- **Behavioral anomaly detection** — velocity/burst/off-hours heuristics; generic and, per
  ScopeZero's own framing, advisory-only for good reason.

## Bottom Line

One clear extraction already happened (taintgate). The one promising second candidate
(**egress-containment prover**) was hostile-reviewed and **downgraded** — sound framing,
but single-probe mechanism proving too little, in a space netassert-class tools already
cover; best used as a companion essay, not a repo. The timely-but-weak-code candidate (MCP
trust registry) is better as a data/community play. The rest is reputation material —
essays, not repos. There is **no second platform and no clean second taintgate** in here,
and that's the honest read.
