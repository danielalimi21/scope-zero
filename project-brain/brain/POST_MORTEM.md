# ScopeZero — Post-Mortem

An honest account of what got built, why it didn't become a business, and what left the
building alive.

## What Got Built

A complete, hardened agent-authorization platform — not a prototype:

- **Engine:** Ed25519 signed mission capsules, a pure-function policy engine (deterministic
  gates block; advisory signals escalate to a human, never decide alone), action contracts
  matching `(tool, operation, data_class, destination)`, delegation-depth + chain-cycle
  enforcement.
- **Containment:** HTTP CONNECT proxy bound to a live mission, plus a kernel egress block
  in two tiers (k8s NetworkPolicy with default-deny + pinned DNS, or a Docker internal
  network) and admission webhooks that inject and validate the proxy config, fail-closed.
- **Proof:** hash-chained ledger, HMAC-keyed so a writer with file access can't forge the
  chain; a multi-replica shared-sequencer Postgres variant (cluster-wide advisory lock,
  monotonic `seq`) that stays valid under concurrent appends; a standalone verifier.
- **Surrounding surface:** SQLite→Postgres store with tenant RLS, MCP trust registry with
  180-day trust decay + OSV CVE signals, agent identity certs, behavioral anomaly
  detection, a SOC2/EU-AI-Act/HIPAA compliance report, 45 API routes, CI with SBOM +
  image signing.
- **Honesty apparatus:** `RED_TEAM.md` — 22 attacks tried against the controls, each with
  before/after status and the regression test that locks it, plus an explicit
  "still NOT covered" section. This is the strongest cultural artifact in the repo.

Scale: 227–259 tests, 0 failures. The demos (`npm run demo:breach`, `demo:exfil`) are
executable proofs with non-zero exit on any containment failure.

## Why It Didn't Become a Business

**The parts were commodity; only the assembly was novel — and assembly isn't defensible.**

- **Signed authority grant** → capability tokens / macaroons / biscuit. Prior art deep.
- **Kernel egress containment** → standard k8s NetworkPolicy + proxy. Real engineering,
  but anyone with the same requirement builds the same thing.
- **Hash-chained verifiable ledger** → transparency logs / Certificate Transparency /
  sigstore. A solved category.
- **Co-sign on irreversible actions** → maker-checker / dual-control, decades old.

The pitch even conceded the intersection *was* the position ("detectors don't contain;
gateways don't bind actions to a signed delegation; the intersection is the position").
But an intersection of commodity parts is a feature set, not a moat — a well-resourced
incumbent (an AI gateway, a cloud IAM team) can assemble the same intersection once the
requirement is proven.

**The buyer problem compounded it.** Original positioning sold top-down to enterprise
CISOs — a slow, credential-gated motion. The `REPOSITIONING.md` pivot (to dev-led embed
for irreversible actions, one deep wedge: cloud/IAM mutations) was the right correction,
but it arrived at the same underlying truth: the depth that would have made it a product
lived in *one* control, not the platform.

**The one uncovered thing was a control, not a company.** Across the whole red-team, the
genuinely novel catch was laundering confidential data into benign prose and posting it to
an *allowed* host — caught by session/ingest taint (RED_TEAM #7, #8, #14), which host
allowlisting and stateless content scanning both structurally miss. That is one sharp,
defensible, embeddable idea. A single embeddable control is a library, not a platform
business — which is exactly what it became.

## What Left the Building Alive

- **taintgate** — the session-taint egress / anti-laundering sliver, extracted as a
  standalone zero-dep library. The defensible core, now its own reputation play. See the
  taintgate brain.
- **The honesty posture** — RED_TEAM's self-published bypasses and "honest scope" framing
  became taintgate's DNA (openly stating what it misses by design).

## The Lesson (why this file exists)

A platform assembled from commodity parts, however well-built and well-tested, is not
defensible — the moat has to live in a part, not the assembly. Build to find the one
uncovered control, then ship *that* alone. ScopeZero's real output was the method for
finding taintgate, not the platform around it.
