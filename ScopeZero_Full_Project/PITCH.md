# ScopeZero — the egress gate for AI agents

**Your agents will get prompt-injected. ScopeZero is the fail-closed, kernel-enforced gate that binds every byte of egress to a signed, time-boxed mission — and proves it in a tamper-evident ledger.**

---

## The problem

Companies are handing autonomous agents real credentials — GitHub, Slack, Gmail, AWS, internal MCP servers. An agent is a confused deputy by design: it reads untrusted content (web pages, tickets, emails, tool outputs) and then acts with privileged access. One prompt injection turns "summarize these diligence docs" into "email the customer revenue file to attacker@gmail.com," and nothing structurally stops it. The security team can't even answer the question their auditor asks: *prove what your agent did last Tuesday, and that it was authorized.*

Existing answers don't fit. An egress proxy allow-lists hosts but knows nothing about *which agent on whose authority for what purpose*. A guardrail SDK inspects prompts but an injected agent can route around the SDK entirely. An IAM role is static; an agent's task is per-mission and ephemeral.

## The wedge

ScopeZero issues a **signed mission capsule** before an agent runs: *this agent, delegated by this human, may use these tools, on this data class, to these destinations, until this timestamp.* Then it enforces that capsule at the layer an injected agent can't route around — **the network**, fail-closed at the kernel.

- Agent egress is forced through ScopeZero by a Kubernetes **NetworkPolicy** (kernel-level — a raw socket can't skip it) plus admission webhooks that inject the proxy config and **reject pods that strip it** (`failurePolicy: Fail` → ScopeZero down means no new agent pods, not open ones).
- Every outbound HTTPS `CONNECT` is refused unless it's bound to a mission that is **signature-valid, unexpired, active, owned by the requesting agent, and whose contract permits the destination**. An expired or tampered mission opens nothing.
- DNS is pinned to the cluster resolver, closing the obvious exfil side-channel.
- Every decision — allow, block, redact, approval, quarantine — is written to a **hash-chained, HMAC-keyed ledger**. Edit one entry and verification breaks; you can't re-forge the chain without the signing secret.

## Why an incumbent can't just ship this

A service mesh enforces *network identity*; it has no concept of a *signed, human-delegated, time-boxed agent mission*. A prompt-firewall enforces *content*; it's bypassed the moment the agent opens its own socket. ScopeZero is the only layer that ties **kernel-enforced egress** to a **cryptographic mission contract** with a **court-admissible audit trail** — the intersection is the moat, and it's the exact shape of what a CISO has to certify for SOC 2 / EU AI Act / HIPAA.

## The proof — run it in 10 seconds

```
npm test            # 187 tests, 0 failures
npm run demo:breach # injected agent vs. a signed mission
npm run bench       # persistence hot-path throughput
```

`demo:breach` walks an injected diligence agent through every escape and shows containment, then verifies the ledger: SDK exfil → blocked; raw tunnel to pastebin → blocked; **expired-mission replay → blocked**; **forged capsule → blocked**; ledger verifies clean. Exit code is non-zero if any containment fails — so the guarantee is executable, not a slide.

## Architecture in five lines

- **Mission capsule** (`src/capsules.js`) — HMAC-signed, TTL-bounded authorization token; vendor-neutral action contracts `(tool, operation, data_class, destination)`.
- **Enforcement** — Layer 1 pre-exec gateway (SDK, action-level; fail-closed on block/approval *and* on gateway error, redact enforced via a redactor), Layer 2 HTTPS `CONNECT` proxy (mission-bound, destination-level), Layer 3 K8s NetworkPolicy + admission webhooks (kernel, fail-closed).
- **Ledger** (`src/ledger.js`) — append-only, HMAC-keyed hash chain, optional external anchoring.
- **Defense-in-depth** — server-side data classification, evasion-resistant prompt-injection detection (homoglyph fold, letter-spacing/punctuation collapse, base64 — 100% recall / 0 false-positives on the adversarial corpus in `tests/prompt-injection-corpus.test.js`), a deterministic intent-drift screen (keyword-overlap heuristic — a fast first-pass signal, not semantic "understanding"), behavioral anomaly detection (incl. baseline-independent low-and-slow ceiling), MCP trust registry with scheduled CVE refresh, agent identity certs.
- **Multi-tenant** — Postgres with row-level security (every tenant table, incl. hot-path); hot-path state (behavior, session risk, metrics) on per-row atomic upserts so the gateway scales past single-writer throughput. `npm run bench`: ~31k hot-path writes/sec with **0 full-state-blob rewrites** on the persistence layer.

## Honest scope (what's enforcement vs. governance)

The network layer is *containment* and only as strong as the K8s NetworkPolicy being applied — that's the hard, demoable guarantee, and the pitch leads with it. Tunneled HTTPS is enforced at destination + live-mission granularity, not per-request action (TLS bodies are opaque) — per-action enforcement is the SDK layer's job. Recursive DNS-tunnel prevention needs a filtering resolver (pinning to kube-dns kills the direct path; the rest is roadmap). We say this out loud because a security product that overclaims is worse than one that's precise.

## Threat coverage

Mapped to OWASP Top 10 for LLM Applications (2025) and MITRE ATLAS in
[`SECURITY_COVERAGE.md`](SECURITY_COVERAGE.md) — strong on the slice ScopeZero
owns (Excessive Agency, Sensitive-Info Disclosure, Prompt-Injection containment,
Unbounded Consumption), honest about what's another layer's job.

## The line

**Adopt ScopeZero and an injected agent is contained at the kernel, bound to a signed mission, and provable to your auditor. Skip it and you're trusting that your agents never read anything malicious. They will.**
