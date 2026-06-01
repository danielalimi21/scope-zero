# ScopeZero — Honest Assessment & Path Forward

> A frank technical and strategic read on ScopeZero, written for the founder and the AI coding assistant working in this repo. The goal is to be useful, not flattering. Read all of it before reacting to any single part of it.

---

## TL;DR

ScopeZero is **thoughtful engineering on a real problem with a positioning gap and a closing market window**. The code is more serious than most demos at this stage. The pitch line is sharp. The buyer-facing materials are well-produced.

But:

1. The technical "moat" pieces are **rules-engine deep, not AI deep** — the components marked as AI-safety controls are regex blocklists and self-reported flags.
2. The market is about to be **commoditized by incumbents** — MCP gateways, AI gateways, IAM vendors, and agent platforms are all moving into this layer.
3. The **narrative is well ahead of the customer evidence** — twelve buyer-packet documents, one acquirer memo, zero signed pilots visible in the repo.

The single highest-leverage move is **one signed paid pilot in the next two quarters**. The technical work to support that pilot is a small fraction of what the repo currently contains. Everything else is premature.

This document explains the specific problems, the specific code work that matters, and a recommended path. It is intended to be read by both the founder and the coding assistant that will help execute it.

---

## 1. What ScopeZero Is (for context)

A pre-execution authorization gateway for AI-agent tool calls. The agent (or an MCP proxy) asks ScopeZero "is this specific action allowed?" before any tool runs. ScopeZero returns `allow`, `block`, `redact`, `quarantine_context`, `approval`, or `pause_session`, and appends the decision to a hash-chained evidence ledger.

Core primitive: the **Mission Action Contract** — a short-lived HMAC-signed capsule declaring allowed tools, data classes, destinations, delegation depth, and risk budget for a specific agent on a specific objective.

Pitch line: *"The agent was authorized. The action was not."* — this is genuinely good. Keep it.

---

## 2. The Strategic Problems

### 2.1 This is a feature, not a company — yet

Every plausible buyer already has a strong incumbent vendor that wants to own this layer:

| Incumbent category | Examples | Why they win |
| --- | --- | --- |
| MCP protocol/hosts | Anthropic, MCP working group | Native authorization primitives being added to the protocol itself |
| AI gateways | LiteLLM, Portkey, Kong AI Gateway, Cloudflare AI Gateway | Already sit in the agent's outbound path |
| Cloud IAM | AWS IAM, Okta, Microsoft Entra | "Agent identity + action policy" is on every roadmap |
| CASB/DLP | Netskope, Zscaler | Already in the egress path with mature DLP |
| Agent platforms | LangChain, CrewAI, OpenAI Agents SDK | Building guardrails natively |
| Policy engines | OPA/Cedar/Rego | Mature, audited, free, the security architects already trust them |

Standalone "agent action gateway" is a crowded category for a budget line item that doesn't yet exist at most enterprises. The window to establish a category before incumbents commoditize is **roughly 12 months**. Probably less.

### 2.2 "Vendor-neutral" cuts both ways

It's a great pitch. It also means ScopeZero competes with everyone and partners with no one natively. The connector list shows the asymmetry: GitHub PRs and Slack messages are the easy ones. The systems where governance actually matters in enterprise (Salesforce, ServiceNow, NetSuite, SAP, Oracle, custom internal APIs, M365 admin) are each multi-month integrations.

### 2.3 The buyer packet is doing too much work

Twelve buyer-facing markdown files, a sales playbook, pricing pages, an acquirer memo. The narrative is way ahead of customer evidence. That's normal for fundraising — risky for product-market fit. **Polish on the deck does not substitute for one logo on a contract.**

### 2.4 Pre-execution latency is unaddressed

Every tool call now has a network round-trip to ScopeZero. For an agent doing 50 tool calls in a planning loop, that's a real UX problem and a real competitive surface. Competitors will weaponize it: "ours runs in-process / as a sidecar / cached." There is no story for this in the repo.

---

## 3. The Technical Problems

These are specific, file-referenced, and most have **2–6 weeks of focused engineering each**. They are not catastrophic — but they are exactly the things a sharp CISO or solutions architect will probe in the third meeting, and right now they will not survive that probing.

### 3.1 The "AI safety" components are not AI

**Prompt injection shield → seven hardcoded regex strings.**

In `ScopeZero_Full_Project/config/defaultPolicy.json`:

```json
"blocked_prompt_patterns": [
  "ignore previous",
  "ignore all previous",
  "bypass policy",
  "send to external",
  "exfiltrate",
  "disable guardrails",
  "reveal system prompt"
]
```

Any half-decent attacker uses synonyms, base64, leetspeak, translation, or instruction nesting. Modern prompt-injection defense is model-graded (a small classifier rates intent) or embedding-distance based (compare against known-good intent vectors). Right now, `prompt_injection_shield: true` in the policy gives a buyer the impression of an AI-native control. **It is a substring blocklist.** A technical CISO will discover this in the demo.

**Fix path:** replace `detectPromptInfluence` in `src/sensitiveData.js` with a real classifier. Two reasonable options:
- A small local model (e.g., a fine-tuned BERT-class classifier) → ~2–3 weeks including eval set
- An embedding-distance check against known malicious/known-mission patterns → ~1–2 weeks but lower ceiling

Either way, keep the regex blocklist as a *fallback fast path*, not the primary control.

### 3.2 Action classification is regex on tool names

In `src/actionAuthorization.js:8` and `src/actionAuthorization.js:147`:

```js
const OPERATION_HINTS = [
  ["external_send", /\b(send|email|post|publish|share|transmit|forward)\b/i],
  ["export", /\b(export|download|extract|dump|archive)\b/i],
  ...
];
```

A tool named `transmit_record`, `gmail.dispatch`, `outbound.deliver`, or anything in a non-English vocabulary slips through. This is the part of the system that decides whether an action is `external_send` vs `read` — and it's pattern matching on the tool's *name*, not its *behavior*.

**Fix path:** action classification should come from a registered **tool manifest** declared at connector-registration time, not inferred from the string. Each connector should publish a typed manifest (`tool_id`, `operation`, `data_in_classes`, `data_out_classes`, `external_capable`, `mutating`, `irreversible`, `requires_approval_default`). The regex inference becomes a *fallback for unregistered tools* only.

This also kills a whole class of evasion bugs at once.

### 3.3 Mission alignment is self-reported by the agent

In `src/policyEngine.js:64`:

```js
if (policy.mission_lock && request.context?.mission_aligned === false) {
  addRisk(42, "intent-drift", "Requested action no longer matches the approved mission.");
  decision = "block";
}
```

The agent passes `context.mission_aligned`. A compromised, jailbroken, or adversarial agent will set this to `true`. The control checks the agent's self-report. That's not a control — that's a comment.

**Fix path:** infer mission alignment from the *server* side: compare the action's operation+data class+destination against the mission's declared objective using an embedding similarity or a small LLM judge. This is a real piece of work (2–4 weeks) and it's also genuinely defensible if done well — *server-side mission alignment* is one of the few things that's hard to replicate quickly.

### 3.4 The policy engine is OPA/Cedar with extra steps

`src/policyEngine.js` is ~200 lines of well-structured conditional logic. The action contracts in `src/actionAuthorization.js` are wildcard string matches over tool / operation / data class / destination. This is the exact problem space OPA, Cedar, and Rego were built for.

A security architect at a serious enterprise will ask: *"Why not express this as a Rego policy bundle against our existing OPA deployment?"* And the honest answer is: there isn't a strong one yet, except "we did it for you with an agent-flavored schema."

**Two ways to respond:**

1. **Lean into it.** Embrace "we are the policy-as-code layer for agents, with the agent-domain schema you don't have to invent." Win on schema, connector breadth, audit format, and curated policy libraries per vertical. The engine itself is commoditizable — that's fine, Okta's SAML wasn't a moat either.
2. **Build something OPA can't easily replicate.** Server-side mission alignment, behavioral baselining, embedding-based intent matching, learned anomaly detection on tool-call sequences. This is harder but it's where algorithmic defensibility lives.

These are not exclusive. Path 1 is the GTM bet, Path 2 is the technical moat.

### 3.5 Sensitive-data classification is shallow

`classifyPayload` in `src/sensitiveData.js` (not fully reviewed but the surface area suggests it) returns a 1–5 rank from deterministic checks. Every DLP vendor has been doing this for 20 years and they all admit it misses the long tail. This is fine as a fast prefilter; it is not a differentiator and shouldn't be sold as one.

**Fix path:** keep the deterministic rank, but layer on a small classifier for ambiguous cases. Or, more pragmatically, integrate with an existing DLP signal (Netskope, Microsoft Purview, Google DLP) rather than competing with them.

### 3.6 Latency in the hot path

Every tool call → HTTP round-trip → policy evaluation → ledger append → response. For an agent in a planning loop with 50 tool calls, this adds noticeable latency, and the ledger append is on the synchronous path.

**Fix path options:**
- **Decision cache** keyed on `(mission_id, tool, operation, data_class, destination_hash)` with short TTL. Most agents make repeated similar calls.
- **Sidecar mode** — ship a thin local enforcer that holds a signed policy bundle and only round-trips to central for novel decisions and ledger writes.
- **Async ledger append** with a write-ahead log and a background flusher. Decision returns immediately; durability is guaranteed by the WAL.

Pick at least one before the first pilot. Sidecar is the strongest pitch for AI-platform teams.

### 3.7 Connector breadth is shallow where it matters

Real connectors today: GitHub (live), Slack (live), AWS IAM (simulation only — never actually mutates). Everything else is a registered boundary without an adapter. For a buyer, this means **ScopeZero governs three systems in a real deployment**, and one of them in simulation.

The systems where enterprise agent governance actually has urgency:

- Salesforce (record updates, mass actions, data export)
- ServiceNow (ticket workflows, change approvals)
- M365 admin actions and Graph API writes
- Snowflake / BigQuery query and export
- GitHub Enterprise (org-level admin actions, not just PRs)
- Okta admin actions
- Production AWS (not just IAM — S3, RDS, Lambda invocations with side effects)

**Fix path:** pick **two** of these based on the first pilot customer's stack and build them properly. Each is 3–6 weeks done well. Don't build all of them speculatively.

### 3.8 Multi-tenancy and isolation are untested under load

The SQLite local store is fine for demos. The Postgres path exists but the isolation model (row-level security? per-tenant schemas? service-level filtering only?) needs to be explicitly designed and tested with a hostile-tenant test, not just "we filter by `tenant_id` in queries." A single missed filter is a cross-tenant data leak — and for a security product, that's existential.

**Fix path:** before pilot #2 (multi-tenant), implement Postgres RLS (`row_security = on`, per-tenant policies) so a missed `WHERE tenant_id = ?` becomes harmless instead of catastrophic. Add a test that runs every query under a tenant role and asserts no other tenant's rows are returned. 1–2 weeks.

### 3.9 Production hardening gaps

From `COMMERCIAL_READINESS.md` and what's actually in the repo:
- No distributed rate limiter (`rateLimiter` is an in-memory `Map` in `server.js`)
- Secrets are local-vault style; no integration with HashiCorp Vault / AWS Secrets Manager / Azure Key Vault tested
- No image signing, no SBOM, no dependency scanning in CI
- No external pentest
- No SOC 2 — not even Type I

None of these are blockers for a pilot. All of them are blockers for production customer #1. Plan accordingly.

### 3.10 The ledger is great; the verification story is incomplete

Hash-chained JSONL with a verifier is a genuinely good audit story. But: the file is on local disk. A motivated insider with shell access can rewrite history and the chain will verify against itself (because they regenerate the hashes). The ledger needs either:

- An external anchor (periodic hash to a write-only S3 object lock, or to a public timestamping service, or to a customer-controlled append-only log)
- Or a third-party witness (e.g., notarize batch hashes to a transparency log)

Without that, the audit story is "trust the operator." For SOC 2 evidence this is workable; for high-trust enterprise it isn't.

**Fix path:** add an S3 Object Lock (or equivalent) integration that writes ledger batch hashes hourly. 1 week of work, huge credibility upgrade.

---

## 4. What Would Actually Move the Needle

The question is not "how do I make the product better." It's "what is the smallest set of work that gets to a signed pilot, and from there to a defensible position."

### Tier 1 — Pilot-ready. ~3–6 months.

**Goal:** sign one paid pilot with a name-brand logo.

Engineering (8–12 weeks of one engineer, ideally executed in parallel by the founder + coding assistant):

| Work | File(s) | Effort |
| --- | --- | --- |
| Real prompt-injection classifier | `src/sensitiveData.js` | 2–3 weeks |
| Server-side mission alignment (embedding-based) | `src/policyEngine.js`, new `src/missionAlignment.js` | 2–4 weeks |
| Tool manifest schema (replace name-regex inference) | `src/actionAuthorization.js`, `src/connectors.js` | 2 weeks |
| Decision cache for hot-path latency | `src/runtime.js` | 1 week |
| Postgres RLS + hostile-tenant test | `db/postgres/schema.sql`, `src/postgresStore.js`, new test | 1–2 weeks |
| One real connector beyond GitHub/Slack (pick from pilot customer's stack) | `src/connectors.js`, new adapter | 3–4 weeks |
| Ledger external anchor (S3 Object Lock or equivalent) | `src/ledger.js` | 1 week |
| Tested SSO against actual customer IdP | `src/auth.js` | 1–2 weeks (with customer cooperation) |

Total ~12–16 engineer-weeks. Doable solo if the founder is full-time. Faster with the AI coding assistant carrying the well-scoped pieces (manifest schema, decision cache, RLS, anchor).

**Non-engineering — 60–80% of the founder's time:**

- Cold outreach to 50+ mid-market CISOs and heads of AI platform.
- Discovery calls. Ask what they're actually trying to govern, not what you want to sell.
- Don't send the buyer packet first. Send a one-pager. Save the deep packet for round 2.
- Get to one signed pilot. Even a discounted one. Even one with caveats.

**If pilot is signed by month 6: the product is real.** Continue to Tier 2.

**If no pilot by month 6: stop building. Either pivot positioning narrower (see Section 5) or have the acquihire conversation.**

### Tier 2 — Product with 3–5 paying customers. ~9–15 months.

Adds:

- SOC 2 Type I in flight (table stakes for enterprise; 3–6 months of process)
- 5–8 production connectors based on customer demand
- A real policy authoring UI (the current command center is demo-grade — CISOs and platform teams need to author/version/review without writing JSON)
- Customer success / pilot delivery muscle (probably a second hire)
- Sidecar enforcer mode for latency-sensitive customers

Team grows to 3–5. ~$2–4M of funding needed unless customers prepay generously.

### Tier 3 — Defensible standalone company. ~18–30 months.

Adds:

- Real algorithmic moat: behavioral baselines per agent, learned anomaly detection on tool-call sequences, embedding-based intent
- 15+ connectors or a marketplace/partnership model
- SOC 2 Type II + relevant industry certs
- A repeatable sales motion not dependent on founder hustle
- Team of 8–15, Series A done, Series B in sight

**Important:** the clock to Tier 3 is not 30 months from today. It's *however long until incumbents ship native agent-action policy*. That's roughly 12 months. So the realistic question is whether ScopeZero can be too far ahead by then to be commoditized — and that requires winning customers in Tier 1 and Tier 2 *fast*.

---

## 5. Strategic Bets to Pick

You can't be vendor-neutral, broad, and standalone all at once with a small team. Pick one bet primarily:

### Bet A — The policy-as-code layer for agents

Embrace that the engine is commoditizable. Compete on:
- The schema (Mission Action Contracts as the industry standard for agent action policy)
- Connector breadth and quality
- Curated policy libraries per vertical (financial services, healthcare, public sector)
- Audit and evidence format as a SOC-grade artifact

**This is the Okta playbook.** SAML wasn't the moat; the directory and integrations were. Hardest part: distribution. Best fit if the founder has enterprise sales DNA.

### Bet B — The AI-native detection layer

Lean into Sections 3.1, 3.3, and 3.5. Build the server-side mission alignment, the behavioral baselining, and the embedding-based intent matching that OPA can't replicate. Position as "policy engines tell you the *what*; ScopeZero tells you the *whether-this-agent-actually-meant-it*."

**Hardest part: ML engineering depth.** Probably needs a co-founder or early hire with applied-ML/security background. Best fit if the founder can recruit that person.

### Bet C — A vertical wedge

Pick one regulated industry (financial services agents, healthcare PHI workflows, public-sector / FedRAMP-adjacent) and own agent governance there. The incumbents will be slower to specialize.

**Hardest part: domain expertise and certifications.** SOC 2 isn't enough; you'll need HIPAA / SOX / FedRAMP depending on vertical. Slowest path but most defensible if you survive it.

### Recommendation

Given the current code, founder profile (solo so far, judging by repo), and the closing window: **Bet A with one foot in Bet B.** Sell as policy-as-code-for-agents in the near term; invest the technical R&D in server-side mission alignment as the differentiator. Don't try Bet C unless a pilot customer drags you into a vertical.

---

## 6. What to Stop Doing

These are net-negative right now:

1. **Writing more buyer-packet markdown.** Twelve is already too many. Nobody reads past the executive brief in the first meeting. Two more documents do not move the deal.
2. **Polishing the browser command center demo.** It's already good enough to demo. Spend that time building one more real connector.
3. **Selling "vendor-neutral everything."** Pick the two connectors that matter for the first pilot and let everything else stay on the roadmap.
4. **The acquirer memo.** Either it's premature (no acquirer is looking at a pre-pilot company) or it's a distraction from the actual job (signing the first customer). Delete it from the buyer packet — buyers should not see "here's how I'd sell out" before they've bought.
5. **Generating reports as the proof.** `LOCAL_PILOT_REPORT.md` and `CISO_PROOF_REPORT.md` are generated by your own tooling. They're useful as test artifacts. They are not customer proof. Stop calling them proof.

---

## 7. Guidance for the Coding Assistant

If you (the AI coding assistant) are reading this, here's what's true about working in this codebase right now:

### Conventions

- ES modules only. Node 20+ standard library. No npm dependencies except optional `pg`. Don't introduce frameworks.
- Tests are `node --test`. Don't propose Jest/Vitest.
- Ledger entries are append-only. Every state change should produce one via `ledger.append({ event_type, ... })`.
- Policy decisions only *escalate* via `stronger()`. Never overwrite `decision` unconditionally in `policyEngine.js`.
- When you add files in `src/` or `tools/`, add them to the explicit list in `package.json`'s `check` script.
- Don't commit anything under `data/` (SQLite, ledger). It's runtime state.

### Priorities

Work on Tier 1 items from Section 4 in this order:

1. **Tool manifest schema** (Section 3.2) — unblocks everything else because it gives connectors a typed interface
2. **Postgres RLS** (Section 3.8) — security-critical, blocks pilot #2
3. **Decision cache** (Section 3.6) — quick win, big latency improvement
4. **Ledger external anchor** (Section 3.10) — quick win, big credibility upgrade
5. **Server-side mission alignment** (Section 3.3) — the actual differentiator
6. **Prompt injection classifier** (Section 3.1) — replace the regex stub
7. **One real connector** — but only after the founder names the pilot customer's stack. Don't speculate.

### Things not to do

- Don't add features the founder didn't ask for. The repo already has too many.
- Don't write more buyer-facing markdown. Don't expand the buyer packet.
- Don't refactor the policy engine for elegance. It's working and auditable. Add capability via new checks that use `stronger()`.
- Don't introduce LLM calls in the synchronous decision path without a cache and a hard timeout. Latency matters here more than in most products.
- Don't claim a capability exists in the code that doesn't. If something is a regex stub (like prompt injection detection), the config flag name should not imply more than that, and the docs should be honest. A buyer who finds a gap between marketing claims and code is gone forever.

### Things to do

- When adding a control, add a test that proves the *unhappy* path (it blocks/escalates the bad case) and the *happy* path (it doesn't false-positive the good case).
- When you touch `policyEngine.js`, add a row to a control matrix doc somewhere that maps the control name → file:line → what it actually does. This document does not exist yet. Create it. Keep it honest.
- When you add a connector, register a tool manifest (Section 3.2) — don't rely on regex inference.
- When evaluating LLM calls or embeddings, prefer a small local model over a hosted API for the hot path. Latency, privacy, and cost all push the same direction.

---

## 8. The Hard Decision

The window is ~12 months before incumbents commoditize this layer.

The realistic milestones:

- **Month 3:** real prompt-injection classifier shipped, tool manifest schema in place, one new real connector started. First serious customer discovery calls done. 10+ CISO conversations logged.
- **Month 6:** one paid pilot signed, even if discounted. Or pivot decision made.
- **Month 9:** pilot in production, evidence ledger generating real audit trails for a real customer, SOC 2 Type I started.
- **Month 12:** decision point — second pilot signed and growing, or this is an acquihire conversation with one of the likely acquirers (MCP-host vendors, AI-gateway vendors, IAM vendors).

That's the path. It's tight but it's real. The code is far enough along. The product framing is good enough. The missing piece is customer evidence, not more engineering.

**The hardest piece of advice in this document:** if by month 6 there is no signed pilot, the answer is not "ship more features." The answer is to either narrow the wedge dramatically (Bet C) or have the acquihire conversation. Continuing to build a vendor-neutral standalone product without a paying customer is the path most likely to end in a portfolio piece.

---

## 9. The Things This Document Got Right About Itself

This assessment is opinionated and confident. It is also written without the full context of:

- What the founder's actual fundraising / runway situation is
- What customer conversations have already happened off-repo
- What the founder's prior enterprise sales experience is
- Whether there are co-founders or contractors involved
- Whether any pilots are *informally* underway

Re-read this document with those facts in hand and discount accordingly. The technical critiques (Section 3) are grounded in the code and stand on their own. The strategic critiques (Sections 2, 4, 5) are grounded in the market and the public state of the repo — they should be adjusted against private context the document doesn't have.

The single load-bearing claim that does not depend on private context:

> **The technical work is far enough along that the bottleneck is not engineering. It is the absence of a paying customer. Spend accordingly.**

That one is true regardless.

---

## 10. Closing

The code is good. The framing is good. The market is real. The window is closing.

Two quarters of focused work — most of it sales, some of it the specific engineering listed in Section 4 — will tell you whether this is a company, a feature, or a portfolio piece. None of those outcomes are bad. Knowing which one you're in is the only thing that matters.

Good luck.
