# ScopeZero — Authorized Autonomy

Architecture and path of work for the repositioned product.

This document supersedes the positioning in `PRODUCT_ARCHITECTURE.md`. The
engine described there is reused almost entirely; what changes is **who we sell
to, what we lead with, and which one job we go deep on**. The code stays; the
product around it sharpens.

---

## 1. The repositioning in one line

**ScopeZero is the embeddable trust layer that companies building AI agents drop
in so their agents can take irreversible actions — move money, change cloud
infrastructure, send things to the outside world — without exceeding what a
human authorized, and with a verifiable receipt for every action.**

We do not detect bad agents. We make it impossible for an agent to exceed a
signed authority, and we prove it couldn't have. Detection is a probability
after the fact; we sell a guarantee before the fact. That guarantee only matters
where the action **cannot be undone** — so that is the only place we aim it.

### From → To

| | Old positioning | New positioning |
| --- | --- | --- |
| Product shape | Enterprise runtime authorization **gateway** | Embeddable authorization + containment + proof **SDK** (gateway is infra behind it) |
| Buyer | Enterprise CISO / platform security | **Builders of action-taking agents** (devops/cloud copilots, fintech-ops, RPA-killers) |
| Sold job | "Govern all agent tool calls" (horizontal) | "Let your agent take irreversible actions your customer will approve" (vertical) |
| Lead control | Policy verdicts + detection heuristics | **Signed authority + hard gate on irreversible actions + kernel containment + proof receipt** |
| Distribution | Top-down enterprise security sales | **Dev-led embed**, bottom-up |
| Winning line | "Authorize every action" | "The agent couldn't have done it — here's the proof" |

### What we stop leading with (keep, demote)

Command-center UI, broad connector registry, SIEM/CEF/LEEF exports, SOC2 control
map, behavior-anomaly and intent-drift heuristics. All real, all retained as
secondary surface. None of it is the pitch.

---

## 2. Core concepts — renamed for the new story

The mechanics are unchanged; the names are repointed at the buyer's mental model
(maker-checker / dual-control, which finance and ops already understand).

| Engine primitive (today) | Product name (repositioned) | Code |
| --- | --- | --- |
| Mission action contract / capsule | **Authority Grant** — a signed, scoped, expiring authority a human gives an agent | `src/capsules.js`, `src/crypto.js` |
| Action authorization | **Action Gate** — pre-execution decision, with irreversible actions as a first-class hard gate | `src/runtime.js`, `src/actionAuthorization.js`, `src/policyEngine.js` |
| Approval broker | **Co-Sign** — mandatory human dual-control on irreversible actions | `src/approvalNotifier.js`, approval endpoints |
| Egress proxy + NetworkPolicy | **Containment** — kernel-enforced boundary an injected agent can't route around | `src/proxyEnforcer.js`, `k8s/networkpolicy.yaml` |
| Hash-chained ledger | **Proof Receipt** — verifiable attestation per action, shown to the builder's own customer | `src/ledger.js`, `tools/verify-ledger.js` |

API stays backward-compatible; new names land as aliases in docs and SDK
surface, not as a breaking rewrite.

---

## 3. Architecture — four layers

```
   Human (delegator)
        │  approves a scope
        ▼
┌─────────────────────────────────────────────────────────────┐
│ 1. AUTHORITY   signed, time-boxed Authority Grant (Ed25519)  │  capsules.js / crypto.js
└─────────────────────────────────────────────────────────────┘
        │  agent attempts an action
        ▼
┌─────────────────────────────────────────────────────────────┐
│ 2. GATE        pre-execution decision (fail-closed)          │  runtime.js / policyEngine.js
│                ── irreversible action? → HARD gate + Co-Sign │  actionAuthorization.js
└─────────────────────────────────────────────────────────────┘
        │  action that leaves the process
        ▼
┌─────────────────────────────────────────────────────────────┐
│ 3. CONTAINMENT kernel egress boundary (only exit path)       │  proxyEnforcer.js / networkpolicy
└─────────────────────────────────────────────────────────────┘
        │  every decision
        ▼
┌─────────────────────────────────────────────────────────────┐
│ 4. PROOF       hash-chained Proof Receipt, independently     │  ledger.js / verify-ledger.js
│                verifiable by the builder's customer          │
└─────────────────────────────────────────────────────────────┘
```

**Layer 1 — Authority.** A human approves a scope (tools, data classes,
destinations, money/privilege limits, TTL). Signed into an Authority Grant. The
agent holds it; it cannot widen it (signature + `kid` keyset already enforce
this). Reused as-is.

**Layer 2 — Gate.** Each attempted action becomes an action descriptor
(`describeActionRequest`) and is matched against the grant
(`evaluateActionContract`) plus policy. The descriptor **already carries**
`action_type` ∈ {`payment`, `privilege_change`, `export`, `external_send`,
`delegate`}, plus `money`, `privilege`, and manifest `irreversible`/`mutating`
flags. The repositioning makes **irreversible** a non-overridable branch: an
irreversible action never returns bare `allow` — it requires Co-Sign, and
fails closed on gateway error.

**Layer 3 — Containment.** For irreversible actions that leave the process
(egress, external calls), the kernel egress boundary makes the gate the *only*
exit. An injected agent that skips the SDK still can't reach a destination
outside the grant. Reused as-is; this is the differentiator detectors lack.

**Layer 4 — Proof.** Every decision (allow / co-sign / refuse) is appended to a
hash-chained receipt that verifies independently. Repositioning adds a
**standalone receipt verifier** the builder can hand to *their* customer —
"don't trust us, verify the chain yourself."

---

## 4. The embed surface — this is the product

SDK-first. The spine already exists: `sdk/guard-core.js` (`authorizeAndExecute`)
is fail-closed authorize-then-execute. Builders wrap their agent's tool/function
layer once; every action routes through the four layers.

Two deploy shapes:

- **In-process SDK** — gate call to a local or hosted gateway. Fastest embed;
  gives Authority + Gate + Proof. (Containment requires the boundary below.)
- **Sidecar / proxy** — adds Layer 3. The kernel boundary is what turns "the SDK
  asks nicely" into "the agent physically can't." Required for the full
  irreversible-action guarantee.

The gateway (`server.js`) stays — it becomes infrastructure *behind* the SDK,
not the headline.

### Reuse / demote / build

**Reuse as-is:** `crypto.js`, `capsules.js`, `ledger.js`, `runtime.js`,
`policyEngine.js`, `actionAuthorization.js`, `guard-core.js`, `startupGate.js`,
`proxyEnforcer.js`, `store.js` / `postgresStore.js`.

**Demote (retain, stop leading):** command-center UI, SIEM exports, connector
registry breadth, `behaviorAnalyzer.js` / `missionAlignment.js` (advisory only,
never the sole control), compliance matrix.

**Build new:**
1. Generic SDK tool-call wrapper + framework adapters (beyond the existing
   OpenAI/Anthropic wrappers) so any agent loop embeds in minutes.
2. **Co-Sign** flow: irreversible actions require an out-of-band human
   approval before execution, on by default, not overridable from inside the
   agent.
3. **One deep irreversible-action connector** replacing a simulation (see §5).
4. **Standalone Proof Receipt verifier** — a tiny tool/library the builder's
   customer runs to confirm the chain, no ScopeZero trust required.
5. Builder quickstart + a runnable sample agent showing the 10-minute embed.

---

## 5. The wedge depth — pick ONE irreversible-action class first

Going deep on one class is what separates "product" from "feature." Breadth
(GitHub + Slack + AWS-sim) currently reads as a demo surface.

**First class: cloud / infrastructure mutations (IAM, prod changes).** Rationale:
`tools/aws-iam-pilot.js` already exists; the buyer (devops/platform agent
builders) is dev-led and reachable; the action is irreversible and audited;
"agent tried to grant itself AdministratorAccess → contained + receipt" is a
visceral hero demo.

**Second class (next): payment / money movement.** `payment` action type and
`money` descriptor field already exist. Maps cleanly to maker-checker.

Deepen the first class to real, not simulated: a live (scoped, safe) connector,
the `irreversible` flag enforced as a hard Co-Sign gate, and the resulting
receipt surfaced to the end customer.

---

## 6. Runtime flow (repositioned)

1. A human approves a scope → ScopeZero signs an **Authority Grant**.
2. The builder's agent attempts a tool action.
3. The SDK routes it through the **Gate**.
4. If the action is **irreversible**: hard gate → mandatory **Co-Sign**; if it
   egresses, the **Containment** boundary is the only exit path.
5. Execute only on explicit allow / completed co-sign; fail closed otherwise.
6. Append a **Proof Receipt**.
7. The builder shows the receipt to their customer: *authorized, in-scope,
   provable.*

---

## 7. Path of work

Five sprints. Sprint 1 is mostly framing + thin aliases (no rebuild); the depth
and trust investments are Sprints 2–5.

### Sprint 1 — Reposition the spine
- Rewrite `README.md`, `PITCH.md`, `PRODUCT_ARCHITECTURE.md` around Authorized
  Autonomy and the four layers.
- Land concept aliases (Authority Grant / Action Gate / Co-Sign / Containment /
  Proof Receipt) in docs and SDK naming; keep API backward-compatible.
- Demote UI / SIEM / connector breadth in all framing.
- Repoint the hero demo from pastebin exfil to an **irreversible action**
  (`breach-containment-demo.js` → IAM escalation / wire attempt).
- **Done when:** a builder reading the README understands the embed and the
  irreversible-action job in under two minutes.

### Sprint 2 — Irreversible-action depth
- Make `irreversible` a non-overridable branch in the Gate: never bare `allow`,
  always Co-Sign, fail-closed on error.
- Build the **Co-Sign** flow (out-of-band human approval, default-on).
- Replace one simulated connector (cloud/IAM) with a real, scoped, safe one.
- Tests for the hard gate and co-sign path.
- **Done when:** an agent cannot complete an irreversible cloud action without a
  human co-sign, proven by a test and the demo.

### Sprint 3 — Embed surface
- Generic SDK tool-call wrapper + at least one framework adapter beyond
  OpenAI/Anthropic.
- Document and script the sidecar deploy mode (Containment on).
- 10-minute quickstart + a runnable sample agent repo.
- **Done when:** a new builder embeds the SDK and bounds an agent in ≤10 min
  from a clean machine.

### Sprint 4 — Proof for the end customer
- Standalone **Proof Receipt verifier** (no ScopeZero trust required).
- Attestation export the builder hands their customer.
- "Prove it" doc: what the receipt asserts and how to verify.
- **Done when:** a third party verifies a receipt's chain without running
  ScopeZero.

### Sprint 5 — Trust the tech
- External red-team of the irreversible-action path (the real bar for a security
  product).
- Key-lifecycle hardening (rotation, ledger-secret handling) under adversarial
  review.
- Land one design-partner embed.
- **Done when:** someone who isn't us has tried to break the irreversible path,
  and one real builder has embedded it.

---

## 8. Proof the repositioning worked

Not a pilot, not an LOI. One agent-building company embeds the SDK and says:
**"we can now ship autonomous mode we couldn't ship before."** Unpaid
design-embed = signal. Paid = bet-on-it. That single sentence, said back
unprompted, is the metric the architecture serves.
