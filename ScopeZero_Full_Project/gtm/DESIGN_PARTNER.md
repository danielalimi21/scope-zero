# Design-partner conversation

The artifact for the first 5–10 real conversations. Not a sales doc — a proposal
to build something together and find out, honestly, whether it's worth it. The
goal of these conversations is **validation, not revenue**.

Who to bring this to: see [ICP.md](ICP.md). One sentence — a team already running
autonomous agents with real credentials, that feels the "prove what they did"
pain (compliance pressure, a scare, or both).

---

## The 30-second version

> You're giving AI agents real credentials. When one gets prompt-injected — and
> it will — two things are true: nothing structurally stops it from acting outside
> its job, and you can't show an auditor what it actually did. ScopeZero gives the
> agent a signed, time-boxed mission, authorizes every action against it before it
> runs, and writes every decision to a tamper-evident record. You get a provable
> log of agent behavior *and* fail-closed prevention. I'll deploy it against one of
> your agents for free and we'll watch it contain a real injection together.

Lead with the **record** ("prove what your agents did"), because that's the
easier door and the harder thing to copy. The prevention is the depth.

---

## What we're proposing

A **time-boxed, free pilot** on **one** real agent workload. 4 weeks. White-glove
— we do the integration with your team, not a docs hand-off. No commitment to buy;
the deal is that we learn from you and you get real protection on one workload.

### What you commit

- **One real agent workload** with real credentials (GitHub / Slack / Gmail / AWS
  / an internal MCP server). Not a toy.
- **~1 hour/week** with the engineer who owns that agent.
- **Honest feedback** — including "this is in the way" or "this isn't worth it."
- If it works: **a reference conversation** with one other team, and a quote.

### What you get

- Enforcement deployed on one workload, at the tier you choose: SDK wrapper
  (governance + audit), HTTPS proxy (destination-level containment), or kernel
  egress lockdown (K8s NetworkPolicy / Docker internal network — bypass-proof).
- A **tamper-evident record** of every action that agent took — exportable for
  your auditor.
- A live demonstration of containment **on your workload**, against an injection
  scenario your team cares about.
- Direct influence on the roadmap, and locked early-design-partner pricing if you
  later choose to buy.

---

## Success criteria (agree these up front, in writing)

The pilot succeeds if, by week 4, all three hold on your workload:

1. **Containment** — a prompt-injection scenario your team designs is contained
   before execution (blocked or escalated), and we can show exactly why in the
   record.
2. **No breakage** — the legitimate agent path runs without false-positive blocks
   that the engineer who owns it considers unacceptable. (We tune the policy with
   you; over-blocking that gets it turned off is a failure, and we treat it as one.)
3. **Evidence an auditor accepts** — a ledger export answers "what did this agent
   do last week, and was each action authorized?" in a form your compliance/GRC
   contact signs off on.

If any of the three fails, we say so, and you owe us nothing. Defining "fail"
before we start is the point.

---

## Honest scope — what ScopeZero does NOT do

Say this unprompted. A security product that overclaims is worse than one that's
precise, and saying it first is how you earn the technical buyer.

- **It does not read inside an allowed TLS tunnel at the network layer.** The
  proxy gates by destination host; it can't inspect encrypted payloads. Payload-
  level control (e.g. catching sensitive data leaving for an *allowed* host) lives
  at the action/SDK layer, where the bytes are visible — `npm run demo:exfil`
  shows exactly this, and shows the proxy correctly allowing the same host.
- **It does not understand intent.** The mission-alignment and prompt-influence
  signals are heuristics — they raise risk and route to a human; they never block
  on their own. The deterministic contract gates (tool / operation / data class /
  destination) are what block. We don't sell the heuristics as the control.
- **It does not judge content quality** — hallucination, factual accuracy, model
  safety. That's another layer.
- **It does not protect a mis-scoped mission.** If the human grants an over-broad
  mission, the agent gets that breadth. ScopeZero enforces the contract you write;
  it doesn't write it for you.
- **Network enforcement is only as strong as the tier you deploy.** SDK-only is
  governance/audit (a raw socket can ignore it); real containment needs the kernel
  egress block. We'll tell you which tier you're on.

---

## The objections you'll hear (and the honest answer)

- **"How is this not my egress proxy with extra steps?"** — A proxy allow-lists
  hosts. It has no concept of a signed, human-delegated, time-boxed mission, no
  per-action authorization, and no tamper-evident record of decisions. The record
  is the part a proxy can't give you.
- **"You're TLS-opaque, so you don't stop exfil to my allowed hosts."** — At the
  network layer, correct — and we say so. We catch it at the action layer instead;
  `demo:exfil` proves it. The proxy is the backstop for un-instrumented egress.
- **"You're inline — aren't you a SPOF and a latency tax?"** — The enforcement
  gate is; the record is not (it can run out of path). In the pilot we measure the
  latency on your workload and you decide the tier. Fail-closed is a deliberate
  choice — we'll show you the failure behavior.
- **"Who writes the missions? If my dev over-scopes, I'm unprotected."** — True,
  and it's why we tune scoping with you in the pilot. We can also derive a starting
  mission from the agent's observed behavior so you're not authoring from scratch.
- **"Maturity?"** — Early. That's why it's a free design-partner pilot, not a
  six-figure contract. You get influence and locked pricing for taking the bet.

---

## The close

> Are you running an agent with real credentials today? Pick the one that would
> scare you most if it got injected. That's the one we deploy against — free, four
> weeks, and we define up front what "it worked" means. Worst case, you get a
> tamper-evident record of that agent for a month and an honest read on the risk.

→ {your contact}
