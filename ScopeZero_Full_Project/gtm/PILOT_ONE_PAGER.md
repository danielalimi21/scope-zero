# ScopeZero — what a first pilot looks like

**Signed authority for AI agents.** A 3–4 week design-partner pilot to put
ScopeZero on your agents — visibility first, enforcement when you're ready, zero
production risk at the start.

---

## The shape: observe first, enforce when you trust it

**Week 1 — Observe (zero risk).**
Deploy the ScopeZero gateway next to your agents and wrap your agent's action
layer with the SDK. Run in **monitor mode**: ScopeZero records every agent action
and the decision it *would* make — allow, block, or hold for human co-sign — into
a tamper-evident, hash-chained ledger. It **never blocks**. You get full
visibility across your agent fleet on day one, and a provable record of agent
behavior most teams don't have today.

**Weeks 2–3 — Enforce one irreversible action.**
Pick the action that scares you most — a payment, an IAM/config change, an
external send. Turn enforcement on just for that: out-of-scope is blocked before
execution, and the action is held for a one-click human co-sign (in your Slack or
your own tooling). Everything else stays in observe.

**Weeks 3–4 — Review and decide.**
Look at the evidence together: what observe caught, how enforce behaved, whether
the co-sign flow fits your team. Decide whether to expand.

## What you provide

- One real agent workload (start on a non-critical path).
- An engineer as the integration point (a few hours, week 1).
- A Slack channel (or endpoint) for the human co-sign.
- Honest feedback.

## What I provide

- The gateway, SDK, and hands-on integration — I do the heavy lifting.
- The co-sign wiring into your Slack/tooling.
- Daily support through the pilot; fast fixes.
- The tamper-evident audit ledger and a receipt verifier.

## Success criteria (agreed up front)

- Observe gives you full visibility into agent actions you couldn't see before.
- Observe surfaces real would-block / would-co-sign events on your workload.
- Enforce holds the chosen irreversible action **without** false-blocking
  legitimate ones.
- The human co-sign flow works in your environment.
- The ledger verifies clean — provable to your team or your customer.

## Commercials

**Free.** This is a design-partner pilot — no cost. In exchange: your candid
feedback, and if it delivers, a reference or the right to say we work together.
I'm early and pre-revenue; I'm optimizing for getting this right on a real
workload, not for a contract.

## Honest boundaries

- Single-replica is fully correct; multi-replica has documented trade-offs we'll
  scope to your setup. Capacity is there — ~1,300 authorizations/sec across
  hundreds of agents in testing.
- Not yet externally security-audited — that's the next bar, and a pilot is a good
  forcing function for it. We start on a non-critical path for exactly this reason.
- The classifier/heuristics are advisory; the real controls are the deterministic
  authority gates, kernel-level containment, and the human co-sign.

## Next step

A 30-minute technical scoping call: pick the one agent flow and the one
irreversible action to start with, and I'll have you running in observe mode that
week.
