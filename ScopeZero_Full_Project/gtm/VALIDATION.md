# Validation plan — does Authorized Autonomy pull?

Purpose: find out **who pulls hardest and whether they'll pay** before we build
the deep features (real connector, co-sign UX, sidecar). The architecture is
sound under any path; the open question is the buyer. Let the market pick the
lane — don't let it be picked by assumption.

## The bet being tested

Builders of agents that take irreversible actions can't ship "autonomous mode"
their enterprise customers approve. ScopeZero is the embeddable layer that lets
them. If true, a builder embeds the demo and says: *"we can now ship autonomous
mode we couldn't ship before."* That one sentence, said back unprompted, is the
signal. Paid pilot = strong signal. Polite interest = not it.

## Two segments to test in parallel

Run both for ~2 weeks, ~5 conversations each, then double down on whichever pulls.

**A. Agent builders (primary hypothesis — dev-led, reachable).**
Companies building action-taking agents: cloud/devops copilots, fintech-ops
agents, automation that mutates production. Reach: founders/eng leads, dev
communities, MCP / agent-framework ecosystems, YC batches building agents.

**B. Enterprise security buyers (fallback — higher willingness to pay, slower).**
Platform-security / CISO teams at companies *deploying* action-taking agents
internally. Reach: warm intros, AI-security communities.

## The one-line (open with this)

> "We let AI agents take irreversible actions — move money, change cloud infra —
> without exceeding what a human signed for, and with a receipt you can verify.
> The agent can't grant itself admin or wire money out; legitimate irreversible
> actions need a human co-sign. Want to see it contain a hijacked agent in 10
> seconds?"

Then: `npm run demo`. The demo is the pitch.

## Cold message template (builders)

> Subject: shipping autonomous mode your customers will approve
>
> You're building an agent that takes real actions. The wall most teams hit:
> enterprise customers won't approve an agent that *might* do something
> irreversible it shouldn't — and "we have a prompt-injection filter" isn't an
> answer for an agent that can move money or change infra.
>
> I built the layer that fixes that. The agent works autonomously inside a signed
> authority; it's blocked before execution if it tries to exceed it; irreversible
> actions need a human co-sign; every action gets a verifiable receipt. Runs in 10
> seconds: `npm run demo`.
>
> Worth 20 minutes? I want to know if this removes a blocker for you — or if I'm
> wrong about the problem.

## The five discovery questions (don't pitch — listen)

1. What's the most irreversible thing your agent can do today? What happens if it
   does it wrong?
2. Has a customer (or your own security team) blocked or slowed a launch over
   exactly this? What did they ask for?
3. What do you do about it now — DIY guardrails, a vendor, or "we don't let it do
   that yet"?
4. If embedding a layer made "the agent can't exceed what a human signed for, and
   here's the proof" true — does that unblock something specific for you?
5. Who would have to approve paying for it, and what would they need to see?

## What counts as signal (be honest with yourself)

- **Strong:** a paid pilot, or a builder embedding the SDK into a real product and
  telling their customer about it.
- **Real:** "this unblocks our enterprise deal" with a named deal.
- **Weak (discard):** "cool, neat demo," "we'd consider it later," "send me docs."
  Politeness is not demand.

## Decision gate (after ~10 conversations)

- Builders pull hardest → build Sprint 2 (deep connector + co-sign) for them, SDK-first.
- Enterprise pulls hardest → same engine, repackage for direct deployment + the
  attestation/compliance angle.
- Neither pulls → the wedge is early. Hold the build; revisit when more agents
  take irreversible actions in production. Don't build deep into silence.

## Cost discipline

Sprint 1 (done: repositioned docs + hero demo) is the only spend that precedes a
signal. Everything in Sprints 2–5 of [REPOSITIONING.md](../REPOSITIONING.md) waits
on a pull from this plan.
