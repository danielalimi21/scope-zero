# Outreach — start 5 conversations this week

Goal: book 5 short calls with people who match `ICP.md`. You're not selling a
license; you're offering to solve a problem for free in exchange for the truth
about whether it's a real problem. That's a design-partner motion.

## Cold message (LinkedIn / email / Slack DM)

> Subject: containing prompt-injected agents
>
> Hi {name} — saw {company} is running {agents / an AI agent product}. Quick one:
> when an agent gets prompt-injected, what stops it from using its real
> credentials to exfiltrate data — and could you prove to an auditor it didn't?
>
> I built ScopeZero: a fail-closed gate that binds every agent action + network
> call to a signed, time-boxed mission, and logs it to a tamper-evident ledger.
> There's a 90-second runnable demo of an injected agent getting contained.
>
> Not selling anything — looking for 3–4 security folks running agents to tell me
> if this is real or if I'm solving a non-problem. 15 min?

Keep it short. Lead with their pain, not your features. The "tell me if I'm
wrong" framing gets replies because it's low-pressure and flattering to the expert.

## The design-partner offer (on the call, if they have the pain)

> I'll deploy ScopeZero against one of your agents, free, and we'll watch it
> contain a real injection attempt together. In exchange: honest feedback, and
> if it's useful, a quote or intro. No contract, no cost.

Design partners give you: proof it works on real traffic, the integration
friction list, and the language real buyers use (which becomes your pitch).

## What to actually learn (write these down after each call)

1. Do they run agents with real credentials in prod? (pain exists / doesn't)
2. Have they had an incident or near-miss? (urgency)
3. What's their current "control"? (usually: nothing / prompt instructions)
4. Would they deploy a gateway? **What stops them?** (the real objection)
5. Who signs off — them, or a CISO/compliance gate? (buyer vs user)

## The kill criterion (be honest with yourself)

If you talk to 8–10 ICP-matched people and none have the pain or would deploy,
that's the most valuable signal you can get — **before** building more. Either
the timing is early or the wedge is wrong. Don't explain it away; act on it.

## Assets to send

- 90-second demo: `npm run demo:breach` (record it as a Loom/asciinema).
- One-pager: `gtm/ONE_PAGER.md`.
- Try-it-yourself: `gtm/QUICKSTART.md` (10 minutes, their machine).
