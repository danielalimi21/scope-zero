# ScopeZero — Authorized Autonomy

**The trust layer companies embed so their AI agents can take irreversible
actions — move money, change cloud infrastructure, send things outside — without
ever exceeding what a human authorized, with a verifiable receipt for every one.**

---

## The problem

The moment an agent stops *drafting* and starts *doing* — wiring a payment,
attaching an IAM policy, sending an email, merging a PR — the rules change. A bad
draft is an edit away from fixed. A bad wire is gone. A bad privilege grant is a
breach. And agents are confused deputies by design: they read untrusted content
(web pages, tickets, tool output) and then act with real credentials. One prompt
injection turns "review these invoices" into "wire the balance to this account."

The teams building these agents hit a wall: **their own enterprise customers
won't approve an agent that *might* take an irreversible action it shouldn't.**
"We have a prompt-injection classifier" is not an answer a CISO accepts for an
agent that can move money. Detection is a probability after the fact. What's
needed is a guarantee before the fact — and proof.

## Why existing answers don't fit

- **Guardrail / prompt-firewall SDKs** inspect content. An injected agent opens
  its own socket and routes around them; and "probably safe" doesn't hold for an
  irreversible action.
- **AI gateways** (route + cache + observe LLM calls) govern the *model call*,
  not the *action* the agent then takes against the world.
- **IAM** is static and identity-scoped; an agent's authority is per-task,
  ephemeral, and needs to be *narrower* than the human's.
- **SIEM / audit** tells you what happened after it happened. Too late for the
  action you can't undo.

## The wedge — Authorized Autonomy

A human signs a **scoped, time-boxed authority** for the agent (Ed25519). Before
each action, ScopeZero decides:

1. **In authority → run.** The agent works autonomously inside its signed scope.
2. **Exceeds authority → contained.** Blocked before execution — self-granting
   admin, wiring money out, sending to an off-contract destination. The kernel
   egress boundary means an agent that skips the SDK still can't reach a
   destination outside its authority.
3. **Irreversible but legitimate → human co-sign.** Privilege change, payment,
   external send are held for an out-of-band human approval, then cleared — not
   run on the agent's word, not blocked outright.
4. **Always → a tamper-evident receipt.** Every decision is hash-chained and
   independently verifiable. The builder hands it to *their* customer:
   *authorized, in-scope, provable.*

## Why an incumbent can't trivially ship this

The differentiator is the *combination*: a **cryptographic human→agent authority**
+ **kernel-enforced containment** an injected agent can't route around + a
**mandatory co-sign on irreversible actions** + a **receipt your customer can
verify without trusting you.** Detectors don't contain; gateways don't bind
actions to a signed human delegation; service meshes have no concept of a mission.
The intersection is the position.

## The proof — run it in 10 seconds

```
npm run demo          # Authorized Autonomy, end to end
npm run demo:breach   # injected agent vs. a signed authority — every escape contained
npm test              # 259 tests, 0 failures
```

`npm run demo` walks one agent through the whole story: an in-scope read runs
autonomously; a self-grant of AdministratorAccess is contained; a $250k wire to
an outside account is contained; a *legitimate* policy change is held for a human
co-sign, approved, then cleared; the receipt verifies clean. Exit code is
non-zero if any guarantee fails — the proof is executable, not a slide.

## Who it's for

Companies **building agents that take real actions** — cloud/devops copilots,
fintech-ops agents, automation that mutates production systems. They embed
ScopeZero so they can ship "autonomous mode" their customers actually approve.

## Honest scope

The full containment guarantee on egress holds only with the kernel egress block
applied (Kubernetes NetworkPolicy or a Docker internal network) — that's the hard
part, and we lead with it rather than overclaiming. The advisory signals
(content classifier, prompt-influence heuristic) raise risk and route to a human;
they are never the sole control — the deterministic authority gates and the
co-sign are. A security product that overclaims is worse than one that's precise.

## The line

**Embed ScopeZero and your agent can take real actions your customer will sign
off on: it can't exceed the authority a human gave it, irreversible moves need a
co-sign, and every action is provable. Skip it and you're asking an enterprise to
trust that your agent never reads anything malicious. It will.**
