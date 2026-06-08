# ScopeZero

**ScopeZero authorizes every AI-agent action against a signed, human-delegated mission before it runs — and keeps a tamper-evident record of every decision, so you can prove what your agents did and that it was authorized.**

![ScopeZero containing a hijacked agent — run it yourself in 10s with `npm run demo:breach`](ScopeZero_Full_Project/gtm/scopezero-demo.gif)

> **The agent was authorized. The action was not.**

An AI agent is a worker you hand real keys to (GitHub, Slack, email, cloud, internal APIs). One hidden instruction in something it reads can hijack it into doing damage with those keys — and afterward you can't prove what it did. ScopeZero wraps that worker in three things:

1. **A signed permission slip** — what this agent may do, with what data, to where, until when. Cryptographically signed, can't be forged.
2. **A guard at the door** — every action is checked against the slip *before* it runs, and blocked if it's off-mission — even if the agent tries to skip the gate.
3. **A tamper-proof logbook** — every decision recorded so it can't be quietly rewritten.

New here? Start with the no-jargon explainer: [**ScopeZero in Plain English**](ScopeZero_Full_Project/gtm/PLAIN_ENGLISH.md).

## See it work — 10 seconds, no install

```bash
cd ScopeZero_Full_Project
npm run demo:breach    # a hijacked agent vs. a signed mission — every escape contained
npm run demo:exfil     # the hard case: a leak to an ALLOWED host, caught in the payload
```

No dependencies to install. Exit code is non-zero if any containment fails — the guarantee is executable, not a slide.

## Verify

```bash
cd ScopeZero_Full_Project
npm run check
npm test                # full automated suite
node tools/verify-ledger.js
```

We also red-teamed it ourselves and published what it *can't* yet stop: [**RED_TEAM.md**](ScopeZero_Full_Project/RED_TEAM.md).

## Repository Contents

- [`ScopeZero_Full_Project/`](ScopeZero_Full_Project/) — runtime gateway, policy engine, signed mission capsules, tamper-evident ledger, connectors, SDK, tests, examples, and deployment manifests. Full docs in its [README](ScopeZero_Full_Project/README.md).

## Where it fits

IAM decides whether an agent *has access*. ScopeZero decides whether the *exact autonomous action* is authorized before it executes — checked against mission, policy, data class, destination, risk, tool manifest, and approval rules before GitHub, Slack, AWS, SaaS APIs, or MCP tools are allowed to run.
