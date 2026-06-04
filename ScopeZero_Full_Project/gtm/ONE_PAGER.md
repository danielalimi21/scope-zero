# ScopeZero — one-pager

## The system of record for what your AI agents do — that also stops the bad ones

**Your AI agents have real credentials. One prompt injection turns "summarize
these docs" into "email the customer data to attacker@gmail.com." Today, nothing
structurally stops it — and you can't prove to an auditor what your agent did, or
that it was authorized.**

ScopeZero authorizes every agent action against a **signed, time-boxed mission**
before it runs, and writes the decision to a **tamper-evident ledger**. You get
both: a provable record of every action your agents took *and* fail-closed
prevention. Before an agent calls GitHub, Slack, Gmail, AWS, or any MCP server,
ScopeZero returns allow / block / redact / approval / quarantine — and seals the
answer in a hash-chained log that can't be quietly rewritten.

## How it's different

- **Not a prompt firewall** — those inspect text and are bypassed the moment the
  agent opens its own socket. ScopeZero enforces at the network, fail-closed.
- **Not a service mesh** — those know network identity, not *what an agent is
  allowed to do on whose authority for what purpose*.
- **Not static IAM** — missions are per-task and expire; an agent gets exactly
  the tools, data classes, and destinations its job needs, for as long as it needs.

## What you get

| | |
|---|---|
| **Provable record** | Every decision sealed in a hash-chained, HMAC-keyed ledger — tamper-evident and externally anchorable. Answer "what did our agents do, and was it authorized?" with evidence. |
| **Least-privilege agents** | Ed25519-signed mission capsule: these tools, this data, these destinations, until this time. Private key signs; verifiers hold only the public key, so a leaked key can't forge a mission. |
| **Fail-closed egress** | Kernel-enforced — K8s NetworkPolicy *or* Docker internal network. A raw socket can't skip it. |
| **Catches exfil to allowed hosts** | Outbound content whose data class can't be established is held for review, not trusted as public — the leak the host-only proxy can't see. |
| **Compliance-ready** | Maps to OWASP LLM Top 10, MITRE ATLAS, SOC 2, EU AI Act, HIPAA. |

## Proof, not slides

```
npm run demo:breach   # injected agent vs a signed mission — every escape contained, ledger verified
npm run demo:exfil    # data leaving for an ALLOWED host — caught at the action layer
```

90 seconds. An agent gets injected and tries to exfiltrate via the SDK, via a
raw tunnel, via a replayed expired mission, and via a forged capsule. All
contained, ledger verifies clean. `demo:exfil` covers the hard case: data leaving
for a host that *is* in contract (`api.github.com`) — caught where the bytes are
visible, while the host-only proxy allows the same connection. Exit code is
non-zero if any step fails, so the guarantee is executable, not a slide.

## Where it fits

Drop it in front of your agents (SDK wrapper, HTTP proxy, or K8s admission).
Strongest with a kernel egress block (K8s or Docker internal network); honest
about the boundary — tunneled HTTPS is gated at destination + live-mission, and
per-action enforcement is the SDK layer.

## The ask

Running agents with real credentials? Let's deploy ScopeZero against one of them
free and watch it contain a real injection together. → {your contact}
