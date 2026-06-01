# ScopeZero — one-pager

## The gate that contains a prompt-injected agent

**Your AI agents have real credentials. One prompt injection turns "summarize
these docs" into "email the customer data to attacker@gmail.com." Today, nothing
structurally stops it — and you can't prove to an auditor what your agent did.**

ScopeZero is a pre-execution authorization gateway for AI agents. Before an
agent calls GitHub, Slack, Gmail, AWS, or any MCP server, ScopeZero checks a
**signed, time-boxed mission** and returns allow / block / redact / approval /
quarantine. Every decision is sealed in a **tamper-evident ledger**.

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
| **Least-privilege agents** | Signed mission capsule: these tools, this data, these destinations, until this time. |
| **Fail-closed egress** | Kernel-enforced — K8s NetworkPolicy *or* Docker internal network. A raw socket can't skip it. |
| **Tamper-evident audit** | HMAC-keyed hash-chained ledger. Court-admissible "here's exactly what the agent did." |
| **Evasion-resistant detection** | Prompt-injection shield (homoglyph/spacing/base64), behavioral anomaly detection. |
| **Compliance-ready** | Maps to OWASP LLM Top 10, MITRE ATLAS, SOC 2, EU AI Act, HIPAA. |

## Proof, not slides

```
npm run demo:breach   # injected agent vs a signed mission — every escape contained, ledger verified
```

90 seconds. An agent gets injected and tries to exfiltrate via the SDK, via a
raw tunnel, via a replayed expired mission, and via a forged capsule. All
contained. The ledger verifies clean.

## Where it fits

Drop it in front of your agents (SDK wrapper, HTTP proxy, or K8s admission).
Strongest with a kernel egress block (K8s or Docker internal network); honest
about the boundary — tunneled HTTPS is gated at destination + live-mission, and
per-action enforcement is the SDK layer.

## The ask

Running agents with real credentials? Let's deploy ScopeZero against one of them
free and watch it contain a real injection together. → {your contact}
