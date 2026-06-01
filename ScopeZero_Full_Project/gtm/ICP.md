# Ideal Customer Profile (who to talk to first)

Don't sell to "any company." Sell to the narrow buyer for whom this is already a
problem they feel. The goal of the first 5–10 conversations is **validation, not
revenue**: do they have the pain, would they deploy, what stops them.

## The bullseye

A company that is **already running autonomous AI agents with real credentials**
(GitHub, Slack, Gmail, AWS, internal MCP servers), in production or close to it,
**and** has at least one of:

- **Compliance pressure** — SOC 2, EU AI Act, HIPAA, or a customer security
  review that now asks "how do you control what your AI agents can do?"
- **A scare** — an agent already did something it shouldn't have (over-broad
  action, near-miss exfiltration, a prompt-injection incident).
- **Kubernetes** — they run workloads in K8s, so the strongest enforcement tier
  is a `kubectl apply` away (low integration friction). *(Docker-only is fine
  too now — internal-network lockdown — but K8s shops convert fastest.)*

## Who carries the pain (titles)

- Head of Security / CISO at an AI-native startup (Series A–C).
- Security engineer / platform engineer who owns the agent infrastructure.
- Head of AI / ML platform shipping internal or customer-facing agents.

## Where to find them

- AI-agent infra communities (MCP, LangChain, CrewAI, AutoGPT Discords/forums).
- "We're hiring an agent/AI platform engineer" job posts → that company runs agents.
- Security-leader Slack groups, LinkedIn posts about "AI agent security".
- YC / a16z portfolio companies building agent products.

## Disqualifiers (don't waste the conversation)

- No agents in production yet → it's hypothetical for them, they won't buy.
- Agents with no real credentials (read-only demos) → no blast radius, no pain.
- "We'll just prompt the model not to" → not a buyer yet; note and move on.

## The one question every conversation must answer

> "If one of your agents got prompt-injected tomorrow, what stops it from
> emailing your customer data out — and could you prove to an auditor it didn't?"

Their answer tells you if they're a buyer. If they shrug, they're not — yet.
