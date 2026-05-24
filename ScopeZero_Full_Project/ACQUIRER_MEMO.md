# ScopeZero Acquirer Memo

## Strategic Thesis

ScopeZero is a control plane for the next enterprise security gap: autonomous AI-agent actions.

The winning cybersecurity platforms already protect humans, devices, workloads, networks, cloud assets, SaaS, and data. The next category is different. AI agents are delegated actors that can interpret context, chain tasks, call tools, and move across enterprise systems. They require runtime authorization based on signed mission contracts, not only static access.

## Why A Major Cyber Company Would Care

AI agents create risk across several existing security categories at once:

- **Identity security:** every agent needs ownership, scope, rotation, and deprovisioning.
- **Data security:** agents can leak sensitive data through prompts, tools, files, and generated outputs.
- **Cloud security:** agents can alter infrastructure faster than review teams can react.
- **SOC:** agent behavior needs detection, replay, triage, and response.
- **SASE and network:** agent tool traffic needs inspection and policy enforcement.
- **GRC:** regulated companies need evidence that autonomous actions were controlled.

That makes ScopeZero strategically relevant to multiple large acquirers, not only one niche budget.

## The Product Wedge

Start as an **Agent Action Authorization Gateway**.

Developers route agent tool calls through ScopeZero. The gateway evaluates each action before execution:

1. Is the agent identity valid?
2. Which human or system delegated authority?
3. What mission was approved?
4. Which mission action contract covers this tool and operation?
5. Is the data class allowed by the contract?
6. Is the destination approved?
7. Was the request influenced by untrusted content?
8. Does the action exceed risk budget or approval thresholds?

Then ScopeZero returns: allow, block, redact, quarantine, approve, or pause.

## Breakthrough Claim

The breakthrough is the **Mission Action Contract**.

Classic identity says:

> This actor has permission to access this resource.

ScopeZero says:

> This autonomous actor can perform this action only if the requested tool, operation, data class, destination, and impact level match a signed human-approved mission contract.

That difference matters because agent misuse often happens through valid credentials and valid tools. The breach is not always unauthorized access. It is authorized access used for the wrong intent.

## Defensibility

ScopeZero compounds through action authorization telemetry:

- agent missions
- mission action contracts
- tool call patterns
- prompt-influence signals
- data-boundary decisions
- blocked misuse patterns
- approval outcomes
- incident evidence chains

This dataset becomes a proprietary map of how autonomous work behaves inside real enterprises.

## Platform Roadmap

1. Agent tool gateway
2. Mission action contract registry
3. Prompt-injection and context influence detection
4. Sensitive data egress controls
5. Human approval workflow
6. SIEM and SOC integrations
7. Agent-to-agent delegation controls
8. Compliance evidence export
9. Runtime anomaly models
10. Industry protocol for agent action authorization telemetry

## Demo Message

The demo should land one point:

> The agent was authorized. The action was not.

That is the category.

## Potential Strategic Buyers

- Identity platforms that need agent identity.
- Endpoint and XDR platforms that need agent behavior telemetry.
- Cloud security platforms that need AI automation control.
- SASE platforms that need a new traffic boundary.
- SIEM vendors that need high-value agent telemetry.
- AI platforms that need enterprise trust and compliance.

## Why Build This Now

The enterprise is moving from AI assistants to AI actors. Once agents can act across production systems, the absence of runtime authorization becomes a board-level risk.

The company that defines this layer can become the security standard for autonomous work.
