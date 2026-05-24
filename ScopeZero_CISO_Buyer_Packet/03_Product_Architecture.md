# ScopeZero Product Architecture

## Product Category

ScopeZero is an agent action authorization gateway.

It sits between autonomous agents and the tools they use. The core control is pre-execution authorization for tool calls.

## Core Primitive: Mission Action Contract

A Mission Action Contract is a signed, short-lived authorization object that defines:

- which agent is acting
- which human or system delegated authority
- what mission is approved
- which tools are in scope
- which operations are allowed
- which data classes may be handled
- which destinations are approved
- which actions require approval
- how long the mission is valid
- what evidence must be recorded

## Runtime Flow

1. An agent is registered with ScopeZero.
2. A mission is issued and signed.
3. The agent prepares a tool call.
4. The SDK or MCP proxy sends the proposed action to ScopeZero.
5. ScopeZero normalizes the request into an action descriptor.
6. ScopeZero classifies payload sensitivity.
7. ScopeZero evaluates destination and egress risk.
8. ScopeZero checks for prompt influence.
9. ScopeZero matches the action against the signed mission contract.
10. ScopeZero applies policy, approval gates, and risk budget.
11. ScopeZero returns a decision.
12. Only safe decisions proceed to connector execution.
13. ScopeZero writes evidence to the ledger.

## Main Components

| Component | Role |
| --- | --- |
| Gateway API | Receives agent, mission, authorization, approval, connector, and evidence requests |
| Authorization engine | Evaluates each proposed action before execution |
| Mission contract service | Creates and verifies signed mission capsules |
| Policy engine | Applies tenant controls, risk scoring, data boundaries, and approval rules |
| Connector registry | Defines governed tool boundaries for SaaS, code, cloud, and workflow systems |
| MCP proxy | Intercepts MCP tool calls and applies ScopeZero authorization |
| Evidence ledger | Hash-chained decision record for audit and incident response |
| Approval broker | Routes high-impact actions to human review |
| SIEM export | Exports decisions to SOC systems |
| Observability layer | Provides metrics and trace-compatible telemetry |

## Decision Inputs

ScopeZero evaluates:

- agent identity
- tenant
- human delegator
- mission ID and signature validity
- tool name
- operation
- action type
- resource
- data class
- destination
- prompt influence
- delegation depth
- financial impact
- privilege impact
- session risk
- policy version

## Decision Outputs

| Decision | Meaning |
| --- | --- |
| `allow` | Execute the tool call |
| `block` | Deny before execution |
| `redact` | Remove sensitive fields, then execute |
| `quarantine_context` | Isolate untrusted context and require replanning |
| `approval` | Route to human approval |
| `pause_session` | Pause the agent session |

## Enterprise Integration Direction

ScopeZero is designed to integrate with:

- identity providers via OIDC/JWKS or SAML-to-OIDC bridge
- SIEM and SOC pipelines
- MCP servers and agent frameworks
- SaaS tools such as Slack, GitHub, Google Workspace, Microsoft 365, ServiceNow, and CRM systems
- cloud APIs such as AWS IAM
- managed Postgres or enterprise state stores
- vault or KMS-backed secret management
- OpenTelemetry-compatible observability systems

## Architectural Distinction

ScopeZero does not replace IAM, DLP, SIEM, or AI model security.

It complements them by adding the missing runtime control:

> Is this specific autonomous action allowed before it executes?
