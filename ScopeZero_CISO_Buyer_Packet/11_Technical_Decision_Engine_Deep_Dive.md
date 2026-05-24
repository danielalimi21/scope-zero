# ScopeZero Technical Decision Engine Deep Dive

## Design Goal

ScopeZero is built around a narrow control objective:

> No autonomous agent tool call should execute until it is authorized against identity, mission, policy, data, destination, and risk.

The engine is deterministic by design. It does not require an LLM to decide whether a tool call is safe. That makes decisions repeatable, explainable, auditable, and suitable for security review.

## Runtime Inputs

For each proposed tool call, ScopeZero receives a structured authorization request:

- agent ID
- tenant ID
- mission ID
- tool name
- requested operation
- payload
- destination
- resource
- context signals
- delegation depth
- financial impact
- privilege impact
- output channel

ScopeZero enriches that request with:

- registered agent metadata
- the active mission capsule
- tenant policy
- payload sensitivity classification
- prompt influence detection
- destination trust evaluation
- current session risk

## Step 1: Normalize The Tool Call

Agents and tools speak different languages. GitHub, Slack, AWS, Google Workspace, ServiceNow, and MCP tools all have different request shapes.

ScopeZero converts each request into a common action descriptor:

| Field | Meaning |
| --- | --- |
| `tool` | The tool being called, such as `github.pr`, `slack.draft`, or `aws.iam.attachPolicy` |
| `operation` | The normalized operation, such as `read`, `write`, `export`, or `privilege_change` |
| `action_type` | The risk category of the action |
| `vendor` | The tool family or connector owner |
| `resource` | The target resource |
| `data_class` | The sensitivity class of the involved data |
| `destination` | Where the result or data is going |
| `delegation_depth` | Whether the agent is handing work to another agent |
| `money` | Financial impact, if present |
| `privilege` | Privilege impact, if present |

This gives ScopeZero one authorization language across many tools.

## Step 2: Classify The Payload

ScopeZero inspects payloads and explicit classification labels to assign a data class:

- `public`
- `internal`
- `confidential`
- `restricted`

The current engine detects markers such as secrets, API keys, private keys, payroll terms, payment or banking terms, confidential markers, personal data indicators, customer revenue language, and email addresses.

This classification affects the decision. For example, an agent can be allowed to post a normal internal Slack update but blocked from posting restricted customer revenue or credential material.

## Step 3: Detect Prompt Influence

Autonomous agents often act on text from emails, tickets, documents, web pages, repositories, chats, or tool outputs. That text can contain malicious instructions.

ScopeZero checks whether the current action is influenced by untrusted context or blocked instruction patterns. If prompt influence is detected, the engine can quarantine the context, block the action, or require replanning.

This matters because the dangerous instruction may not come from the user. It may come from a document, issue, webpage, pull request comment, or SaaS record the agent read.

## Step 4: Evaluate The Mission Action Contract

The Mission Action Contract is the primary authorization boundary.

It defines what the agent is allowed to do for this mission:

- allowed tools
- allowed operations
- allowed data classes
- allowed destinations
- maximum delegation depth
- default effect, such as allow or approval

ScopeZero checks the normalized action against the contract:

1. Does this tool appear in the contract?
2. Is this operation allowed for that tool?
3. Is this data class within the mission boundary?
4. Is this destination approved?
5. Does the contract require approval instead of direct execution?

If the action does not match the contract, ScopeZero blocks it before execution.

## Step 5: Apply Tenant Policy

The tenant policy adds organization-wide rules on top of the mission.

Examples:

- require action contracts for all tool calls
- enforce strict data-class boundaries
- enforce strict destination boundaries
- block specific action types
- block mission drift
- enable prompt-injection shielding
- block sensitive external egress
- limit delegation depth
- require approval for financial actions
- require approval for administrative privilege changes
- redact sensitive outputs
- enforce runtime risk budgets

This lets the enterprise define global rules while still giving each agent a short-lived mission boundary.

## Step 6: Score Risk

ScopeZero maintains a risk score for the proposed action.

Risk increases when the action contains sensitive data, uses an unknown agent, has no valid mission, tries an out-of-scope tool, crosses an external destination boundary, shows prompt influence, exceeds delegation depth, involves money, changes privileges, or would push the session over its risk budget.

The score is not the only control. Hard policy violations still block the action. The risk score helps rank severity, trigger approvals, and explain why a decision was made.

## Step 7: Choose The Strongest Decision

ScopeZero uses an ordered decision model:

1. `allow`
2. `redact`
3. `quarantine_context`
4. `approval`
5. `pause_session`
6. `block`

If multiple rules apply, the engine keeps the strongest required decision.

For example:

- A safe documentation PR can be allowed.
- A Slack message with restricted data sent externally can be blocked.
- A cloud policy change can be routed to approval.
- A prompt-influenced tool call can be quarantined before replanning.
- A sensitive summary can be redacted before execution.

## Step 8: Execute Only If Safe

Only decisions marked safe can proceed to connector execution.

Safe execution decisions are:

- `allow`
- `redact`

All other decisions stop the tool call from reaching the downstream system unless a human approval flow completes.

This is the key architectural point:

> ScopeZero does not merely observe bad actions. It prevents unauthorized actions before the tool call executes.

## Step 9: Write Evidence

Every decision is written to a tamper-evident ledger.

The evidence record includes:

- request summary
- normalized action descriptor
- decision
- reason codes
- controls applied
- risk score
- required action
- policy context
- evidence hash
- chain linkage

This creates a verifiable record for SOC review, incident response, GRC, legal review, and executive reporting.

## Why Deterministic Matters

LLMs are useful for reasoning, generation, and workflow planning. They are not ideal as the final authorization authority for high-impact enterprise actions.

ScopeZero's authorization layer is deterministic so that:

- the same input and policy produce the same decision
- every decision can be explained with reason codes
- controls can be tested with unit and proof scenarios
- CISOs can review policy logic
- auditors can verify evidence
- enterprises can run the gateway without sending decision logic to an external model

ScopeZero can be used with LLM-powered agents, but the control plane itself does not depend on an LLM to decide whether the action is allowed.

## Security Outcome

ScopeZero turns agent autonomy into governed autonomy.

The enterprise can let agents operate across useful tools while enforcing mission scope, data boundaries, destination controls, approval gates, and evidence capture at the exact point where risk becomes action.

