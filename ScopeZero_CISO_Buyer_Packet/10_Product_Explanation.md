# ScopeZero Product Explanation

## Simple Explanation

ScopeZero is a security checkpoint for AI agents before they take action.

An AI agent is useful because it can do work: open a pull request, send a Slack message, read data, create a ticket, call an API, or change cloud permissions. That is also the danger. If the agent is confused, tricked, over-permissioned, or pointed at the wrong tool, it can do real damage very quickly.

ScopeZero sits between the agent and the tools.

Before the agent is allowed to do anything, ScopeZero asks:

- Who is this agent?
- What mission was it given?
- Which human or system approved that mission?
- Which tools is it allowed to use?
- What type of action is it trying to perform?
- What data is involved?
- Where is the data going?
- Is this action normal for the mission?
- Is this too sensitive, too risky, or too powerful to run automatically?
- Should this be allowed, blocked, redacted, paused, or sent to a human for approval?

The important part is that ScopeZero decides before the tool call executes.

If the action is safe and matches the approved mission, ScopeZero allows it. If the action is dangerous, outside the mission, includes sensitive data, looks prompt-influenced, or tries to change privileges, ScopeZero blocks it or asks for human approval.

It does not need to be an LLM to make that decision. It uses deterministic policy checks, signed mission contracts, data classification, destination rules, risk scoring, approval gates, and an evidence ledger.

In plain English:

> ScopeZero gives companies a way to let AI agents work without giving them unlimited freedom.

## Industry Explanation

ScopeZero is a vendor-neutral action authorization gateway for autonomous AI-agent tool calls.

It addresses a gap that sits between IAM, AI gateway controls, DLP, SIEM, and SaaS security posture tools. Traditional IAM can answer whether an identity has permission to access a tool. It usually does not answer whether a specific autonomous action is appropriate for the current mission, data class, destination, prompt context, privilege level, and risk state.

ScopeZero introduces a pre-execution authorization layer for agent actions.

The core primitive is the Mission Action Contract: a signed, short-lived authorization object that defines the mission boundary for an agent. It specifies allowed tools, operations, data classes, destinations, delegation depth, approval requirements, and evidence obligations.

At runtime, every proposed agent tool call is normalized into a vendor-neutral action descriptor. ScopeZero evaluates that descriptor against the signed mission contract and tenant policy before allowing connector execution.

The decision engine evaluates:

- agent identity and registration status
- mission status, signature validity, and expiration
- tool and operation allowlists
- action type, such as read, write, export, external send, privilege change, payment, or delegation
- data class, including public, internal, confidential, and restricted
- destination trust boundary and egress risk
- prompt influence or untrusted-context indicators
- delegation depth
- financial impact
- administrative privilege impact
- session risk budget
- high-impact action approval gates
- policy version and evidence requirements

The output is a deterministic decision:

- `allow`: execute the tool call
- `block`: deny before execution
- `redact`: remove sensitive fields before execution
- `quarantine_context`: isolate untrusted context and require replanning
- `approval`: route to a human approver
- `pause_session`: pause the agent session

ScopeZero has proof coverage across code, communication, and cloud privilege surfaces:

- GitHub: allowed an in-contract pull request and blocked a dangerous out-of-contract pull request
- Slack: allowed a safe internal message and blocked a sensitive prompt-influenced message
- AWS IAM: blocked admin privilege escalation and routed a high-impact policy change to approval

Every decision is written to a tamper-evident evidence chain so security teams can review what the agent attempted, which policy was applied, why the action was allowed or denied, and what evidence hash proves the decision sequence.

The product is designed to integrate through SDK, API, MCP proxy, and tool connectors. It complements IAM, SIEM, DLP, SSPM, and AI security gateways by enforcing authorization at the action boundary:

> IAM governs access. ScopeZero governs autonomous action.

