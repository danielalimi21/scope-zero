# ScopeZero Demo Access And Evaluation

## Demo Purpose

The ScopeZero demo is designed to prove one control:

> Can an autonomous agent action be authorized or denied before the downstream tool call executes?

The demo is not a static mockup. It demonstrates the runtime pattern: mission contract, proposed action, deterministic decision, connector outcome, and tamper-evident evidence.

## Recommended Demo Format

The strongest format is a guided 20-minute technical demo.

Recommended attendees:

- CISO or security architecture leader
- AI platform owner
- identity/security engineering owner
- cloud security or AppSec owner
- SOC/detection engineering reviewer

## Demo Flow

1. Review the mission contract.
2. Show how an agent proposes a tool action.
3. Show the action normalized into a common authorization descriptor.
4. Show ScopeZero evaluating policy before execution.
5. Show safe actions being allowed.
6. Show unsafe actions being blocked before the tool call reaches the destination.
7. Show high-impact actions routed to approval.
8. Show the evidence ledger and decision reason codes.

## Proof Scenarios

| Surface | Scenario | Expected Outcome |
| --- | --- | --- |
| GitHub | Safe documentation pull request | Allowed |
| GitHub | Dangerous out-of-contract pull request | Blocked before execution |
| Slack | Safe internal communication | Allowed |
| Slack | Sensitive or prompt-influenced communication | Blocked before execution |
| AWS IAM | Admin privilege escalation | Blocked before cloud mutation |
| AWS IAM | High-impact policy change | Routed to approval |

## What Evaluators Should Look For

The key evaluation questions are:

- Did ScopeZero decide before execution?
- Was the decision based on identity, mission, tool, operation, data, destination, and risk?
- Did the decision produce clear reason codes?
- Could the security team explain the decision after the fact?
- Could the control fit into an existing agent, MCP, SaaS, cloud, or SOC workflow?
- Which connector or workflow would make this valuable in the evaluator's environment?

## Access Options

ScopeZero can be evaluated in three ways:

1. Guided demo: a live walkthrough of the runtime, proof scenarios, and evidence.
2. Controlled technical pilot: deployed against one approved internal workflow and one or two connectors.
3. Architecture review: review of the gateway API, mission contract model, policy logic, and evidence design.

## Best Pilot Candidate

The best first pilot is narrow:

- one agent workflow
- one mission contract
- one or two enterprise tools
- one high-risk blocked action
- one approval-gated action
- one evidence report reviewed by security

The goal is not to replace existing controls. The goal is to prove that pre-execution agent action authorization adds a missing control point.

## Success Criteria

A successful evaluation proves:

- safe in-scope actions continue
- out-of-scope actions are blocked before execution
- sensitive egress is denied or redacted
- high-impact actions require approval
- the evidence is usable by security, SOC, GRC, or incident response teams
- the buyer can identify the next production connector

