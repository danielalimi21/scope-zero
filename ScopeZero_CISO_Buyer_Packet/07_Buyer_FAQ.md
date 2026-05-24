# ScopeZero Buyer FAQ

## Is ScopeZero an AI agent?

No. ScopeZero is not an agent. It is a control layer between agents and tools.

Agents request tool actions. ScopeZero decides whether those actions are allowed before execution.

## Does ScopeZero use an LLM to make security decisions?

The core authorization decision is deterministic. It is based on policy, signed mission contracts, data class, destination, prompt influence signals, risk budget, and approval rules.

LLMs may be used in the future for summaries, explanations, or analyst assistance, but the enforcement decision should remain deterministic and auditable.

## How is this different from IAM?

IAM answers whether an identity can access a system.

ScopeZero answers whether a specific autonomous action should execute right now.

An agent may have valid credentials and still attempt an action outside its approved mission.

## How is this different from DLP?

DLP focuses on sensitive data detection and movement.

ScopeZero evaluates a broader action context:

- identity
- delegation
- mission
- tool
- operation
- data
- destination
- prompt influence
- privilege impact
- approval rules

## How is this different from SIEM?

SIEM usually records and correlates events after they happen.

ScopeZero makes a pre-execution decision and then exports evidence to the SOC.

## Does ScopeZero replace AI safety tools?

No. AI safety tools and prompt security are complementary.

ScopeZero focuses on tool-call authorization: what the agent is allowed to do in enterprise systems.

## What is the first buying motion?

The recommended first step is a controlled pilot around one agent workflow and two or three tools.

## What does a strong pilot prove?

It proves that ScopeZero can:

- allow in-scope actions
- block out-of-scope actions before execution
- route high-impact actions to approval
- produce evidence the security team can review

## What systems should ScopeZero integrate with first?

Common first integrations:

- GitHub
- Slack or Microsoft Teams
- AWS IAM
- Google Workspace or Microsoft 365
- ServiceNow or Jira
- SIEM/SOC export path

## What is the main risk ScopeZero reduces?

ScopeZero reduces the risk that an autonomous agent with valid access performs the wrong action faster than a human can review it.
