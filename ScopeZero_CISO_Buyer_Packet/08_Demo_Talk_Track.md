# ScopeZero Demo Talk Track

## 30-Second Opening

AI agents are becoming enterprise actors. They do not just answer questions. They call tools, move data, write code, post messages, and touch cloud systems.

IAM can tell us whether the agent has access.

ScopeZero tells us whether the specific action is authorized before execution.

## 3-Minute Demo

1. Start with the problem:

   > An agent can have valid credentials and still take the wrong action.

2. Show the mission contract:

   > This agent is approved for a specific mission, specific tools, data classes, destinations, and approval rules.

3. Show an allowed action:

   > The GitHub or Slack action matches the mission contract, so ScopeZero allows it and records evidence.

4. Show a blocked action:

   > The next action uses the same kind of tool access, but attempts sensitive data movement, credential exposure, or infrastructure change. ScopeZero blocks it before tool execution.

5. Show AWS IAM:

   > Cloud privilege changes are high-impact. Admin escalation is blocked. Lower-risk policy change is routed to approval.

6. Show evidence:

   > Every decision has a hash-linked evidence record, so the SOC can prove what happened and why.

## 10-Minute CISO Flow

1. Why this matters now.
2. Where ScopeZero sits.
3. Mission Action Contract.
4. GitHub proof.
5. Slack proof.
6. AWS IAM proof.
7. Evidence report.
8. Pilot proposal.

## Closing Line

> The agent was authorized. The action was not.

## Buyer Ask

> The right next step is not a broad platform rollout. It is a controlled pilot around one real agent workflow, two or three tools, one mission contract, one approval gate, and one evidence export.
