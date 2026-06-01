# ScopeZero Landing Site Short Read-Aloud Script

Use this while screen recording the landing page. It is written to be read naturally while scrolling through the site in order.

## Opening

ScopeZero is an action authorization gateway for autonomous AI agents.

When an agent wants to use a real tool, ScopeZero checks the action before it happens. It does not only ask whether the agent has access. It asks whether this exact action should be allowed right now.

## The Core Idea

This is the basic product idea.

Safe actions are allowed. Dangerous actions are blocked. High-impact actions go to approval. And if an action is influenced by unsafe context, ScopeZero can quarantine it before the agent acts.

## The Problem

AI agents are moving from chat into real operational work.

They can open pull requests, send messages, export data, call APIs, trigger workflows, and change cloud permissions. That means they are becoming backend actors, not just assistants.

## The Security Gap

Existing security tools do not fully answer this new question.

IAM controls access. SIEM shows what happened afterward. Prompt tools inspect language and model behavior. But ScopeZero answers the runtime question: should this exact autonomous action execute before it reaches the tool?

## Where ScopeZero Sits

ScopeZero sits in the backend path between the agent service and the tools the agent uses.

Before the backend runs a method, it asks ScopeZero for a decision. If the action is approved, it continues to GitHub, Slack, AWS, SaaS tools, APIs, or MCP tools. If not, it stops before execution.

## How It Works

The backend sends ScopeZero a structured request: the agent, mission, tool, method, data class, destination, and risk context.

ScopeZero uses a deterministic policy engine. It checks mission scope, method, resource, data sensitivity, destination, prompt influence, privilege impact, and approval rules.

Then it returns a clear decision: allow, block, redact, quarantine, pause, or require human approval.

## Proof: GitHub

Here is the safe path.

A coding agent opens a normal pull request inside the approved repository and mission scope. ScopeZero allows the action and records the decision as evidence.

## Proof: Slack

Now the risky path.

The same agent tries to send customer-confidential information to an external Slack destination. The agent may have Slack access, but this action crosses a data boundary, so ScopeZero blocks it before Slack receives the message.

## Proof: AWS

For cloud permissions, ScopeZero can require approval.

If an agent tries to attach administrator permissions in AWS, ScopeZero recognizes the high privilege impact and routes the action to a human instead of letting it execute automatically.

## Proof: MCP

For MCP tools, ScopeZero can also handle prompt influence.

If an agent reads untrusted content that tries to manipulate its next tool call, ScopeZero can quarantine that context before the unsafe action happens.

## Why It Is Different

ScopeZero does not replace IAM, DLP, SIEM, or prompt security.

It adds the missing layer: control over the autonomous action itself, before execution.

## Product Surface

ScopeZero is built as a control plane for agent action.

It includes the runtime gateway, mission contracts, deterministic policy engine, approval broker, evidence ledger, and connector layer for tools like GitHub, Slack, AWS, SaaS APIs, internal services, and MCP.

## Closing

The big idea is simple.

Enterprises want AI agents to work across real systems, but they cannot give them unchecked production power.

ScopeZero gives them the control layer they need: every important agent action is checked, governed, and recorded before it happens.
