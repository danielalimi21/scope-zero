# ScopeZero Landing Site Read-Aloud Script

Use this while screen recording the landing page. Read it naturally, and scroll to the next section when the paragraph changes.

## Opening

ScopeZero is an action authorization gateway for autonomous AI agents.

The simplest way to understand it is this: when an AI agent wants to use a real tool, ScopeZero checks the action before it happens.

So instead of only asking, "Does this agent have access?", ScopeZero asks, "Should this exact action be allowed right now?"

## Live Authorization Stream

This stream shows the product idea in a simple way.

Some actions are safe, so ScopeZero allows them.

Some actions are dangerous, so ScopeZero blocks them.

Some actions are high impact, so ScopeZero sends them to approval.

And some actions may be influenced by unsafe context, so ScopeZero can quarantine them before the agent acts.

## The Problem

AI agents are moving from chat into real operational work.

They can open pull requests, send Slack messages, export data, call internal APIs, trigger workflows, and even change cloud permissions.

That creates a new security problem, because these agents are no longer just producing text. They are becoming backend actors.

## The Gap In Existing Security

Traditional security tools were not built for this exact problem.

IAM can tell you whether the agent has access to a system.

SIEM can tell you what happened after the event.

Prompt security tools can inspect language and model behavior.

But the missing question is: should this exact autonomous action execute before it reaches the tool?

That is the gap ScopeZero is designed to solve.

## Where ScopeZero Sits

ScopeZero is not something every employee installs on a laptop.

It sits in the backend path, between the agent service and the tools the agent uses.

Before the backend runs a method, it asks ScopeZero for an authorization decision.

If the action is approved, it continues to GitHub, Slack, AWS, SaaS tools, APIs, or MCP tools.

If the action is not approved, it stops before the downstream tool receives it.

## The Integration Pattern

The integration is simple.

The backend sends ScopeZero a structured request: which agent is acting, what mission it is working on, what tool it wants to use, what method it wants to call, what data is involved, and where that data is going.

ScopeZero evaluates the request and returns a decision.

Then the backend enforces that decision before the real tool call happens.

## How The Engine Works

ScopeZero does not rely on an LLM to decide what is safe.

The decision engine is deterministic.

It checks the approved mission, the tool, the method, the resource, the data class, the destination, prompt influence, privilege impact, risk, and policy rules.

That means the same action, under the same conditions, produces the same decision.

This is important for security teams because the control must be explainable, repeatable, and auditable.

## The Decision Flow

First, ScopeZero checks whether the action fits the mission the agent was given.

Then it checks what method is being called and what resource will be touched.

Then it checks what type of data is involved and where it is going.

Then it checks whether the action was influenced by untrusted context, and whether it can affect money, permissions, or production systems.

Finally, it returns a clear result: allow, block, redact, quarantine, pause, or require human approval.

## Proof Scenario: GitHub

Here is the safe path.

A coding agent wants to open a normal pull request inside the approved repository and mission scope.

ScopeZero sees that the action matches the mission, the data is source code, and the impact is low.

So the action is allowed, and the decision is recorded as evidence.

## Proof Scenario: Slack

Now the same idea, but with a dangerous action.

An agent tries to send customer-confidential information into an external Slack destination.

The agent may technically have access to Slack, but this specific action crosses a data boundary.

ScopeZero blocks it before Slack receives the message.

## Proof Scenario: AWS IAM

Some actions are not simply safe or unsafe.

For example, an agent may try to attach administrator permissions in AWS.

That might be legitimate in rare cases, but the impact is too high for automatic execution.

So ScopeZero routes the action to human approval instead of allowing the agent to perform it by itself.

## Proof Scenario: MCP

Modern agents often use MCP tools and can be influenced by documents, webpages, tickets, or messages they read.

If an agent reads untrusted content that tries to manipulate its next action, ScopeZero can detect that prompt influence.

Instead of letting the agent continue, ScopeZero quarantines the context and prevents the unsafe tool call.

## Why ScopeZero Is Different

ScopeZero does not replace IAM, DLP, SIEM, or prompt security.

It adds the missing control layer between them.

IAM controls identity access.

DLP watches data movement.

SIEM gives visibility after events happen.

Prompt tools inspect model behavior.

ScopeZero controls the actual autonomous action before execution.

## Product Surface

ScopeZero is built as a control plane around agent action.

The runtime gateway intercepts proposed tool calls.

Mission contracts define what the agent is allowed to do.

The policy engine evaluates each action deterministically.

The approval broker routes high-impact actions to a human.

The evidence ledger records every decision.

And the connector layer makes GitHub, Slack, AWS, SaaS tools, internal APIs, and MCP tools governable.

## Closing

The big idea is simple.

Enterprises want to use AI agents, but they cannot give them unchecked production power.

ScopeZero gives them the control layer they need.

It lets agents work across real systems while every important action is checked, governed, and recorded before it happens.

ScopeZero is pre-execution action authorization for autonomous enterprise AI agents.
