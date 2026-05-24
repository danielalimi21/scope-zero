# ScopeZero Company Brief

## Company

**ScopeZero** builds vendor-neutral action authorization for autonomous AI agents.

The company exists to make autonomous enterprise work safe enough for regulated, high-stakes organizations.

## Category

**Agent Action Authorization**

Traditional cybersecurity protects users, devices, workloads, networks, applications, and data. AI agents are a new class of enterprise actor: they are delegated, autonomous, prompt-influenced, tool-using, and capable of chaining actions across systems.

ScopeZero secures that actor's actions at runtime.

## Core Insight

The breach of the AI-agent era will often look like legitimate access used for the wrong purpose.

An agent may have permission to read files, query CRM, draft email, inspect code, or modify cloud settings. But if a malicious PDF, webpage, Slack message, ticket, or tool result manipulates the agent, the action can still become dangerous.

The key distinction:

> The agent was authorized. The action was not.

ScopeZero enforces that distinction.

## Product

ScopeZero sits between AI agents and enterprise tools.

Before an agent can execute a tool call, ScopeZero evaluates:

- agent identity
- human delegator
- approved mission
- requested tool
- requested operation
- data sensitivity
- destination
- prompt influence
- delegation chain
- behavioral risk
- approval requirements

ScopeZero then returns one of six runtime decisions:

- allow
- block
- redact
- quarantine context
- require human approval
- pause session

The current product core already includes a live gateway API, signed mission action contracts, runtime policy evaluation, sensitive data classification, approval objects, an SDK, an example agent, and a hash-chained evidence ledger.

## Breakthrough Primitive

**Mission Action Contract**

Classic IAM says:

> This identity can access this resource.

ScopeZero says:

> This autonomous identity can perform this action only if the requested tool, operation, data class, destination, delegation chain, and impact level match a human-approved mission contract.

This turns static permission into pre-execution runtime authority.

## First Product Wedge

**Agent Action Authorization Gateway**

Developers and AI platform teams route agent tool calls through ScopeZero. Security teams get policy control, visibility, forensic replay, and approval gates without blocking AI adoption.

Initial use cases:

- MCP/tool-call action authorization
- prompt-injection-driven egress prevention
- sensitive data redaction
- high-impact approval gates
- agent identity registry
- mission-scoped action contracts
- forensic evidence capsules

## Why Now

Enterprises are moving from AI assistants to AI actors. Those actors will touch email, documents, code, CRM, finance, cloud infrastructure, and customer data.

Security teams cannot manually review every autonomous action. Blocking agents will create shadow AI. The market needs a runtime control layer that lets companies adopt agents without surrendering control.

## Buyers

Primary:

- CISO
- CIO
- VP Security Engineering
- Head of AI Platform
- Head of Identity
- Head of Cloud Security

Secondary:

- GRC and compliance leaders
- SOC leaders
- data security leaders
- legal and risk teams

## Strategic Acquirers

ScopeZero is strategically relevant to:

- identity security platforms
- XDR and endpoint platforms
- cloud security platforms
- SASE vendors
- SIEM vendors
- GRC platforms
- AI platform companies
- hyperscalers

## Positioning

Short:

> ScopeZero is the action authorization layer for autonomous AI agents.

Sharper:

> ScopeZero stops AI agents from taking actions outside their approved mission contract.

Boardroom:

> ScopeZero gives enterprises mission-scoped action control, approval, and forensic evidence over autonomous AI work.

Category:

> Agent action authorization starts where traditional IAM stops: at the moment an autonomous agent decides to act.

## Demo Story

The demo shows an M&A diligence agent with legitimate access to enterprise documents.

The agent reads a malicious PDF containing hidden instructions. It then attempts to export confidential customer revenue data to an external destination.

ScopeZero:

1. Allows normal mission-aligned reads.
2. Detects untrusted prompt influence.
3. Blocks the raw export.
4. Blocks external confidential data egress.
5. Allows a sanitized summary.
6. Seals a forensic evidence capsule.

## Moat

ScopeZero's defensible asset is action authorization telemetry:

- which agents act
- which tools they use
- which missions they operate under
- which mission action contracts allowed or denied them
- which prompts influence them
- which data they touch
- which actions are blocked, redacted, approved, or allowed
- which decisions were later confirmed as correct

That dataset becomes the map of autonomous enterprise behavior.

## Long-Term Vision

ScopeZero becomes the trusted runtime layer for autonomous work.

If every enterprise eventually has thousands or millions of AI agents, every serious enterprise will need:

- agent identity
- mission authorization
- mission action contracts
- tool-call control
- data-boundary enforcement
- agent-to-agent delegation policy
- runtime risk scoring
- incident replay
- compliance evidence

ScopeZero aims to define that layer.
