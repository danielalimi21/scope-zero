# ScopeZero Full Overview

## Executive Summary

ScopeZero is a vendor-neutral action authorization gateway for autonomous AI-agent tool calls.

The product exists because enterprises are moving from chatbots to agents that can use tools, access data, call APIs, open tickets, send messages, write code, and modify cloud systems. IAM can tell whether an agent has access. ScopeZero decides whether a specific action is authorized before execution.

The core line:

> The agent was authorized. The action was not.

## What ScopeZero Sells

ScopeZero sells a runtime control point for enterprise AI agents.

It gives security, identity, SOC, and AI platform teams:

- pre-execution allow/block/approval decisions for agent tool calls
- signed mission action contracts
- sensitive data and destination enforcement
- prompt-influence detection
- MCP tool-call governance
- human approval gates
- hash-chained evidence
- SIEM and OTEL outputs
- policy versioning and auditability

## Why This Matters Now

The market is moving from human users to non-human actors:

- API keys
- service accounts
- OAuth apps
- CI/CD jobs
- AI agents
- MCP servers
- autonomous workflows

Recent acquisitions and market movement around non-human identity security validate that companies care about this problem. But identity is only the first layer.

ScopeZero's wedge is the next layer:

> Non-human identity tells you who the actor is. ScopeZero tells you whether the actor's action is allowed.

## The Product Primitive

The central primitive is the **Mission Action Contract**.

A mission action contract defines:

- agent identity
- human delegator
- objective
- allowed tools
- allowed operations
- allowed data classes
- allowed destinations
- expiry
- approval profile
- risk budget
- delegation depth

The contract is signed. If it is missing, expired, or tampered with, the action is blocked.

## Current Product Surface

The project includes:

- live gateway
- browser command center
- SDK
- OpenAPI contract
- automated tests
- CI workflow
- mission contract signing
- policy engine
- action descriptor normalization
- prompt-influence detector
- sensitive data classifier
- human approval workflow
- MCP proxy
- connector registry
- SIEM export
- OpenTelemetry-compatible traces
- encrypted secret references
- optional Postgres store
- Kubernetes and Docker deployment scaffolding
- security review and threat model
- enterprise readiness report
- pricing and pilot package

## Buyer Personas

Primary:

- CISO
- VP Security Engineering
- Head of AI Platform
- Identity security leader
- SOC leader
- Data security leader
- Cloud security leader

Strategic:

- AI platform company
- identity security company
- SIEM/SOC platform
- MCP infrastructure company
- cloud security platform
- enterprise workflow platform

## Use Cases

1. **MCP gateway enforcement**
   Approve or block MCP `tools/call` before execution.

2. **Sensitive data egress**
   Stop agents from sending confidential/restricted data to external destinations.

3. **AI coding agent governance**
   Require approval for deploys, repository writes, secrets access, or privileged changes.

4. **Cloud automation control**
   Gate IAM, infrastructure, and production-impacting actions.

5. **SOC evidence for agents**
   Export every agent decision to SIEM with hash-linked evidence.

6. **Regulated workflow pilots**
   Govern finance, healthcare, insurance, legal, HR, and M&A agents.

## Commercial Wedge

The first commercial wedge should not be "secure every agent everywhere."

The first wedge should be:

> Govern one high-risk internal agent workflow before it touches sensitive tools.

Example pilot:

- one internal agent
- two or three tools
- one sensitive workflow
- one IdP
- one SIEM
- one approval gate
- one blocked out-of-scope action with evidence

## Competitive Positioning

ScopeZero is not trying to replace:

- IAM
- DLP
- SIEM
- EDR
- AI model safety
- agent frameworks

It complements them.

Positioning:

- IAM answers access.
- DLP answers data sensitivity.
- SIEM answers what happened.
- Agent frameworks execute workflows.
- ScopeZero answers whether the next agent action should execute.

## Maturity

ScopeZero is a commercial pilot package, not yet a fully hosted enterprise SaaS.

It is ready to pitch and run controlled pilots because it has:

- real gateway APIs
- deterministic decision engine
- SDK and MCP path
- evidence ledger
- tests
- OpenAPI
- deployment scaffolding
- security docs
- buyer docs

Before production customer data, it needs:

- real IdP connection
- managed Postgres deployment
- real SIEM integration
- vault/KMS integration
- one production connector worker
- distributed rate limiting
- SBOM/image signing
- external security review

## Final Narrative

ScopeZero is a serious product direction because agent adoption creates a new security question:

> Not "can this identity access the system?" but "is this autonomous action authorized by the mission?"

That is the question ScopeZero is built to answer.
