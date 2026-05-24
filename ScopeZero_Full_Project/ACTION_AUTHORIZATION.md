# ScopeZero Action Authorization

ScopeZero is not positioned as a generic AI security dashboard. The core product is a **vendor-neutral action authorization layer for AI agents**.

## Category Sentence

ScopeZero authorizes every autonomous AI-agent action before it reaches a tool, then seals the decision into cryptographic evidence.

## The Core Distinction

Traditional IAM asks:

> Can this identity access this resource?

ScopeZero asks:

> Is this exact action allowed for this agent, mission, data class, destination, delegation chain, and risk level right now?

## Mission Action Contract

A mission action contract is the signed policy object that makes the runtime decision possible. It defines:

- agent identity
- human delegator
- approved objective
- allowed tools
- allowed operations
- allowed data classes
- allowed destinations
- maximum delegation depth
- risk budget
- approval requirements
- evidence schema

## Runtime Decision

Agents call:

```text
POST /v1/action-authorizations
```

The gateway returns:

- `allow`
- `block`
- `redact`
- `quarantine_context`
- `approval`
- `pause_session`

Every response includes:

- `authorization_id`
- matched mission contract, if any
- risk score
- reasons
- required action
- hash-chained evidence record

## Why This Is Differentiated

Many AI security products scan prompts, govern model usage, or monitor AI apps. ScopeZero's sharper wedge is pre-execution authorization for agent tool calls across vendors, frameworks, MCP servers, SaaS tools, cloud APIs, and internal systems.

The wedge is:

> Mission-scoped action authorization plus cryptographic evidence for autonomous enterprise work.
