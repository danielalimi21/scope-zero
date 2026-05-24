# ScopeZero Mini Deck

## Slide 1 - Title

**ScopeZero**

Vendor-neutral action authorization for autonomous AI-agent tool calls.

Tagline:

> The agent was authorized. The action was not.

## Slide 2 - The New Actor

AI agents are becoming enterprise actors.

They read documents, call APIs, update systems, write code, trigger workflows, and move data.

They are not just users, endpoints, scripts, or SaaS apps.

## Slide 3 - The Security Gap

Classic IAM asks:

> Can this identity access this resource?

Agent security also needs to ask:

> Should this autonomous action be allowed right now, given the signed mission contract, data class, prompt influence, tool, destination, delegation chain, and risk?

## Slide 4 - The Product

ScopeZero sits between agents and tools.

Every tool call is checked against a mission action contract and receives a runtime decision:

- allow
- block
- redact
- quarantine
- approval
- pause

Every decision becomes evidence.

## Slide 5 - Demo

Scenario:

- M&A diligence agent
- valid access to documents
- malicious PDF injects hidden instructions
- agent attempts confidential data export
- ScopeZero rejects actions outside the mission contract and blocks external email
- cryptographic evidence generated

## Slide 6 - First Wedge

MCP and agent action authorization.

2-4 week pilot:

- one internal agent
- 2-3 tools
- mission-scoped action contract
- runtime policy
- SIEM export
- evidence replay

## Slide 7 - Why This Can Be Big

Every major enterprise AI deployment will need:

- agent identity
- mission action contracts
- pre-execution tool-call control
- data egress protection
- approval gates
- forensic replay
- SIEM/GRC evidence

ScopeZero aims to become the control layer for autonomous work.
