# ScopeZero

## Agent Action Authorization For AI Agents

AI agents are becoming a new enterprise actor. They can read documents, call APIs, write code, update SaaS records, trigger workflows, modify cloud settings, and move data. Existing security tools can tell whether an identity has access. They usually cannot tell whether a specific autonomous action matches the approved mission contract.

**ScopeZero stops AI agents from taking actions outside their approved mission contract.**

The core distinction:

> The agent was authorized. The action was not.

## Problem

Enterprises are moving from AI assistants to autonomous AI agents. Those agents will operate across Microsoft 365, Google Drive, Slack, GitHub, Salesforce, ServiceNow, AWS, databases, and internal tools.

This creates a new breach path:

1. A human authorizes an agent for a legitimate task.
2. The agent reads an untrusted document, ticket, page, chat, or tool output.
3. Hidden or malicious instructions influence the agent.
4. The agent uses valid credentials to perform a harmful action.
5. Classic IAM sees an authorized identity. The business sees a breach.

## Product

ScopeZero is a vendor-neutral runtime gateway between agents and tools.

Before an agent tool call executes, ScopeZero evaluates:

- agent identity
- human delegator
- signed mission action contract
- requested tool
- requested operation
- data sensitivity
- destination
- prompt influence
- delegation chain
- behavioral risk
- approval requirements

The gateway returns:

- allow
- block
- redact
- quarantine context
- require human approval
- pause session

Every decision is sealed into a hash-chained evidence ledger and can be exported to SIEM.

## Working Alpha

ScopeZero already includes:

- live backend gateway
- browser demo
- SDK
- signed mission action contracts
- action authorization endpoint
- runtime policy engine
- MCP JSON-RPC proxy
- connector registry
- SIEM exports: JSON, CEF, LEEF, OTLP-style logs
- auth/RBAC and tenant isolation
- SQLite persistence
- Docker and Kubernetes manifests
- security review, runbook, pilot plan, and compliance matrix

## First Wedge

**MCP and agent action authorization for enterprise AI teams.**

Pilot offer:

> A 2-4 week pilot that routes one internal AI-agent workflow through ScopeZero, enforces mission-scoped action contracts, and exports evidence to the security team.

## Why Now

The market is forming now. CrowdStrike acquired Pangea to secure enterprise AI and launch AI Detection and Response. Palo Alto Networks completed its CyberArk acquisition and explicitly framed the need to secure human, machine, and agentic identities. Gartner has predicted guardian agents as a coming agentic AI category.

Sources:

- CrowdStrike / Pangea: https://ir.crowdstrike.com/news-releases/news-release-details/crowdstrike-acquire-pangea-secure-every-layer-enterprise-ai
- Palo Alto / CyberArk: https://www.paloaltonetworks.com/company/press/2026/palo-alto-networks-completes-acquisition-of-cyberark-to-secure-the-ai-era
- Gartner Guardian Agents: https://www.gartner.com/en/newsroom/press-releases/2025-06-11-gartner-predicts-that-guardian-agents-will-capture-10-15-percent-of-the-agentic-ai-market-by-2030

## Buyer

Primary buyers:

- CISO
- Head of AI Platform
- VP Security Engineering
- Head of Identity Security
- Head of Cloud Security
- SOC / Detection Engineering leader

## Ask

> Would you be open to 20 minutes of blunt feedback on whether mission-scoped action authorization maps to a real security problem in your environment?
