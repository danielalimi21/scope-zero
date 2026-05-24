# ScopeZero Objection Handling

## "Isn't this just IAM?"

No. IAM decides whether an identity can access a resource. ScopeZero decides whether an autonomous action should execute right now, given the signed mission contract, data class, destination, prompt influence, tool, operation, and risk.

Short answer:

> IAM grants access. ScopeZero governs autonomous action.

## "Isn't this prompt-injection detection?"

Prompt-injection detection is one signal. ScopeZero is the runtime enforcement layer that uses prompt influence plus identity, mission action contract, data sensitivity, destination, and policy to make an allow/block/approval decision.

## "Can't existing DLP solve this?"

DLP helps classify and restrict data movement. ScopeZero adds agent context: mission contract, tool call, operation, delegated authority, prompt influence, and forensic replay.

## "Why would we need this if we trust our agent framework?"

Agent frameworks optimize building and running agents. ScopeZero is an independent control plane for security teams. Enterprises usually want enforcement outside the application logic being governed.

## "Is it production ready?"

Answer honestly:

> It is a working alpha / release-candidate foundation. The core gateway, policy engine, MCP proxy, SIEM export, auth/RBAC, tenant isolation, SDK, and evidence ledger exist. Production deployment requires connecting your real IdP, SIEM, secrets vault, cloud environment, and first agent workflow.

## "Who owns this budget?"

Likely owners:

- CISO
- AI platform
- identity security
- cloud security
- SOC / detection engineering
- data security

The pilot should identify which owner feels the pain fastest.

## "What is the first pilot?"

Best first pilot:

> One internal AI agent, 2-3 tools, a signed mission action contract, runtime allow/block/approval policy, SIEM export, and evidence replay.

## "How is this different from CrowdStrike/Pangea or Palo Alto/CyberArk?"

Position carefully:

> Those moves validate the market. ScopeZero's wedge is narrower and sharper: pre-execution authorization for agent tool calls, especially MCP/tool workflows, based on signed mission action contracts and cryptographic evidence.
