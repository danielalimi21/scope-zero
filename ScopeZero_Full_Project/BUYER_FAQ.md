# ScopeZero Buyer FAQ

## Is ScopeZero an AI agent?

No. ScopeZero is not an agent. It is the gateway that authorizes or blocks what agents try to do.

## Does ScopeZero use an LLM?

The core authorization decision does not use an LLM. It is deterministic policy logic based on signed mission contracts, tool/action descriptors, data classification, destination checks, prompt-influence signals, risk scoring, and approval gates.

An LLM could later be used for explanation, policy authoring assistance, or unusual-action summarization, but not as the trusted enforcement core.

## How is this different from IAM?

IAM asks:

> Can this identity access this system?

ScopeZero asks:

> Is this exact autonomous action authorized by this mission right now?

An agent may have Gmail access but still should not send restricted revenue data to an external address. ScopeZero controls that second question.

## How is this different from Astrix or non-human identity security?

Non-human identity products discover and govern API keys, OAuth apps, service accounts, tokens, and agent identities.

ScopeZero governs the actions those identities attempt to take.

Short version:

> Astrix-style NHI security governs non-human identities. ScopeZero governs non-human actions.

## How is this different from DLP?

DLP focuses on detecting or preventing sensitive data movement. ScopeZero includes data sensitivity as one signal, but also checks mission, tool, operation, destination, prompt influence, approval policy, and risk budget.

## How is this different from SIEM?

SIEM receives evidence after events. ScopeZero makes a decision before the tool call executes and then exports evidence to SIEM.

## How does ScopeZero stop prompt injection?

ScopeZero does not claim to eliminate prompt injection. It detects prompt-influence signals and treats them as authorization context.

If hostile instructions push an agent outside the mission, ScopeZero can block, quarantine, or require approval before execution.

## What is the first real use case?

The strongest first use case is one internal agent touching sensitive tools:

- documents
- spreadsheets
- Slack/email
- GitHub
- cloud IAM
- ServiceNow/Jira

The goal is not to govern every agent on day one. The goal is to prove runtime action control on one risky workflow.

## What does a buyer get in a pilot?

- gateway deployment
- mission action contract
- SDK or MCP integration
- policy package
- blocked-action test
- approval test
- evidence export
- readiness report

## What is production-ready today?

The product core is pilot-ready:

- API gateway
- SDK
- MCP proxy
- deterministic policy engine
- signed mission contracts
- evidence ledger
- SIEM export
- OpenAPI
- tests
- Docker/Kubernetes scaffolding

Production customer data still needs real IdP, managed Postgres, vault/KMS, SIEM, connector workers, distributed rate limiting, SBOM/image signing, and external security testing.

## What should I say if a buyer asks "is this finished?"

Say:

> ScopeZero is a pilot-ready product core. It is ready for a controlled design pilot around one agent workflow. It is not yet a fully managed enterprise SaaS.

That is credible and better than overclaiming.
