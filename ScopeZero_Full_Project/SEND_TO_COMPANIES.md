# ScopeZero Company Pitch

## One-Line Pitch

ScopeZero is a vendor-neutral action authorization gateway that stops autonomous AI agents from taking tool actions outside their approved mission contract.

## Category

**Agent Action Authorization**

This is the runtime layer between AI agents and enterprise tools. IAM proves that an identity has access. ScopeZero proves that a specific autonomous action is allowed before it executes.

## Core Wedge

Enterprises are starting to deploy agents that can call SaaS tools, MCP servers, cloud APIs, code repositories, documents, spreadsheets, ticketing systems, and internal workflows.

That creates a new security problem:

> An agent can have valid credentials and still take the wrong action.

ScopeZero solves the wedge with:

- signed mission action contracts
- pre-execution tool-call authorization
- sensitive data and destination checks
- prompt-influence detection
- human approval gates
- hash-chained evidence
- SIEM and SOC export
- MCP proxy enforcement

## Best Buyers

Start with teams that already feel the pressure of agent adoption:

- CISO
- Head of AI Platform
- VP Security Engineering
- Identity security leader
- Cloud security leader
- Data security leader
- SOC platform leader
- Product leader at a cybersecurity company
- Corporate development at a cybersecurity, identity, cloud, or AI platform company
- Partner at a cyber-focused or AI-infrastructure VC

## Best Company Categories

- Identity security and IAM platforms
- XDR, SIEM, and SOC platforms
- Cloud security and CNAPP platforms
- SASE/SSE and secure access platforms
- DLP and data security platforms
- AI security and AI governance companies
- Agent platforms and MCP infrastructure companies
- Cloud providers and productivity suites
- Enterprise workflow platforms
- Regulated enterprises building internal agents

## Why They Should Care

Every serious enterprise agent deployment needs a control point that can answer:

- Which human delegated authority to this agent?
- What mission was the agent approved to perform?
- Is this tool in scope?
- Is this operation in scope?
- Is the data class approved?
- Is the destination approved?
- Is the action influenced by hostile context?
- Does this require human approval?
- Can the company prove the answer later?

ScopeZero makes those answers runtime-enforceable instead of after-the-fact forensic guesses.

## What You Can Show

You can show a working gateway, not only slides:

- Product UI at `http://localhost:8788`.
- Full CISO proof run with GitHub, Slack, and AWS IAM.
- `CISO_PROOF_REPORT.md` with artifacts, decisions, evidence hashes, and ledger verification.
- Live attack simulation.
- SDK-driven malicious diligence agent.
- MCP proxy path.
- Runtime action authorization API.
- Policy proposal and approval APIs.
- Hash-chained ledger verification.
- SIEM exports.
- OpenTelemetry traces.
- Kubernetes and Postgres deployment path.
- Security review and threat model.

## Strongest Current Proof

Run:

```bash
npm run proof:ciso
```

The proof shows:

- GitHub safe pull request allowed.
- GitHub dangerous pull request blocked before execution.
- Slack safe message allowed.
- Slack sensitive/prompt-influenced message blocked before execution.
- AWS IAM admin escalation blocked before execution.
- AWS IAM policy change routed to human approval.

Buyer line:

> "IAM says whether the agent has access. ScopeZero says whether this exact autonomous action is authorized right now."

## 90-Second Demo Script

> "AI agents are becoming delegated enterprise actors. They read files, call APIs, use SaaS tools, write code, and move data.
>
> Existing IAM tells us whether the agent has access. It does not tell us whether this specific action matches what a human approved the agent to do.
>
> ScopeZero sits between agents and tools. Before execution, it checks identity, delegation, mission contract, tool, operation, data class, destination, prompt influence, risk budget, and approval policy.
>
> In this demo, ScopeZero governs GitHub, Slack, and AWS IAM actions. It allows safe in-contract actions, blocks dangerous code and communication actions before execution, blocks an AWS admin privilege escalation, and routes a policy change to human approval.
>
> ScopeZero writes cryptographic evidence for every decision, so the SOC can prove what happened and why.
>
> Our thesis is simple: the agent was authorized, the action was not."

## Email Template

Subject options:

- Action authorization for AI-agent tool calls
- Runtime control for autonomous enterprise agents
- MCP and agent action authorization demo
- The agent was authorized. The action was not.

Email:

> Hi [Name],
>
> I am building ScopeZero, a vendor-neutral action authorization gateway for autonomous AI-agent tool calls.
>
> The thesis is simple: enterprises are giving agents real tool access, but IAM only answers whether an agent can access a system. It does not answer whether a specific autonomous action matches the mission a human approved.
>
> ScopeZero sits between agents and tools. Before execution, it evaluates identity, human delegation, signed mission contract, tool, operation, data class, destination, prompt influence, risk budget, and approval rules. It then returns allow, block, redact, quarantine, or approval, and writes hash-chained evidence for the SOC.
>
> I have a working local gateway, SDK, MCP proxy, SIEM export, policy approval flow, and a CISO proof run across GitHub, Slack, and AWS IAM showing allowed actions, blocked actions, approval routing, and cryptographic evidence before execution.
>
> If your team is thinking about enterprise agents, MCP, AI security, identity, SOC evidence, or agent governance, I would value 20 minutes of blunt feedback.
>
> [Link or attached zip]
>
> Best,
> [Your Name]

## 20-Minute Meeting Plan

1. State the category: agent action authorization.
2. Explain the gap: identity is not enough for autonomous actors.
3. Run the browser attack simulation.
4. Show the SDK example output.
5. Show the evidence ledger and SIEM export.
6. Show the architecture checklist: OIDC/JWKS, Postgres, OTLP, MCP, policy approvals, Kubernetes.
7. Ask where this would need to integrate first to be valuable.
8. Ask what would make the buyer trust or reject it.

## Buyer Questions

Ask pain-discovery questions, not compliment-seeking questions:

- Are teams already using agents that call tools or APIs?
- Are MCP servers entering your environment?
- Who owns agent identity today?
- Can security see and block agent tool calls before execution?
- What happens if an agent with valid access takes the wrong action?
- Can you reconstruct why an agent acted after an incident?
- Which tools create the most risk: email, files, code, cloud, tickets, finance, customer data?
- Would this sit closer to IAM, SOC, DLP, AI platform, or cloud security in your organization?
- What proof would you need for a pilot?

## Pilot Ask

Ask for a narrow pilot, not a broad platform decision:

- One internal agent.
- Two or three tools.
- One sensitive workflow.
- One mission contract.
- One SIEM export.
- One approval gate.
- One success metric: blocked out-of-scope action with usable evidence.

## Paid Pilot Offer

Use this when someone shows real interest:

> "The best first step is a controlled six-week pilot. We pick one internal agent workflow, two or three tools, one mission contract, one approval gate, and one SIEM export. The success criterion is simple: ScopeZero blocks an out-of-scope agent action before execution and produces evidence your security team can use."

Suggested price range:

- technical validation: $10k-$25k
- controlled pilot: $50k-$150k
- enterprise expansion: $150k-$500k+ annual

See `PRICING_AND_PACKAGING.md` and `CUSTOMER_PILOT_PROPOSAL.md`.

## Strategic Buyer Logic

ScopeZero could be valuable to:

- Identity companies that need action-level authorization for non-human actors.
- SOC/SIEM platforms that need high-signal agent telemetry.
- Cloud security companies that need control over agent-initiated infrastructure changes.
- DLP/data security companies that need agent-aware egress context.
- AI platforms that need enterprise trust for tool-using agents.
- MCP infrastructure companies that need policy enforcement and auditability.

## What Not To Overclaim

Do not say:

- "Nobody else is doing this."
- "This is already a finished enterprise SaaS."
- "It replaces IAM, DLP, SIEM, or AI governance."
- "It eliminates prompt injection."

Say:

> "This is a focused runtime authorization layer. It complements IAM, DLP, SIEM, and AI security by enforcing whether each agent action is authorized before execution."

## Strongest Lines

- "The agent was authorized. The action was not."
- "IAM answers access. ScopeZero answers action authority."
- "Mission action contracts turn delegated intent into runtime enforcement."
- "Every enterprise agent needs a control point between reasoning and execution."
- "Astrix-style NHI security governs non-human identities. ScopeZero governs non-human actions."
