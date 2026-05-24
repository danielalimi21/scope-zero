# ScopeZero Founder Sales Playbook

## What You Have

ScopeZero is no longer just a demo screen. It is a strong commercial pilot package around a clear security category:

> ScopeZero is a vendor-neutral action authorization gateway for autonomous AI-agent tool calls.

The product shows a real buyer problem:

- companies are starting to give AI agents access to tools
- those agents can read data, write code, send messages, open tickets, call APIs, and change cloud permissions
- IAM can say whether the agent has access
- ScopeZero says whether this exact action is authorized before execution

The strongest proof you have:

- GitHub connector: safe PR allowed, dangerous PR blocked
- Slack connector: safe message allowed, sensitive prompt-influenced message blocked
- AWS IAM simulation: admin escalation blocked, high-impact policy change routed to approval
- tamper-evident ledger: every decision has evidence
- deterministic engine: no LLM required for authorization
- buyer packet: clean executive, architecture, security, proof, and pilot materials

## The Simple Pitch

"AI agents are becoming non-human employees with tool access. They can open pull requests, send Slack messages, read data, call APIs, and change cloud permissions. Existing IAM tells you whether the agent has access. ScopeZero decides whether the specific action is allowed before it happens, and leaves evidence for the security team."

## The CISO Pitch

"ScopeZero is a pre-execution authorization gateway for autonomous agent tool calls. It normalizes each tool call into a vendor-neutral action descriptor, checks it against a signed mission contract and enterprise policy, evaluates data class, destination, prompt influence, privilege impact, and session risk, then returns allow, block, redact, quarantine, approval, or pause. Every decision is written to a tamper-evident evidence chain. The goal is to let enterprises adopt agents without giving them unchecked execution authority."

## The One Sentence That Matters

IAM governs access. ScopeZero governs autonomous action.

## Why The Timing Is Good

The market is moving toward agentic AI, MCP servers, non-human identities, and autonomous tool execution. Cisco's planned acquisition of Astrix for roughly $400 million validates that non-human identity and AI-agent access are becoming board-level security issues. Okta, Cisco, Salt Security, Entro, WitnessAI, and other vendors are also moving into adjacent parts of the agent security market.

That is good news. It means the problem is real. Your job is not to claim nobody else sees it. Your job is to explain the precise wedge:

> ScopeZero is focused on pre-execution authorization for the action itself.

## What Not To Pitch

Do not pitch it as:

- "an AI agent"
- "an LLM product"
- "a chatbot security wrapper"
- "a full IAM replacement"
- "a full DLP replacement"
- "a SIEM replacement"
- "a finished enterprise platform with every connector already production-hardened"

Pitch it as:

- a focused action authorization layer
- a security control for agent tool use
- a pilot-ready gateway
- a way to turn agent autonomy into governed autonomy

## Best First Buyers

Start with organizations that already have internal AI-agent work or strong pressure to adopt it safely.

Best target categories:

- financial services
- insurance
- healthcare technology
- cybersecurity companies
- large SaaS companies
- cloud-native software companies
- defense-adjacent technology companies
- AI platform teams inside enterprises
- companies building internal developer agents
- companies experimenting with MCP servers

Best buyer roles:

- CISO
- Deputy CISO
- VP Security Engineering
- Head of AI Security
- Head of AI Platform
- Head of Identity Security
- Head of Cloud Security
- Head of Detection Engineering
- Head of AppSec
- Security Architect

## Named Account Ideas

Use these as research targets, not as guaranteed buyers.

Security and identity companies:

- Okta
- CrowdStrike
- Palo Alto Networks
- Zscaler
- Wiz
- SentinelOne
- CyberArk
- Rubrik
- Tenable
- Snyk

AI-heavy software and infrastructure companies:

- Datadog
- Atlassian
- GitLab
- ServiceNow
- Snowflake
- Databricks
- MongoDB
- Cloudflare
- Stripe
- HashiCorp / IBM

Regulated enterprise targets:

- banks with AI platform teams
- insurance carriers with automation programs
- healthcare platforms using internal AI workflows
- large fintech companies
- public companies with mature security engineering teams

The best first outreach is not to ask them to buy. Ask them to tell you whether the problem is real.

## First Outreach Message

Subject: quick security feedback on AI-agent tool control

Hi [Name],

I am building ScopeZero, a pre-execution authorization gateway for autonomous AI-agent tool calls.

The idea is simple: IAM tells you whether an agent has access. ScopeZero decides whether the exact action is authorized before the agent opens a PR, sends a Slack message, exports data, calls an API, or changes cloud permissions.

I have a working pilot showing GitHub, Slack, and AWS IAM-style controls with allow/block/approval decisions and tamper-evident evidence.

Would you be open to 20 minutes of blunt feedback on whether this is a real security problem inside teams adopting agents?

Best,
[Your Name]

## Discovery Call Questions

Ask questions before pitching hard:

- Are teams inside your company already using AI agents or coding agents?
- Do any of those agents have tool, SaaS, code, or cloud access?
- Who approves what those agents are allowed to do?
- Do you have visibility into the exact actions agents attempt?
- Could you prove after an incident why an agent action was allowed?
- Are you worried more about data egress, privilege changes, code changes, or SaaS actions?
- Would a pre-execution control point be useful if it integrated with your current tools?
- Which connector would make this real for you first?

## Demo Flow

Use a 10-minute demo:

1. Explain the problem in one sentence.
2. Show the mission contract.
3. Show a safe GitHub action being allowed.
4. Show a dangerous GitHub action being blocked.
5. Show a safe Slack message being allowed.
6. Show a sensitive/prompt-influenced Slack message being blocked.
7. Show an AWS admin escalation being denied.
8. Show a high-impact cloud action going to approval.
9. Show the evidence ledger.
10. Ask: "Which action would your team most need to govern first?"

## What To Sell First

Do not sell a giant platform first.

Sell a focused pilot:

- 2 to 4 weeks
- one agent workflow
- one or two connectors
- pre-execution decisions
- evidence report
- success criteria agreed in advance

Best pilot wedges:

- GitHub coding-agent governance
- Slack/data egress governance
- MCP tool-call gateway
- cloud privilege change approval
- agent action evidence for SOC/GRC

## Pilot Success Criteria

A serious pilot should prove:

- ScopeZero can sit in front of a real agent workflow
- safe actions are allowed without blocking productivity
- dangerous actions are stopped before execution
- high-impact actions can be routed to approval
- evidence is clear enough for a security team
- the buyer can name the next connector they want

## Pricing Direction

Early pricing should be simple:

- paid pilot: fixed fee
- production: annual platform subscription
- pricing drivers: number of agents, connectors, decision volume, environments, support level

Avoid over-optimizing price before you have buyer calls. The first goal is evidence that a company will pay to solve the problem.

## Objections And Answers

Objection: "Our IAM already handles this."

Answer: "IAM decides whether an identity can access a system. ScopeZero decides whether this specific autonomous action is authorized under the current mission, data boundary, destination, and risk state."

Objection: "We do not use agents yet."

Answer: "That is common. The question is whether your AI roadmap includes agents with tool access. ScopeZero is most useful before those agents become unmanaged production identities."

Objection: "Is this just DLP?"

Answer: "No. DLP focuses on data movement. ScopeZero evaluates the whole action: identity, mission, tool, operation, data, destination, prompt influence, privilege impact, approvals, and evidence."

Objection: "Does this use an LLM?"

Answer: "The authorization engine is deterministic. It can govern LLM-powered agents, but it does not require an LLM to decide whether an action is allowed."

Objection: "How is this different from Astrix or non-human identity security?"

Answer: "Astrix-style NHI security focuses on discovering and securing non-human identities, credentials, OAuth apps, and excessive permissions. ScopeZero focuses on the runtime action boundary: should this specific agent action execute right now?"

## What To Do Next

1. Make a list of 30 target people.
2. Send 10 personalized messages per week.
3. Ask for feedback, not a purchase.
4. Track which pain point gets the strongest reaction.
5. Offer a 2 to 4 week pilot only when the problem is confirmed.
6. Let the first serious buyer help choose the next connector.

## The Most Important Mindset

You are not trying to convince every company.

You are looking for the first security leader who says:

"Yes, we are about to give agents tool access, and we do not have a good control point for actions."

That is the buyer.

