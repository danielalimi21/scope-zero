# ScopeZero Customer Pilot Proposal

## Proposal

ScopeZero will run a controlled pilot to govern one autonomous AI-agent workflow before it executes high-risk tool calls.

## Pilot Goal

Prove that ScopeZero can:

- intercept agent tool calls before execution
- evaluate each action against a signed mission contract
- block out-of-scope actions
- require approval for high-impact actions
- export evidence to security teams

## Ideal Pilot Workflow

Choose one workflow where an agent touches sensitive systems:

- M&A diligence agent over documents and spreadsheets
- AI coding agent with repository access
- cloud operations agent with IAM or infrastructure access
- finance/HR workflow agent
- customer-support agent with CRM and email access
- security automation agent with ticketing and response tools

## Pilot Scope

Included:

- one tenant
- one agent workflow
- two or three tools
- one mission contract
- one policy package
- one approval gate
- SIEM export path
- readiness and findings report

Excluded from first pilot:

- broad enterprise rollout
- all production connectors
- long-term managed service
- formal compliance audit

## Technical Work Plan

### Week 1: Discovery

- identify agent workflow
- identify tools and data classes
- define allowed actions
- define blocked actions
- define approval triggers
- agree success criteria

### Week 2: Mission Contract Design

- create mission action contract
- map tools and operations
- define data classes and destinations
- define risk budget
- prepare test cases

### Week 3-4: Integration

- deploy ScopeZero gateway
- connect SDK or MCP proxy
- configure auth path
- configure evidence export
- run synthetic test actions

### Week 5: Adversarial Testing

- test prompt-injection style context
- test sensitive egress
- test tool-outside-scope
- test approval action
- verify evidence ledger

### Week 6: Review

- deliver readiness report
- review SOC evidence
- review false positives and false negatives
- propose expansion plan

## Success Criteria

The pilot succeeds if:

- agent actions are evaluated before execution
- allowed actions continue
- out-of-scope action is blocked
- approval action is routed
- evidence is exportable
- security team can explain what happened after the fact

## Buyer Commitment Needed

Customer provides:

- agent owner
- security owner
- one technical integration contact
- test workflow
- sample tool-call payloads
- non-production credentials or synthetic environment
- SIEM/logging contact if available

## Deliverables

- deployed pilot gateway
- mission contract and policy file
- test results
- SIEM/evidence export
- risk findings
- go/no-go expansion recommendation

## Commercial Terms

Recommended pilot price:

**$50k-$150k**, depending on integration depth.

Recommended duration:

**6-10 weeks**.

## Expansion Path

After pilot:

- add more agents
- add more connectors
- deploy managed Postgres
- connect vault/KMS
- connect enterprise IdP
- connect production SIEM
- add admin policy UI
- define annual platform agreement
