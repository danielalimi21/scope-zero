# ScopeZero Controlled Pilot Proposal

## Pilot Objective

Prove that ScopeZero can govern autonomous AI-agent tool calls before execution in a real enterprise workflow.

## Recommended Pilot Scope

- One internal agent workflow.
- Two or three enterprise tools.
- One mission action contract.
- One approval gate.
- One SOC/evidence export path.
- One measurable blocked-action scenario.

## Example Pilot Workflows

### AI Code Remediation Agent

Tools:

- GitHub
- Slack
- ticketing or CI/CD system

Controls:

- allow safe pull requests
- block credential commits
- block production policy changes
- route deployment-impacting changes to approval

### AI Security Operations Agent

Tools:

- SIEM
- Slack
- ticketing
- cloud read-only APIs

Controls:

- allow investigation summaries
- block sensitive external sharing
- route containment actions to approval
- produce incident evidence

### AI Cloud Remediation Agent

Tools:

- AWS IAM
- ticketing
- Slack

Controls:

- allow read-only posture review
- block admin privilege escalation
- route IAM policy changes to approval
- export evidence to SOC

## Success Criteria

The pilot succeeds if ScopeZero:

- receives agent tool calls before execution
- correctly allows approved in-scope actions
- blocks at least one out-of-scope high-risk action before tool execution
- routes at least one high-impact action to approval
- produces evidence hashes for decisions
- exports evidence to the customer's review workflow
- gives security teams enough clarity to trust the result

## Timeline

| Phase | Duration | Outcome |
| --- | --- | --- |
| Discovery and workflow selection | 1 week | Select agent, tools, and risk scenarios |
| Integration | 2-3 weeks | Route agent tool calls through ScopeZero |
| Policy and mission design | 1 week | Define mission contracts and approval gates |
| Pilot execution | 1-2 weeks | Run safe, blocked, and approval scenarios |
| Review | 1 week | Deliver evidence, findings, and expansion plan |

Recommended pilot length: **6-8 weeks**.

## Commercial Structure

Recommended paid pilot range:

- technical validation: $10k-$25k
- controlled enterprise pilot: $50k-$150k
- expansion contract: based on agent count, tool coverage, and deployment model

## Deliverables

- mission contract design
- tool-call enforcement path
- policy configuration
- approval workflow
- evidence export
- pilot report
- production-readiness plan
