# ScopeZero Security Review And Threat Model

## Security Objective

ScopeZero is designed to stop autonomous agents from executing actions outside an approved mission, leaking sensitive data, escalating privilege, or acting on hostile prompt influence, while producing evidence security teams can verify.

## Trust Boundaries

| Boundary | Security Question |
| --- | --- |
| Agent to ScopeZero | Is the agent authenticated and acting under a valid mission? |
| ScopeZero to tool connector | Has ScopeZero approved this specific action before connector execution? |
| Mission contract | Is the action inside the signed human-approved scope? |
| Policy governance | Are policy changes controlled and auditable? |
| Tenant boundary | Are data, missions, policies, and evidence tenant-scoped? |
| Evidence boundary | Can decisions be verified after the fact? |
| Secrets boundary | Are connector credentials protected and kept out of logs/evidence? |

## Primary Threats And Controls

| Threat | ScopeZero Control |
| --- | --- |
| Valid agent identity performs wrong action | Mission action contract matching |
| Agent invokes unapproved tool | Tool allowlist |
| Agent performs disallowed operation | Operation and action-type policy |
| Agent exports sensitive data | Data classification and egress guard |
| Agent sends data to unapproved destination | Destination boundary enforcement |
| Malicious document manipulates agent | Prompt influence detection and quarantine |
| Agent escalates cloud privilege | Privilege-impact controls and approval gates |
| Agent delegates beyond scope | Delegation-depth enforcement |
| High-impact action executes automatically | Human approval broker |
| Audit record is altered | Hash-chained evidence ledger |
| Policy changes are untracked | Policy proposal/version evidence |
| Connector credentials leak | Secret references and redaction model |

## Authorization Model

Every proposed tool call is normalized into an action descriptor:

- tool
- operation
- action type
- vendor
- resource
- data class
- destination
- delegation depth
- money impact
- privilege impact

The action is then evaluated against:

- mission contract
- tenant policy
- data sensitivity
- destination
- prompt influence
- risk budget
- approval rules
- session state

Only `allow` and controlled `redact` decisions are considered safe to execute.

## Evidence Model

ScopeZero records:

- agent registration
- mission issuance
- action authorization evaluations
- approval decisions
- policy proposal and review events

Evidence records are linked through `previous_hash` and `hash`, forming a tamper-evident chain.

## Enterprise Hardening Path

For production deployments, ScopeZero should be connected to:

- enterprise IdP
- managed database
- SIEM
- observability collector
- vault or KMS-backed secret provider
- production connector workers
- private networking
- external security review
- software supply chain controls

## Residual Risk

ScopeZero is a runtime authorization layer. It should be deployed alongside:

- IAM
- endpoint security
- DLP
- SIEM/SOAR
- cloud security posture management
- AI model and prompt security
- human operational review

Its role is the missing pre-execution decision point for autonomous agent actions.
