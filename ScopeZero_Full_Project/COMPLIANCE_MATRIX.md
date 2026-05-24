# ScopeZero Compliance Matrix

This matrix maps product controls to common enterprise assurance themes.

| Control | ScopeZero Capability | Evidence |
| --- | --- | --- |
| Access control | Auth, RBAC, tenant isolation | API logs, role policy, token claims |
| Least privilege | Mission-scoped tool allowlists | mission capsule, policy verdict |
| Change management | Policy proposal, versioning, and approval APIs | policy versions, approval evidence |
| Audit logging | Hash-chained evidence ledger | `data/ledger.jsonl`, SIEM export |
| Incident response | Evidence capsule and replay | `/v1/ledger`, `/v1/siem/events` |
| Data protection | sensitive payload classification | verdict reasons, data classification |
| Human approval | approval gate decisions | approval records |
| Third-party integration | MCP proxy and connector registry | connector registry, MCP verdicts |
| Monitoring | `/metrics`, SIEM exports, OTEL traces | Prometheus, SIEM payloads, traces |
| Tenant isolation | tenant-scoped APIs | filtered state and ledger responses |
| Secret protection | encrypted secret references | `/v1/secrets`, secret refs |

## SOC 2 Readiness Notes

ScopeZero has the technical beginnings for Security and Availability criteria, but formal SOC 2 requires:

- written policies
- employee access processes
- vendor management
- change-management evidence
- incident response testing
- independent audit period

## EU AI Act / AI Governance Notes

ScopeZero can help produce evidence for:

- traceability
- human oversight
- risk management
- logging
- data governance

It is not itself a substitute for legal classification of a customer's AI system.
