# ScopeZero Security Review And Threat Model

## Review Date

2026-05-11

## Security Objective

ScopeZero must stop autonomous AI agents from executing tool calls outside an approved mission contract, leaking sensitive data, escalating privilege, acting on hostile prompt influence, or bypassing human approval, while producing evidence that security teams can verify after the fact.

## Scope Reviewed

- HTTP gateway and API routing.
- Agent SDK.
- Mission action contract signing and verification.
- Runtime action authorization engine.
- Sensitive data classifier.
- Prompt influence detector.
- Policy proposal, versioning, and approval APIs.
- Human approval workflow.
- MCP JSON-RPC proxy.
- Connector registry.
- Local SQLite state store.
- Optional Postgres state store.
- Hash-chained evidence ledger.
- SIEM export.
- OpenTelemetry-compatible traces.
- Encrypted local secret references.
- OIDC/JWKS auth path, local bearer tokens, API key, RBAC, and tenant filtering.
- Docker and Kubernetes manifests.
- Browser command center.

## Trust Boundaries

1. **Agent to ScopeZero**
   The agent is untrusted until authenticated and every action is evaluated against mission and policy.

2. **ScopeZero to enterprise tools**
   Connectors must not execute until ScopeZero returns a safe decision.

3. **User/administrator to policy**
   Policy writes are privileged and should be reviewed through policy proposals in enterprise mode.

4. **Tenant boundary**
   Tenant IDs in state, policy, missions, approvals, and evidence must be enforced on read and write paths.

5. **Evidence boundary**
   Evidence must be append-only or tamper-evident so post-incident review remains credible.

6. **Secrets boundary**
   Connector credentials must be referenced and protected, not written into logs, policy, or evidence.

## Primary Threats And Controls

| Threat | Implemented Control |
| --- | --- |
| Agent uses valid credentials for the wrong purpose | Mission action contracts and pre-execution authorization |
| Agent invokes an unapproved tool | Tool allowlist and action-contract matching |
| Agent performs a disallowed operation | Operation and action-type policy |
| Agent exports sensitive data | Payload classification and egress guard |
| Agent sends data to an unapproved destination | Destination boundary enforcement |
| Malicious document or tool output manipulates agent | Prompt influence detection and quarantine |
| Agent delegates beyond approved scope | Delegation depth enforcement |
| High-impact action happens automatically | Approval gates |
| Cross-tenant data exposure | RBAC and tenant-scoped filtering |
| Audit tampering | Hash-chained evidence ledger and verification tool |
| Unauthenticated API access | `SCOPEZERO_REQUIRE_AUTH`, bearer tokens, API key, OIDC/JWKS |
| Overbroad access | Role permissions and tenant authorization |
| Oversized request | Request body limit |
| Static asset abuse | Path normalization, no-store, security headers |
| Policy change without audit | Policy proposal/version records and ledger evidence |
| Secret leakage | Encrypted secret references and redaction helper |
| Missing operational visibility | Metrics, SIEM export, telemetry traces |

## Authentication

ScopeZero supports:

- Local HMAC-signed bearer tokens for demos and controlled local environments.
- OIDC/JWKS RS256 validation for enterprise SSO.
- Service API key principal for break-glass or service integration.
- Optional hard auth enforcement through `SCOPEZERO_REQUIRE_AUTH=true`.
- Dev token endpoint that should be disabled in production with `SCOPEZERO_ALLOW_DEV_TOKEN=false`.

SAML should be integrated through the enterprise IdP's SAML-to-OIDC bridge or a trusted gateway that issues JWTs accepted by ScopeZero.

## Authorization

Roles:

- `platform_admin`
- `tenant_admin`
- `security_operator`
- `agent_runtime`
- `auditor`

Actions:

- `tenant:read`
- `agent:write`
- `mission:write`
- `tool:evaluate`
- `policy:write`
- `ledger:read`
- `approval:write`
- `siem:read`
- `mcp:proxy`

Tenant-scoped APIs filter state and ledger events for non-platform principals.

## Mission Contract Integrity

Mission capsules are signed using the ScopeZero signing secret and include:

- tenant
- agent
- human delegator
- objective
- allowed tools
- allowed data classes
- allowed destinations
- risk budget
- approval profile
- expiry
- action contracts

Runtime evaluation blocks missing, expired, or signature-invalid mission capsules.

## Action Authorization

Each request is normalized into an action descriptor:

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

The policy engine evaluates mission scope, action contract, data class, destination, prompt influence, sensitive egress, delegation, financial impact, privilege impact, and session risk.

Possible decisions:

- `allow`
- `block`
- `redact`
- `quarantine_context`
- `approval`
- `pause_session`

Only `allow` and `redact` are safe to execute.

## Evidence And Audit

The evidence ledger records:

- agent registration
- mission issuance
- action authorization evaluations
- approval decisions
- policy proposals and reviews

Each entry includes `previous_hash` and `hash`. `tools/verify-ledger.js` replays the chain and reports failures.

Evidence can be exported to:

- JSON
- CEF
- LEEF
- OTLP-style logs

## MCP Security

ScopeZero exposes `/mcp` and `/v1/mcp`.

Supported methods:

- `initialize`
- `notifications/initialized`
- `tools/list`
- `tools/call`

`tools/call` is evaluated by ScopeZero before connector execution. Unsafe calls return an MCP result with ScopeZero verdict, authorization ID, evidence hash, and approval ID if applicable.

## Secrets

The local secret manager stores encrypted secret references using AES-256-GCM with `SCOPEZERO_SECRETS_MASTER_KEY`.

For production, this should be replaced or backed by the customer's cloud KMS or vault. The current API shape is intentionally reference-based so connectors can move to a vault-backed worker without changing the product model.

## Observability

ScopeZero includes:

- `/metrics` Prometheus metrics.
- `/v1/siem/events` for security exports.
- `/v1/siem/otlp` for OTLP-style logs.
- `/v1/telemetry/traces` for local trace inspection.
- Optional OTLP trace export via `OTEL_EXPORTER_OTLP_ENDPOINT`.
- `/v1/ready` reporting auth, store, Postgres, OTEL, and secrets configuration.

## Deployment Hardening

Docker and Kubernetes include:

- non-root user
- dropped Linux capabilities
- no privilege escalation
- read-only root filesystem
- liveness and readiness probes
- ConfigMap and Secret separation
- PVC for local data mode
- NetworkPolicy starter template
- production env example

## Residual Risks Before Real Production Data

- Replace local encrypted secrets with a managed vault or KMS-backed adapter.
- Use managed Postgres with private networking, PITR, backups, and connection pooling.
- Move evidence to append-only object storage or immutable database retention.
- Add distributed rate limiting for multi-replica deployments.
- Enforce separation of duties for policy proposal approval.
- Add signed connector manifests and real OAuth token exchange workers.
- Add mTLS or service mesh policy for internal connector traffic.
- Add SBOM generation, dependency scanning, image signing, and provenance.
- Add automated negative security tests and fuzzing for policy inputs.
- Run an external penetration test.
- Complete formal SOC2 control ownership, procedures, and audit period.

## Security Posture

ScopeZero is a credible pilot-ready security product core. It has the right control plane shape: auth, RBAC, tenant isolation, mission contracts, pre-execution authorization, MCP enforcement, evidence, SIEM export, policy governance, secrets, observability, and deployment scaffolding.

The next security milestone is a controlled pilot with real IdP, SIEM, Postgres, vault, and one production-like agent workflow using synthetic or low-risk data.
