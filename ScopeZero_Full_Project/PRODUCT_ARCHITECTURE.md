# ScopeZero Product Architecture

## Positioning

ScopeZero is a pre-execution authorization gateway for autonomous AI-agent tool calls.

It is not an AI chatbot monitor, prompt scanner, IAM replacement, or SIEM dashboard. It is the runtime control layer that decides whether a specific autonomous action is allowed before the tool call executes.

The core product primitive is the **Mission Action Contract**: a signed, short-lived authorization object that says which agent may perform which actions, through which tools, against which data classes and destinations, under which human delegation and risk limits.

## System Components

1. **Agent SDK**
   Agents call ScopeZero before executing enterprise tools. The SDK wraps health, registration, mission creation, action authorization, MCP, approvals, and SIEM access.

2. **Gateway API**
   `server.js` exposes the runtime API, static product UI, MCP proxy, SIEM export, telemetry, compliance, policy, secrets, and connector endpoints.

3. **Identity And RBAC Layer**
   `src/auth.js` supports local signed bearer tokens, service API keys, OIDC/JWKS RS256 validation, roles, permissions, and tenant filtering.

4. **Mission Contract Service**
   `src/capsules.js` creates signed mission capsules with agent identity, human delegator, objective, allowed tools, allowed data classes, allowed destinations, expiry, delegation limits, approval profile, and action contracts.

5. **Action Authorization Engine**
   `src/runtime.js`, `src/actionAuthorization.js`, and `src/policyEngine.js` convert a tool call into an action descriptor and evaluate it against mission, policy, data, destination, prompt influence, risk budget, and approval rules.

6. **Policy Governance**
   Policies can be read, updated directly for local work, or proposed and reviewed through versioned policy approval endpoints. Policy changes are sealed into the evidence ledger.

7. **Approval Broker**
   High-impact actions can return `approval` instead of execution. Approval decisions are recorded with reviewer and timestamp.

8. **Connector Registry**
   `src/connectors.js` defines vendor-neutral connector boundaries for Google/Microsoft drive, Sheets/Excel, Gmail/Exchange, Slack, GitHub, AWS IAM, and ServiceNow. The current adapters are guarded boundaries suitable for pilots; production connectors should attach real OAuth workers and vendor APIs.

9. **MCP Proxy**
   `src/mcp.js` implements MCP JSON-RPC `initialize`, `tools/list`, and guarded `tools/call`. Every MCP tool call is authorized by ScopeZero before connector execution.

10. **Evidence Ledger**
    `src/ledger.js` writes hash-chained JSONL evidence with `previous_hash` and `hash`. `tools/verify-ledger.js` verifies integrity.

11. **State Store**
    Local mode uses `src/store.js` with Node's built-in SQLite. Production-style mode uses `src/postgresStore.js` with `SCOPEZERO_STORE=postgres` and `DATABASE_URL`.

12. **Secrets And Observability**
    `src/secrets.js` provides encrypted local secret references. `src/telemetry.js` records OpenTelemetry-compatible spans and can export to an OTLP collector.

13. **Command Center UI**
    `index.html`, `styles.css`, and `app.js` show the attack simulation, runtime policy state, evidence room, pitch room, and product story.

## Runtime Flow

1. An agent registers with ScopeZero.
2. A human or system creates a mission action contract.
3. ScopeZero signs the contract into a mission capsule.
4. The agent prepares a tool call.
5. The SDK or MCP proxy sends the proposed action to ScopeZero.
6. ScopeZero classifies payload sensitivity and destination risk.
7. ScopeZero detects prompt influence from documents, pages, chats, or tool output.
8. ScopeZero matches the action against the signed mission contract.
9. ScopeZero applies tenant policy, risk budget, delegation, approval, and egress rules.
10. ScopeZero returns `allow`, `block`, `redact`, `quarantine_context`, `approval`, or `pause_session`.
11. ScopeZero appends the decision to the evidence ledger.
12. The agent executes only if the decision is safe to execute.

## Decision Inputs

- Tenant ID
- Agent ID
- Human delegator
- Mission ID and capsule signature
- Tool name
- Operation
- Action type
- Data class
- Destination
- Resource
- Money or privilege impact
- Delegation depth
- Prompt influence
- Mission alignment
- Session risk consumed
- Tenant policy version

## Enterprise Deployment Surface

ScopeZero now includes the main pieces an enterprise buyer expects to see in a serious pilot:

| Enterprise Need | Project Surface |
| --- | --- |
| Managed Postgres for multi-replica writes | `src/postgresStore.js`, `db/postgres/schema.sql`, `SCOPEZERO_STORE=postgres` |
| OpenTelemetry traces | `src/telemetry.js`, `/v1/telemetry/traces`, `OTEL_EXPORTER_OTLP_ENDPOINT` |
| Enterprise SSO/OIDC/JWKS | `src/auth.js`, `SCOPEZERO_OIDC_*` |
| SAML compatibility | Use IdP SAML-to-OIDC bridge or gateway-issued JWTs |
| Encrypted secrets | `src/secrets.js`, `/v1/secrets`, `SCOPEZERO_SECRETS_MASTER_KEY` |
| Policy versioning and approvals | `/v1/policy/versions`, `/v1/policy/proposals`, review endpoints |
| SIEM export | JSON, CEF, LEEF, OTLP-style log endpoints |
| MCP proxy | `/mcp`, `/v1/mcp` |
| SaaS/cloud connector boundaries | `src/connectors.js` |
| Kubernetes deployment | `k8s/` manifests |
| SOC2-oriented audit controls | `/v1/compliance/controls`, ledger, RBAC, approvals, metrics |
| Threat model | `SECURITY_REVIEW.md` |

## API Map

Core runtime:

- `POST /v1/agents`
- `POST /v1/missions`
- `POST /v1/action-authorizations`
- `POST /v1/tool-calls`
- `POST /mcp`
- `POST /v1/mcp`

Governance:

- `GET /v1/policy`
- `PUT /v1/policy`
- `GET /v1/policy/versions`
- `POST /v1/policy/proposals`
- `POST /v1/policy/proposals/:id/approve`
- `POST /v1/policy/proposals/:id/deny`
- `POST /v1/approvals/:id/approve`
- `POST /v1/approvals/:id/deny`

Evidence and operations:

- `GET /v1/ledger`
- `GET /v1/ledger/verify`
- `GET /v1/siem/events`
- `GET /v1/siem/otlp`
- `GET /v1/telemetry/traces`
- `GET /v1/compliance/controls`
- `GET /metrics`
- `GET /v1/ready`

Integrations:

- `GET /v1/connectors`
- `POST /v1/connectors/oauth/start`
- `GET /v1/connectors/oauth/callback`
- `GET /v1/secrets`
- `POST /v1/secrets`

## Deployment Modes

### Local Product Demo

- SQLite state.
- JSONL evidence ledger.
- Local signed bearer tokens.
- Dev token endpoint enabled.
- Static UI served by the gateway.

### Controlled Enterprise Pilot

- OIDC/JWKS enabled.
- Dev token disabled.
- Managed Postgres.
- OTLP collector configured.
- SIEM export connected.
- Real first connector attached behind the existing connector boundary.
- Secrets moved from local encrypted store to customer vault.
- Kubernetes deployment with private network access.

### Production SaaS Direction

- Dedicated tenant isolation model.
- Distributed rate limiting.
- Ledger storage in append-only object storage or database-backed immutable table.
- Policy separation of duties.
- Signed connector manifests.
- SBOM, dependency scanning, image signing, and external penetration test.
- Formal compliance program and audit period.

## Why This Can Become Valuable

The product sits at the intersection of IAM, AI security, DLP, SOC evidence, MCP governance, cloud security, and enterprise workflow control.

As agents become real enterprise actors, companies will need to answer:

- Who delegated this agent?
- Which mission authorized this action?
- Was the tool call inside scope?
- Was the destination approved?
- Did hostile context influence the action?
- Did sensitive data attempt to cross a boundary?
- Was a human approval required?
- Can we prove the answer after an incident?

ScopeZero is built around those questions.
