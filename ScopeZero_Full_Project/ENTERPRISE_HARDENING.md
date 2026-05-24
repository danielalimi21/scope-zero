# Enterprise Hardening Pack

## Implemented In This Build

### Database

ScopeZero now uses SQLite through Node's built-in `node:sqlite` module. It stores state in:

`data/scopezero.db`

The database maintains relational tables for tenants, agents, missions, approvals, policies, and a primary state document. This keeps the local product dependency-free while giving it durable storage and migration structure.

For enterprise pilots, ScopeZero can run with managed Postgres:

- set `SCOPEZERO_STORE=postgres`
- set `DATABASE_URL`
- install runtime dependencies from `package.json`
- use `db/postgres/schema.sql` as the database shape

### Auth and SSO Readiness

Implemented:

- signed bearer tokens
- service API key
- RBAC permissions
- dev token endpoint
- JWKS discovery placeholder at `/.well-known/jwks.json`

Production SSO path:

- configure OIDC/JWKS validation with `SCOPEZERO_OIDC_ISSUER`, `SCOPEZERO_OIDC_AUDIENCE`, and `SCOPEZERO_OIDC_JWKS_URL`
- bridge SAML through the enterprise IdP's OIDC application where needed
- configure `SCOPEZERO_REQUIRE_AUTH=true`
- disable dev tokens with `SCOPEZERO_ALLOW_DEV_TOKEN=false`

### Policy Governance

Implemented:

- policy version list
- policy proposal API
- policy approval and denial API
- ledger evidence for policy proposals and reviews

### Secrets And Observability

Implemented:

- encrypted local secret references
- OpenTelemetry-compatible traces
- optional OTLP trace export
- Prometheus-compatible metrics

### Tenant Isolation

APIs now enforce tenant access checks and filter state/ledger responses for non-platform principals.

### SIEM Export

Implemented:

- JSON event export
- CEF export
- LEEF export
- OTLP-style log payload export

### MCP Proxy

Implemented:

- `POST /mcp`
- `POST /v1/mcp`
- `initialize`
- `notifications/initialized`
- `tools/list`
- `tools/call`

Every `tools/call` goes through ScopeZero policy evaluation before connector execution.

### Cloud/SaaS Connector Layer

Implemented connector registry and local adapters for:

- Google Drive / Microsoft 365 style document tools
- spreadsheet export
- Gmail / Exchange style email send
- Slack draft
- GitHub pull request
- AWS IAM policy change
- ServiceNow case creation

Current connectors are safe local adapters. Production connectors should bind to OAuth/service-account credentials through a vault.

### Deployment

Implemented:

- Dockerfile
- docker-compose.yml
- Kubernetes namespace
- Kubernetes configmap
- Kubernetes secret example
- Kubernetes PVC
- Kubernetes deployment
- Kubernetes service
- Kubernetes network policy

### Security Review

Implemented:

- threat model
- implemented controls
- residual risks
- production readiness checklist

See `SECURITY_REVIEW.md`.

## Enterprise Run Commands

Local:

```powershell
node server.js
```

Strict auth mode:

```powershell
$env:SCOPEZERO_REQUIRE_AUTH='true'
$env:SCOPEZERO_ALLOW_DEV_TOKEN='true'
node server.js
```

Get a dev token:

```powershell
$body = @{ tenant_id='tenant_contoso'; subject='security@contoso.example'; roles=@('tenant_admin') } | ConvertTo-Json
Invoke-RestMethod -Method Post -Uri http://localhost:8788/v1/auth/dev-token -ContentType 'application/json' -Body $body
```

MCP endpoint:

```text
POST http://localhost:8788/mcp
```

SIEM exports:

```text
GET http://localhost:8788/v1/siem/events?format=json
GET http://localhost:8788/v1/siem/events?format=cef
GET http://localhost:8788/v1/siem/events?format=leef
GET http://localhost:8788/v1/siem/otlp
```
