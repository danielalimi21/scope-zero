# ScopeZero Operations Runbook

## Service

ScopeZero Gateway exposes:

- `GET /v1/health` for liveness
- `GET /v1/ready` for readiness
- `GET /metrics` for Prometheus-compatible metrics
- `POST /mcp` for MCP JSON-RPC tool proxying
- `GET /v1/siem/events` for SIEM export
- `GET /v1/telemetry/traces` for local trace inspection
- `GET /v1/compliance/controls` for control mapping

## Start Locally

```powershell
node server.js
```

## Smoke Test

```powershell
node tools\smoke-test.js
node tools\verify-ledger.js
```

## Backup

```powershell
node tools\backup-data.js
```

Backups are written to `backups/<timestamp>`.

## Production Required Environment

Set:

- `NODE_ENV=production`
- `SCOPEZERO_REQUIRE_AUTH=true`
- `SCOPEZERO_ALLOW_DEV_TOKEN=false`
- `SCOPEZERO_SIGNING_SECRET`
- `SCOPEZERO_AUTH_SECRET`
- `SCOPEZERO_SECRETS_MASTER_KEY`
- `SCOPEZERO_CORS_ORIGIN`
- `SCOPEZERO_PUBLIC_BASE_URL`
- `SCOPEZERO_OIDC_ISSUER`
- `SCOPEZERO_OIDC_AUDIENCE`
- `SCOPEZERO_OIDC_JWKS_URL`
- `SCOPEZERO_STORE=postgres`
- `DATABASE_URL`
- `OTEL_EXPORTER_OTLP_ENDPOINT`

Validate:

```powershell
node tools\config-check.js
```

## Incident Response

1. Export evidence:

```text
GET /v1/siem/events?format=json&limit=500
```

2. Verify ledger integrity:

```powershell
node tools\verify-ledger.js
```

3. Preserve `data/scopezero.db` and `data/ledger.jsonl`.
4. Rotate `SCOPEZERO_AUTH_SECRET` if bearer-token compromise is suspected.
5. Rotate `SCOPEZERO_SIGNING_SECRET` if mission capsule signing is suspected compromised.
6. Rotate `SCOPEZERO_SECRETS_MASTER_KEY` and connector credentials if secret compromise is suspected.
7. Reissue active mission capsules.

## Monitoring

Alert on:

- high `scopezero_blocked_actions_total` increase
- high 4xx/5xx from gateway
- ledger verification failure
- auth failures
- connector OAuth callback spikes
- rate-limit spikes
