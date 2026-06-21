# Live integration harness — real IdP + real OTLP

Proves ScopeZero's production seams against real components, not mocks:

- **IdP / SSO**: ScopeZero verifies RS256 access tokens against **Keycloak**'s
  JWKS (`SCOPEZERO_OIDC_*`).
- **Observability**: ScopeZero exports traces to a real **OpenTelemetry
  collector** over OTLP/HTTP.

The code paths are unit-proven without any external service
(`tests/oidc.test.js` — RS256/JWKS accept + reject wrong sig/issuer/audience/
expiry). This harness is the *live* end-to-end proof for a buyer who wants to see
it run against their stack's shape.

## Run

```bash
docker compose -f deploy/integration/docker-compose.yml up -d --build
./deploy/integration/verify.sh
docker compose -f deploy/integration/docker-compose.yml down -v
```

`verify.sh` gets a real token from Keycloak via client-credentials, calls
ScopeZero with it (expects 200), confirms a forged token is rejected (401), and
checks the OTLP collector received spans.

## Status

Requires Docker. The compose + realm + collector config are committed; the code
paths they exercise are covered by the test suite. Mark this "verified live" once
run on a Docker host (CI or a workstation with Docker).

## Wiring to a customer's stack

- Point `SCOPEZERO_OIDC_ISSUER` / `_AUDIENCE` / `_JWKS_URL` at their IdP (Okta,
  Entra, Auth0, Keycloak). RS256 + JWKS is the standard path.
- Point `OTEL_EXPORTER_OTLP_ENDPOINT` at their collector; SIEM export is also
  available at `/v1/siem/events` (JSON/CEF/LEEF) and `/v1/siem/otlp`.
- Move secrets from the local encrypted store to their vault.
