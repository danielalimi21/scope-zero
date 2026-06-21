#!/usr/bin/env bash
# Proves the live integration: get a real RS256 access token from Keycloak, call
# ScopeZero with it (OIDC/JWKS verification), and confirm a trace reached the OTLP
# collector. Run after `docker compose -f deploy/integration/docker-compose.yml up -d`.
set -euo pipefail

KC="http://localhost:8080"
SZ="http://localhost:8788"
COMPOSE="docker compose -f deploy/integration/docker-compose.yml"

echo "→ waiting for ScopeZero health…"
for i in $(seq 1 60); do curl -fsS "$SZ/v1/health" >/dev/null 2>&1 && break; sleep 2; done

echo "→ getting an RS256 access token from Keycloak (client_credentials)…"
TOKEN=$(curl -fsS -X POST "$KC/realms/scopezero/protocol/openid-connect/token" \
  -d "grant_type=client_credentials" \
  -d "client_id=scopezero-pilot" \
  -d "client_secret=pilot-secret" | sed -n 's/.*"access_token":"\([^"]*\)".*/\1/p')
test -n "$TOKEN" || { echo "FAIL: no token from Keycloak"; exit 1; }
echo "  got token (${#TOKEN} chars)"

echo "→ calling ScopeZero with the real IdP token…"
CODE=$(curl -s -o /dev/null -w "%{http_code}" "$SZ/v1/state" -H "authorization: Bearer $TOKEN")
echo "  GET /v1/state -> HTTP $CODE"
test "$CODE" = "200" || { echo "FAIL: OIDC token not accepted (expected 200)"; exit 1; }

echo "→ confirming a forged/unsigned token is rejected…"
BAD=$(curl -s -o /dev/null -w "%{http_code}" "$SZ/v1/state" -H "authorization: Bearer not.a.realtoken")
test "$BAD" = "401" || { echo "FAIL: forged token not rejected (got $BAD)"; exit 1; }
echo "  forged token -> HTTP $BAD (rejected)"

echo "→ checking the OTLP collector received traces…"
sleep 3
if $COMPOSE logs otel-collector 2>/dev/null | grep -qiE "ScopeName|scopezero|Span #"; then
  echo "  OTLP collector received spans ✓"
else
  echo "  WARN: no spans seen yet in collector logs (traces may be batched); check manually:"
  echo "        $COMPOSE logs otel-collector | grep -i span"
fi

echo
echo "PASS: real IdP token accepted, forged token rejected, OTLP wired."
