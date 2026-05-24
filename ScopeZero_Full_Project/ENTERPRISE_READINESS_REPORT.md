# ScopeZero Enterprise Readiness Report

Generated: 2026-05-19T10:58:30.101Z

## Summary

Readiness artifact coverage: **100%** (29/29)

ScopeZero is a pilot-ready product core for agent action authorization. It includes the runtime gateway, SDK, mission contracts, policy engine, evidence ledger, MCP proxy, SIEM export, auth/RBAC, OpenAPI contract, automated tests, deployment scaffolding, and buyer/security documentation.

## Verified Artifacts

| Area | File | Status | SHA-256 |
| --- | --- | --- | --- |
| Gateway API | `server.js` | present | 90819f5cf0fb |
| OpenAPI contract | `openapi.yaml` | present | 718d93006598 |
| Agent SDK | `sdk/scopezero-sdk.js` | present | 6025193bffb1 |
| Mission contracts | `src/capsules.js` | present | c6658cb18df7 |
| Action authorization | `src/actionAuthorization.js` | present | 508d8d9d56fd |
| Policy engine | `src/policyEngine.js` | present | edc3e8d52eca |
| MCP proxy | `src/mcp.js` | present | ca6164a7992e |
| SIEM export | `src/siem.js` | present | 048a07cf11d4 |
| Evidence ledger | `src/ledger.js` | present | 76db34ea09f7 |
| Ledger verifier | `tools/verify-ledger.js` | present | fd2975584cea |
| OIDC/JWKS and RBAC | `src/auth.js` | present | 77602f155a83 |
| Encrypted secrets | `src/secrets.js` | present | 777dc498ab6b |
| OpenTelemetry traces | `src/telemetry.js` | present | 179f72369ee9 |
| SQLite store | `src/store.js` | present | 7b85367b0727 |
| Postgres store | `src/postgresStore.js` | present | f8b2f4accaaf |
| Postgres schema | `db/postgres/schema.sql` | present | ede715f28a7d |
| Kubernetes manifests | `k8s/deployment.yaml` | present | 61f870a10fa3 |
| Docker image | `Dockerfile` | present | bb8d7ccba29c |
| Security review | `SECURITY_REVIEW.md` | present | a4d06619a148 |
| Product architecture | `PRODUCT_ARCHITECTURE.md` | present | cb27d7ffde69 |
| Company pitch | `SEND_TO_COMPANIES.md` | present | fdbbd3c57874 |
| Full overview | `SCOPEZERO_FULL_OVERVIEW.md` | present | bb0f5f13a9b8 |
| Commercial readiness | `COMMERCIAL_READINESS.md` | present | bf14ead145ff |
| Customer pilot proposal | `CUSTOMER_PILOT_PROPOSAL.md` | present | fbef691c3d75 |
| Pricing and packaging | `PRICING_AND_PACKAGING.md` | present | a19b61db564b |
| Buyer FAQ | `BUYER_FAQ.md` | present | ca3ac8174239 |
| GA checklist | `GA_RELEASE_CHECKLIST.md` | present | 7bb8253c1380 |
| CI workflow | `.github/workflows/scopezero-ci.yml` | present | bc649af6ad60 |
| Automated tests | `tests/policy-engine.test.js` | present | 0eba74d7e942 |

## Verification Commands

- `npm run check`
- `npm test`
- `node tools/smoke-test.js`
- `node examples/malicious-diligence-agent.js`
- `node tools/verify-ledger.js`
- `node tools/config-check.js`

## Production Gaps

- Connect a real enterprise IdP and verify customer role/group claim mapping.
- Run managed Postgres with private networking, PITR, backups, and connection pooling.
- Move local encrypted secret storage to a customer vault or KMS-backed provider.
- Persist evidence to append-only object storage or immutable database retention.
- Add distributed rate limiting for multi-replica production.
- Attach the first real connector worker and OAuth token exchange.
- Add SBOM generation, dependency scanning, provenance, and image signing.
- Run external penetration testing before customer production data.

## Buyer-Relevant Proof Points

- Pre-execution action authorization is implemented through `/v1/action-authorizations` and MCP `tools/call`.
- Mission action contracts are signed and verified before runtime execution.
- Sensitive egress, prompt influence, delegation depth, destination, and high-impact actions are policy inputs.
- Unsafe actions return block, quarantine, redact, approval, or pause decisions before tool execution.
- Every major decision is written into a hash-chained evidence ledger.
- Evidence can be exported to SOC tooling through JSON, CEF, LEEF, and OTLP-style payloads.
- The project includes OpenAPI, tests, Kubernetes, Docker, Postgres path, OTEL path, and security review.

## Recommended Next Pilot

Run one controlled pilot with one internal agent, two tools, one sensitive workflow, one SIEM integration, one IdP integration, and one approval gate. Success is a blocked out-of-scope action with usable SOC evidence.
