# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository Layout

The runnable product lives in `ScopeZero_Full_Project/`. The rest of the repo is sales/buyer collateral:

- `ScopeZero_Full_Project/` — Node.js gateway, policy engine, connectors, SDK, tests, docs, k8s manifests, and pilot tooling. **All development commands must be run from this directory.**
- `ScopeZero_CISO_Buyer_Packet/` — buyer-facing markdown packet plus a standalone static demo (`demo/index.html`, `index.html`).
- `ScopeZero_Founder_Sales_Playbook.md` — sales playbook, not code.

When the user references "the project" they usually mean `ScopeZero_Full_Project/`.

## Commands

All commands run from `ScopeZero_Full_Project/`. Requires Node.js ≥ 20 (CI uses Node 24). There are no production npm dependencies (`pg` is optional); `npm install` is only needed if you opt into Postgres.

```bash
node server.js                    # start the gateway on :8788 (override with --port=, PORT env)
npm run check                     # syntax-check every JS file (run before commits/PRs)
npm test                          # node --test on tests/*.test.js
node --test tests/policy-engine.test.js   # run a single test file
node tools/smoke-test.js          # end-to-end smoke test against a running gateway
node tools/verify-ledger.js       # verify hash-chain integrity of data/ledger.jsonl
npm run proof:ciso                # full GitHub/Slack/AWS buyer proof run; writes CISO_PROOF_REPORT.md
npm run pilot:local               # local pilot scenario matrix; writes LOCAL_PILOT_REPORT.md
npm run readiness:report          # writes ENTERPRISE_READINESS_REPORT.md
```

The CI workflow at `ScopeZero_Full_Project/.github/workflows/scopezero-ci.yml` runs `npm run check`, `npm test`, `npm run readiness:report`, then starts the gateway and runs the smoke test and ledger verification — keep that path green.

Connector pilots (`pilot:github`, `pilot:slack`, `pilot:aws`) require live credentials in env vars (`SCOPEZERO_GITHUB_*`, `SCOPEZERO_SLACK_*`); see `ScopeZero_Full_Project/README.md` for the exact variable names. The gateway and the pilot script must share the same environment.

## Architecture

ScopeZero is a **pre-execution authorization gateway for AI-agent tool calls**. Slogan to keep in mind while editing: *"The agent was authorized. The action was not."* IAM decides access; ScopeZero decides whether a specific autonomous action is allowed before the tool runs.

### Request flow (the core path through the code)

1. Agent registers (`POST /v1/agents` → `runtime.registerAgent`).
2. Human/system creates a **mission action contract** (`POST /v1/missions`). `src/capsules.js` builds and HMAC-signs a short-lived mission capsule containing allowed tools, data classes, destinations, delegation depth, risk budget, and action contracts (default contracts auto-derived by `buildDefaultActionContracts` in `src/actionAuthorization.js`).
3. Agent proposes a tool call (`POST /v1/tool-calls` or `POST /v1/action-authorizations`, or MCP `tools/call` via `src/mcp.js`).
4. `runtime.evaluateToolCall` (`src/runtime.js`) orchestrates:
   - `describeActionRequest` (`src/actionAuthorization.js`) → action descriptor (tool, operation, action_type, data_class, destination).
   - `classifyPayload` / `detectPromptInfluence` / `isExternalDestination` (`src/sensitiveData.js`).
   - Mission capsule signature + expiry check (`verifyMissionCapsule`, `isExpired`).
   - `evaluatePolicy` (`src/policyEngine.js`) returns a verdict: `allow | block | redact | quarantine_context | approval | pause_session`.
5. Verdict is appended to the hash-chained evidence ledger (`src/ledger.js` → `data/ledger.jsonl`), session risk is updated, and approvals are created when needed.

The policy engine is layered — each check can only **escalate** the decision via `stronger()`. When changing policy semantics, preserve that monotonicity or downstream tests/reports will silently regress.

### Component map

| Concern | File |
| --- | --- |
| HTTP server, routing, CORS, rate limit, env wiring | `server.js` |
| Browser UI (static, served from gateway) | `index.html`, `app.js`, `styles.css` |
| Runtime orchestration | `src/runtime.js` |
| Mission capsules (signed HMAC) | `src/capsules.js` |
| Action descriptor + contract matching | `src/actionAuthorization.js` |
| Policy decision engine | `src/policyEngine.js` |
| Default tenant policy | `config/defaultPolicy.json` |
| Sensitive-data + prompt-injection classifier | `src/sensitiveData.js` |
| Hash-chained evidence ledger | `src/ledger.js` (verified by `tools/verify-ledger.js`) |
| Local state store (Node built-in SQLite) | `src/store.js` |
| Optional Postgres store (`SCOPEZERO_STORE=postgres`) | `src/postgresStore.js`, `db/postgres/schema.sql` |
| Auth: dev tokens, API keys, OIDC/JWKS, RBAC, tenancy | `src/auth.js` |
| Connector registry + adapters (GitHub, Slack, AWS IAM…) | `src/connectors.js` |
| MCP JSON-RPC proxy (guarded `tools/call`) | `src/mcp.js` |
| Encrypted local secret references | `src/secrets.js` |
| SIEM export (JSON/CEF/LEEF/OTLP) | `src/siem.js` |
| OpenTelemetry spans + OTLP export | `src/telemetry.js` |
| Agent SDK (used by demos & pilots) | `sdk/scopezero-sdk.js` |
| End-to-end agent demo | `examples/malicious-diligence-agent.js` |
| Formal API contract | `openapi.yaml` |

### State and storage

- Local mode persists to `ScopeZero_Full_Project/data/scopezero.db` (SQLite, WAL) and `data/ledger.jsonl` (append-only, hash-chained). These are runtime artifacts — do not commit them, do not edit them by hand, and treat ledger entries as immutable.
- Postgres mode is opt-in via `SCOPEZERO_STORE=postgres` + `DATABASE_URL`; schema in `db/postgres/schema.sql`. The optional `pg` package is the only npm dependency.

### Auth model

- Local dev: `POST /v1/auth/dev-token` issues a signed bearer token; gated by `SCOPEZERO_ALLOW_DEV_TOKEN` (default on) and `SCOPEZERO_REQUIRE_AUTH` (default off).
- Production: set `SCOPEZERO_REQUIRE_AUTH=true`, `SCOPEZERO_ALLOW_DEV_TOKEN=false`, and configure `SCOPEZERO_OIDC_ISSUER`/`SCOPEZERO_OIDC_AUDIENCE`/`SCOPEZERO_OIDC_JWKS_URL` for RS256 JWT validation.
- `auditPrincipal` (`src/auth.js`) is what handlers use to extract the authenticated principal — go through it rather than re-parsing tokens.

## Conventions That Aren't Obvious From The Code

- **ES modules only** (`"type": "module"` in `package.json`). Use `import` / `export`, not CommonJS.
- **No build step, no transpiler, no test framework.** Stick to `node --test` and Node ≥ 20 standard library (including built-in `node:sqlite`). Don't reach for Jest, Vitest, TypeScript, or bundlers.
- **No runtime npm dependencies** except optional `pg`. Don't introduce new dependencies without strong reason — `npm run check` currently passes against a vendored-stdlib codebase.
- **Keep `npm run check`'s file list in sync** when you add a new source file under `src/`, `tools/`, or `examples/` — it explicitly enumerates each path with `node --check`.
- **Evidence ledger is append-only.** Every state-changing operation should produce a ledger entry via `ledger.append({ event_type, ... })`. Don't mutate prior entries; `tools/verify-ledger.js` will fail and so will CI.
- **Policy decisions only escalate.** New checks in `policyEngine.js` must use `stronger()` rather than overwriting `decision`, or they'll let a higher-severity verdict get downgraded.
- **Buyer-facing markdown files in `ScopeZero_Full_Project/` are part of the product surface.** Reports like `CISO_PROOF_REPORT.md`, `LOCAL_PILOT_REPORT.md`, and `ENTERPRISE_READINESS_REPORT.md` are *generated* by `tools/` scripts — regenerate them via the relevant `npm run` script rather than editing by hand.
