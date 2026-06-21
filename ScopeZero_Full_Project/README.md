# ScopeZero — Authorized Autonomy

**The trust layer you drop in so an AI agent can take real, irreversible actions — move money, change cloud infrastructure, send things to the outside world — without ever exceeding what a human authorized, and with a verifiable receipt for every action.**

![ScopeZero keeping an agent inside its authority — run it yourself in 10s with `npm run demo`](gtm/scopezero-demo.gif)

ScopeZero gives an agent a **signed, time-boxed authority** — *this agent, delegated by this human, may use these tools, on this data, to these destinations, until this time.* Then it enforces that authority before each action runs:

- the agent works **autonomously** inside its authority;
- it is **contained** — blocked before execution — the moment it tries to exceed it;
- any **irreversible** action (grant privilege, move money, external send) is held for a **human co-sign** instead of running on the agent's word;
- every decision lands on a **tamper-evident receipt** you can hand to an auditor — or to your own customer.

We don't try to *detect* a bad agent after the fact. We make it impossible for the agent to exceed a signed authority, and we prove it couldn't have. Detection gives you a probability; containment gives you a guarantee — and a guarantee is what matters when the action can't be undone.

The core line:

> The agent was authorized. The action was not.

> **Repositioning note (Jun 2026):** ScopeZero is moving from a horizontal "AI authorization gateway" to **Authorized Autonomy** — an embeddable layer for builders of agents that take irreversible actions. The engine is the same and fully runnable; what sharpens is the focus. See [REPOSITIONING.md](REPOSITIONING.md) for the architecture and path of work.

## Why It Matters

Enterprises are moving from chatbots to autonomous agents that can reason, browse, retrieve documents, call APIs, write code, modify cloud settings, use SaaS tools, and trigger business workflows.

Existing controls answer pieces of the problem:

- IAM asks whether an identity has access.
- DLP asks whether data looks sensitive.
- EDR/SIEM asks what happened after execution.
- AI safety tools inspect prompts and model behavior.

ScopeZero is the missing runtime control: **pre-execution authorization for every agent tool call**, based on identity, human delegation, mission contract, tool, operation, data class, destination, prompt influence, risk budget, and approval policy.

## What Is Implemented

This repository contains a runnable product. The **core** is the spine of the
product — authorize each action, contain it, record it. Everything under
**Experimental / demo surface** is real and tested but secondary; it exists to
demonstrate breadth and is not what the product leads with.

**Core**

- Live Node.js gateway on `http://localhost:8788`.
- Mission action contracts signed into short-lived capsules.
- Pre-execution action authorization API.
- Runtime policy engine with allow, block, redact, quarantine, approval, and pause decisions — the deterministic contract gates (tool / operation / data class / destination) are the controls that actually block.
- Fail-closed-on-unknown egress: outbound content whose data class can't be positively established *from the bytes* is held for human review, not trusted as public — a tool manifest's declared output class is a verified ceiling, not a skip-flag, so this catches exfiltration to an in-contract host through any tool, manifested or not (`npm run demo:exfil`). "External" is established from the destination address, so a caller cannot self-declare a destination "internal" to dodge the check.
- Ingest-taint / anti-laundering: a *mission* that has read confidential data and then sends lower-classed content to an external destination is held for review — catching data the model rewrote into benign-looking prose, which no content inspection can see (`npm run demo:breach`, step 7). Taint is keyed at mission scope (the Ed25519-bound `mission_id`), so a prompt-injected agent cannot reset it by rotating its `session_id`.
- Default-closed external egress (`seal_external_egress`, **on by default**): every meaningful external post is held for human review unless its destination is an explicitly declared public-broadcast sink (`public_egress_destinations` / contract `public_egress_ok`). Decoupled from the mission's data clearance, so narrowing a mission never *reduces* its egress protection — it closes the residual the bytes and taint can't see (a secret read out-of-band and laundered into prose on a never-tainted session). Autonomy on an external lane is an explicit, signed, auditable opt-in, not the default (`npm run demo:breach`, step 7b). The narrower clearance-gated `seal_sensitive_mission_egress` remains for operators who want the seal only on confidential missions.
- Content classification: keyword + structured-value detection (Luhn cards in any separator style, IBAN, SSN, secret prefixes, high-entropy tokens, with base64/hex decode-and-rescan) and a pluggable seam for an embedding/commercial-DLP classifier.
- Hash-chained, HMAC-keyed evidence ledger with verification tooling and optional external anchoring.
- Agent SDK (authorize-then-execute, fail-closed on block/approval and on gateway error).
- HTTPS `CONNECT` egress proxy + kernel lockdown (K8s NetworkPolicy or Docker internal network) — destination-level containment an injected agent can't route around.
- Human approval broker.
- Advisory signals (raise risk / route to approval, never block alone): keyword data classifier, an obfuscation-normalizing prompt-influence heuristic, a keyword-overlap intent-drift screen.

**Experimental / demo surface**

- Browser command center and attack simulation; end-to-end malicious diligence agent example.
- SIEM exports for JSON, CEF, LEEF, and OTLP-style logs.
- MCP JSON-RPC proxy for guarded `tools/call`; MCP trust registry with OSV CVE refresh.
- Connector registry; live GitHub draft-PR and Slack demo-channel connectors with safe local fallback; AWS IAM safe simulation.
- Agent identity certificates; behavioral anomaly detection.
- OIDC/JWKS validation, local signed bearer tokens, RBAC, API keys, tenant filtering.
- Optional managed Postgres store with row-level security for multi-replica state.
- Encrypted local secret references; policy proposal/approval/version APIs.
- OpenTelemetry traces, Prometheus metrics, Docker/Kubernetes scaffolding.
- SOC2-oriented control map and security review.

## Run Locally

```bash
node --version
node server.js
```

Open:

```text
http://localhost:8788
```

The browser app connects to the live backend when served from the gateway. If `index.html` is opened directly, it still runs in static simulator mode.

## Verify

Run the hero demo first — it's a self-contained, executable proof (exit code is
non-zero if any guarantee fails to hold):

```bash
npm run demo          # Authorized Autonomy: agent works, can't exceed authority, co-sign + receipt
npm run demo:breach   # injected agent vs. a signed authority — every escape contained
```

Then the full verification surface:

```bash
npm run check
npm test                         # 259 tests, 0 failures
node tools/smoke-test.js
node tools/verify-ledger.js
node tools/config-check.js
node tools/gen-keys.js            # generate an Ed25519 signing keypair
node tools/lockdown-selftest.js  # is egress actually contained?
npm run bench                    # persistence hot-path throughput
npm run pilot:local
```

The smoke test validates health, auth, connectors, policy proposal approval, MCP authorization, action authorization, and SIEM export.
The local pilot runs a fuller workflow scenario matrix and writes a local report file.

## GitHub Connector Pilot

The GitHub connector can create a real draft pull request after ScopeZero authorizes the action.

Required environment variables:

```bash
export SCOPEZERO_GITHUB_TOKEN="<github-token>"
export SCOPEZERO_GITHUB_OWNER="your_github_username"
export SCOPEZERO_GITHUB_REPO="scopezero-demo-repo"
```

Run the gateway from the same terminal where those variables are set:

```bash
node server.js
```

Then run the pilot from another terminal that has the same variables:

```bash
npm run pilot:github
```

Expected result: ScopeZero registers a demo agent, issues a signed mission contract, authorizes the `github.pr` tool call, commits `scopezero-demo.md` to a new branch, and opens a draft PR in the configured GitHub repository.

## Slack Connector Pilot

The Slack connector posts only to the configured test channel after ScopeZero authorizes the action.

Required environment variables:

```bash
export SCOPEZERO_SLACK_BOT_TOKEN="<slack-bot-token>"
export SCOPEZERO_SLACK_CHANNEL_ID="C0123456789"
export SCOPEZERO_SLACK_ALLOWED_CHANNEL="scopezero-demo"
```

Run the gateway from the same terminal where those variables are set:

```bash
node server.js
```

Then run:

```bash
npm run pilot:slack
```

Expected result: ScopeZero posts one safe internal Slack message, then blocks a restricted/prompt-influenced Slack message before Slack is called.

## AWS IAM Pilot

The AWS IAM connector runs in safe simulation mode. It does not mutate AWS.

Run:

```bash
npm run pilot:aws
```

Expected result: ScopeZero blocks an attempted `AdministratorAccess` attachment before execution, then routes a lower-risk IAM policy change to human approval. The connector reports `aws_mutation_performed: false`.

## Demo Flow

1. Open `http://localhost:8788`.
2. Start in Command Center.
3. Click **Run Attack Simulation**.
4. Watch an M&A diligence agent read a malicious document.
5. The agent attempts to export confidential revenue data and send it externally.
6. ScopeZero blocks the tool calls before execution.
7. Open Evidence Room to show the hash-chained forensic record.
8. Run `node examples/malicious-diligence-agent.js` to prove the same story through the SDK and live gateway APIs.

## Core APIs

- `GET /v1/health`
- `GET /v1/ready`
- `POST /v1/auth/dev-token`
- `GET /v1/state`
- `GET /v1/ledger`
- `GET /v1/ledger/verify`
- `GET /v1/policy`
- `PUT /v1/policy`
- `GET /v1/policy/versions`
- `POST /v1/policy/proposals`
- `POST /v1/policy/proposals/:id/approve`
- `POST /v1/policy/proposals/:id/deny`
- `GET /v1/secrets`
- `POST /v1/secrets`
- `GET /v1/connectors`
- `POST /v1/connectors/oauth/start`
- `GET /v1/connectors/oauth/callback`
- `POST /v1/agents`
- `POST /v1/missions`
- `POST /v1/action-authorizations`
- `POST /v1/tool-calls`
- `POST /v1/approvals/:id/approve`
- `POST /v1/approvals/:id/deny`
- `GET /v1/siem/events?format=json|cef|leef`
- `GET /v1/siem/otlp`
- `GET /v1/telemetry/traces`
- `GET /v1/compliance/controls`
- `POST /mcp`
- `POST /v1/mcp`
- `GET /metrics`

## Production Configuration

Local mode uses SQLite and JSONL evidence so the project runs without external services. Production-style deployment is configured through environment variables:

```bash
NODE_ENV=production
PORT=8788
SCOPEZERO_REQUIRE_AUTH=true
SCOPEZERO_ALLOW_DEV_TOKEN=false
SCOPEZERO_STORE=postgres
DATABASE_URL=postgres://...
SCOPEZERO_SIGNING_SECRET=...
SCOPEZERO_AUTH_SECRET=...
SCOPEZERO_SECRETS_MASTER_KEY=...
SCOPEZERO_CORS_ORIGIN=https://scopezero.example.com
SCOPEZERO_PUBLIC_BASE_URL=https://scopezero.example.com
SCOPEZERO_OIDC_ISSUER=https://login.example.com/
SCOPEZERO_OIDC_AUDIENCE=api://scopezero
SCOPEZERO_OIDC_JWKS_URL=https://login.example.com/.well-known/jwks.json
OTEL_EXPORTER_OTLP_ENDPOINT=https://otel-collector.example.com/v1/traces
```

See [config/production.env.example](config/production.env.example), [k8s](k8s), and [db/postgres/schema.sql](db/postgres/schema.sql).

## Important Files

- [server.js](server.js) - HTTP gateway and API surface.
- [src/runtime.js](src/runtime.js) - runtime orchestration.
- [src/policyEngine.js](src/policyEngine.js) - authorization decisions.
- [src/actionAuthorization.js](src/actionAuthorization.js) - action descriptors and mission-contract matching.
- [src/capsules.js](src/capsules.js) - signed mission capsules.
- [src/store.js](src/store.js) - local SQLite state store.
- [src/postgresStore.js](src/postgresStore.js) - optional Postgres state store.
- [src/ledger.js](src/ledger.js) - hash-chained evidence ledger.
- [src/auth.js](src/auth.js) - auth, OIDC/JWKS, RBAC.
- [src/mcp.js](src/mcp.js) - MCP proxy.
- [src/connectors.js](src/connectors.js) - connector registry and GitHub PR connector.
- [src/siem.js](src/siem.js) - SIEM exports.
- [src/secrets.js](src/secrets.js) - encrypted secret references.
- [src/telemetry.js](src/telemetry.js) - OpenTelemetry-compatible traces.
- [sdk/scopezero-sdk.js](sdk/scopezero-sdk.js) - agent SDK.
- [examples/malicious-diligence-agent.js](examples/malicious-diligence-agent.js) - live end-to-end demo.
- [tools/github-connector-pilot.js](tools/github-connector-pilot.js) - live GitHub connector pilot.
- [tools/slack-connector-pilot.js](tools/slack-connector-pilot.js) - live Slack connector pilot.
- [tools/aws-iam-pilot.js](tools/aws-iam-pilot.js) - safe AWS IAM privilege-change pilot.
- [openapi.yaml](openapi.yaml) - formal API contract.
- [tests](tests) - automated tests for policy, contracts, auth, secrets, and ledger integrity.
- [.github/workflows/scopezero-ci.yml](.github/workflows/scopezero-ci.yml) - CI verification workflow.
- [PRODUCT_ARCHITECTURE.md](PRODUCT_ARCHITECTURE.md) - technical architecture.
- [SECURITY_REVIEW.md](SECURITY_REVIEW.md) - security review and threat model.
- [RED_TEAM.md](RED_TEAM.md) - adversarial log: attacks tried, what's closed, what isn't.
- [GA_RELEASE_CHECKLIST.md](GA_RELEASE_CHECKLIST.md) - checklist before full general availability.

## Status

ScopeZero is an early product implementation: a runnable gateway, policy engine, evidence ledger, MCP proxy, SDK, auth layer, deployment scaffold, OpenAPI contract, observability surface, and automated tests.

In production the gateway **fails closed at boot** (`src/startupGate.js`): it refuses to start without an explicit Ed25519 signing private key (`node tools/gen-keys.js`), a non-default ledger secret, a declared egress lockdown (`SCOPEZERO_EGRESS_LOCKDOWN=k8s|docker`), auth required, and dev tokens off. Signing keys rotate via a `kid`-stamped keyset (`SCOPEZERO_SIGNING_PUBLIC_KEYS`). CI runs dependency audit + CycloneDX SBOM + keyless image signing; benchmarks (`BENCHMARKS.md`) gate performance.

Still external before real customer production data: a real IdP (OIDC/JWKS path is implemented and tested), managed Postgres, enterprise SIEM, OTLP collector, secrets vault, a distributed rate limiter, a target registry for image signing, and an external security audit.
