# ScopeZero

**ScopeZero is a vendor-neutral action authorization gateway for autonomous AI-agent tool calls.**

It sits between AI agents and the tools they use. Before an agent sends email, exports data, opens a ticket, touches cloud permissions, calls an MCP tool, or moves information across a boundary, ScopeZero asks one question:

> Is this specific action authorized by the agent's approved mission?

The core line is simple:

> The agent was authorized. The action was not.

## Why It Matters

Enterprises are moving from chatbots to autonomous agents that can reason, browse, retrieve documents, call APIs, write code, modify cloud settings, use SaaS tools, and trigger business workflows.

Existing controls answer pieces of the problem:

- IAM asks whether an identity has access.
- DLP asks whether data looks sensitive.
- EDR/SIEM asks what happened after execution.
- AI safety tools inspect prompts and model behavior.

ScopeZero is the missing runtime control: **pre-execution authorization for every agent tool call**, based on identity, human delegation, mission contract, tool, operation, data class, destination, prompt influence, risk budget, and approval policy.

## What Is Implemented

This repository contains a runnable product core:

- Live Node.js gateway on `http://localhost:8788`.
- Browser command center and attack simulation.
- Agent SDK.
- End-to-end malicious diligence agent example.
- Mission action contracts signed into short-lived capsules.
- Pre-execution action authorization API.
- Runtime policy engine with allow, block, redact, quarantine, approval, and pause decisions.
- Sensitive data classifier and prompt-influence detector.
- Human approval broker.
- Hash-chained evidence ledger with verification tooling.
- SIEM exports for JSON, CEF, LEEF, and OTLP-style logs.
- MCP JSON-RPC proxy for guarded `tools/call`.
- Connector registry for SaaS, cloud, and enterprise-tool boundaries.
- Live GitHub draft pull request connector with safe local fallback.
- Live Slack demo-channel connector with safe local fallback.
- AWS IAM safe simulation connector for cloud privilege-change demos.
- OIDC/JWKS validation path, local signed bearer tokens, RBAC, API key support, and tenant filtering.
- Optional managed Postgres store for production-style multi-replica state.
- Encrypted local secret references for connector credentials.
- Policy proposal, approval, and version history APIs.
- OpenTelemetry trace capture and optional OTLP export.
- Prometheus metrics endpoint.
- Docker and Kubernetes deployment scaffolding.
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

In another terminal:

```bash
npm run check
node tools/smoke-test.js
node examples/malicious-diligence-agent.js
node tools/verify-ledger.js
node tools/config-check.js
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
- [GA_RELEASE_CHECKLIST.md](GA_RELEASE_CHECKLIST.md) - checklist before full general availability.

## Status

ScopeZero is an early product implementation: a runnable gateway, policy engine, evidence ledger, MCP proxy, SDK, auth layer, deployment scaffold, OpenAPI contract, observability surface, and automated tests.

Before real customer production data, connect a real IdP, managed Postgres, enterprise SIEM, OTLP collector, secrets vault, distributed rate limiter, image signing, SBOM/dependency scanning, and external security testing.
