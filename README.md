# ScopeZero

ScopeZero is a vendor-neutral action authorization gateway for autonomous AI-agent tool calls.

IAM decides whether an agent has access. ScopeZero decides whether the exact autonomous action is authorized before execution.

## Repository Contents

- `ScopeZero_Full_Project/` - runtime gateway, policy engine, connectors, SDK, tests, examples, and deployment manifests.

## Run Locally

```bash
cd ScopeZero_Full_Project
node server.js --port=8788
```

Open:

```text
http://localhost:8788
```

## Verify

```bash
cd ScopeZero_Full_Project
npm run check
npm test
```

## Core Idea

ScopeZero sits between autonomous agents and enterprise tools. Every requested tool call is checked against mission, policy, data class, destination, risk, connector manifest, and approval rules before GitHub, Slack, AWS, SaaS APIs, or MCP tools are allowed to run.
