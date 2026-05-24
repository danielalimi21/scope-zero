# ScopeZero

ScopeZero is a vendor-neutral action authorization gateway for autonomous AI-agent tool calls.

IAM decides whether an agent has access. ScopeZero decides whether the exact autonomous action is authorized before execution.

## Repository Contents

- `ScopeZero_Full_Project/` - runtime gateway, policy engine, connectors, SDK, tests, docs, examples, and deployment manifests.
- `ScopeZero_CISO_Buyer_Packet/` - professional buyer packet with an interactive demo in `demo/index.html`.
- `ScopeZero_Founder_Sales_Playbook.md` - internal founder sales strategy and outreach guidance.

## Run The Product Demo

Open:

```text
ScopeZero_CISO_Buyer_Packet/demo/index.html
```

Or run the gateway:

```bash
cd ScopeZero_Full_Project
node server.js --port=8788
```

Then open:

```text
http://localhost:8788
```

## Verify

```bash
cd ScopeZero_Full_Project
npm run check
npm test
```

## Positioning

ScopeZero sits between autonomous agents and enterprise tools. Every requested tool call is checked against mission, policy, data, destination, risk, and approval rules before GitHub, Slack, AWS, SaaS, APIs, or MCP tools are allowed to run.
