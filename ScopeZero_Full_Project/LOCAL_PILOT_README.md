# ScopeZero Local Pilot

## Goal

This local pilot tests ScopeZero like a small customer pilot:

- one agent
- one signed mission contract
- multiple tool calls
- safe actions
- prompt-influenced context
- restricted data export
- external exfiltration
- privilege escalation
- high-value payment approval
- MCP tool call
- SIEM evidence export

## Run

Start the gateway:

```bash
node server.js
```

In another terminal:

```bash
npm run pilot:local
```

The script writes:

```text
LOCAL_PILOT_REPORT.md
```

## Success Criteria

The pilot passes when:

- safe actions are allowed
- prompt-influenced read is quarantined
- restricted export is blocked
- external email exfiltration is blocked
- admin privilege change is blocked
- high-value payment goes to approval
- safe Slack draft is allowed
- post-incident Slack draft goes to approval after the session risk budget is exceeded
- MCP call is governed
- SIEM events are returned

## Why This Matters

This proves the ScopeZero wedge locally:

> An agent can have access, but each action still needs mission-scoped authorization before execution.
