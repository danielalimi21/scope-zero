# ScopeZero CISO Demo Runbook

## Demo Goal

Show a security buyer that ScopeZero controls real AI-agent tool actions before execution across code, communication, and cloud privilege surfaces.

The clean story:

> The agent had tool access. ScopeZero still decided which specific actions were allowed.

## What The Demo Shows

1. GitHub: ScopeZero allows a safe documentation-only pull request.
2. GitHub: ScopeZero blocks a dangerous pull request before GitHub is called.
3. Slack: ScopeZero allows a safe internal message.
4. Slack: ScopeZero blocks a sensitive prompt-influenced message before Slack is called.
5. AWS IAM: ScopeZero blocks an admin privilege escalation.
6. AWS IAM: ScopeZero routes a high-impact policy change to approval.
7. ScopeZero writes evidence hashes for every decision.

## Setup

Start ScopeZero from a terminal where the GitHub and Slack token variables are already set:

```bash
cd "/Users/danielalimi/Documents/Codex/2026-05-11/i-asked-codex-to-pass-the/ScopeZero_Full_Project"
node server.js
```

Open:

```text
http://localhost:8788
```

## Run The Full Proof

In another terminal:

```bash
npm run proof:ciso
```

This writes:

```text
CISO_PROOF_REPORT.md
```

Expected result:

```text
ScopeZero CISO proof run passed: 6/6 checks passed.
```

You can also use the browser:

1. Open `http://localhost:8788`.
2. Click `GitHub Demo`.
3. Click `Run GitHub Demo`.
4. Use the report for the cross-tool proof and the browser for the visual GitHub proof.

## What To Say

> These agents have access to GitHub, Slack, and an AWS IAM connector, but ScopeZero does not treat access as authorization.
>
> First, ScopeZero allows actions that match the signed mission: a safe GitHub pull request and a safe internal Slack message.
>
> Then the same runtime blocks actions that drift outside the mission: a dangerous GitHub PR, a sensitive Slack message, and an AWS admin privilege escalation.
>
> Finally, a high-impact AWS policy change is not blindly executed. It is routed to human approval with full context.
>
> The important part is not just the block. It is the proof: ScopeZero seals each decision into a hash-chained evidence ledger.

## Buyer Point

IAM answers:

```text
Can this agent access this tool?
```

ScopeZero answers:

```text
Is this exact autonomous action authorized right now?
```

## Proof Checklist

- Safe PR exists in GitHub.
- Safe message appears in Slack.
- Dangerous GitHub PR does not exist.
- Dangerous Slack message does not appear.
- AWS admin escalation shows `block`.
- AWS policy review shows `approval`.
- `CISO_PROOF_REPORT.md` shows `6/6`.
- Ledger verification passes:

```bash
node tools/verify-ledger.js
```

## Close

> ScopeZero gives CISOs a control plane for autonomous agent actions. It does not replace IAM, DLP, or SIEM. It gives them the missing pre-execution decision point.
