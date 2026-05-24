# ScopeZero Pilot Plan

## Goal

Prove that ScopeZero can safely govern real AI-agent tool calls in a high-stakes enterprise workflow.

## Duration

30 days.

## Pilot Workflow

Recommended first workflow:

> Internal research or diligence agent with read access to approved documents and draft-only messaging.

Why:

- high-value data
- realistic prompt-injection exposure
- clear egress risk
- easy to demonstrate blocking
- low operational risk because outbound actions stay draft-only

## Success Metrics

- 100 percent of pilot agent tool calls routed through ScopeZero
- zero unlogged tool calls
- all blocked actions produce evidence hashes
- SIEM receives ScopeZero events
- security team can replay at least three agent sessions
- no raw confidential egress in blocked scenarios
- median gateway decision latency under 150 ms in pilot environment

## Buyer Questions

- Does this fit under identity, SOC, cloud security, data security, or AI platform ownership?
- Which agent framework should ScopeZero integrate with first?
- Which connector is most urgent?
- Which decision needs human approval?
- What evidence would make legal/compliance trust this?

