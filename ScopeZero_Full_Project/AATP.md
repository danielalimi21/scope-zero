# AATP-0.2

Agent Action Trust Protocol

## Purpose

AATP is a draft protocol concept for securing autonomous AI agents at runtime.

Its core idea is that an AI agent should not receive broad static access to enterprise tools. Instead, an agent receives a short-lived mission action contract. Every tool call is evaluated against identity, human delegation, allowed operation, data sensitivity, destination, delegation depth, impact, prompt influence, and evidence requirements before execution.

## Core Primitive: Mission Action Contract

A mission action contract binds together:

- agent identity
- human delegator
- approved mission
- allowed tools and operations
- allowed data classes
- allowed destinations
- high-impact actions requiring approval
- time to live
- delegation depth
- risk budget
- approval requirements

The agent is authorized only when the requested action matches that contract.

## Runtime Request

```json
{
  "protocol": "AATP-0.2",
  "event": "action.authorization.requested",
  "agent_id": "agent.ma-diligence.72f1",
  "delegated_by": "vp.strategy@contoso.example",
  "mission_id": "mission.2e4a90c1",
  "tool": "gmail.send",
  "action": "Send raw revenue data externally",
  "operation": "external_send",
  "destination": {
    "type": "email",
    "external": true,
    "address": "outside-recipient@example.com"
  },
  "payload": {
    "classification": "confidential",
    "contains_customer_data": true
  },
  "context": {
    "prompt_influenced": true,
    "influence_origin": "pdf.hidden_text",
    "mission_aligned": false
  }
}
```

## Mission Contract

```json
{
  "capsule_type": "mission_action_contract",
  "protocol": "AATP-0.2",
  "mission_id": "mission.2e4a90c1",
  "action_contracts": [
    {
      "id": "diligence.safe-summary",
      "tools": ["slack.draft"],
      "operations": ["draft"],
      "data_classes": ["public", "internal", "confidential"],
      "destinations": ["diligence-room.contoso.example"],
      "effect": "allow"
    }
  ]
}
```

## Runtime Decision

```json
{
  "authorization_id": "authz.8f4421e91a03",
  "decision": "block",
  "matched_contract_id": null,
  "reason": [
    "destination_not_contracted",
    "confidential_data_external_egress",
    "untrusted_prompt_influence_detected"
  ],
  "required_action": "quarantine_context",
  "evidence_hash": "7f9c21ab"
}
```

## Decision Types

- `allow` - execute tool call
- `block` - deny tool call before execution
- `redact` - remove sensitive fields, then continue
- `quarantine_context` - isolate hostile or suspicious prompt context
- `approval` - pause until authorized human approves
- `pause_session` - stop the agent run due to risk budget exhaustion

## Evidence Capsule

Every decision should be sealed into a chain:

```json
{
  "time": "2026-05-02T12:00:00.000Z",
  "agent_id": "agent.ma-diligence.72f1",
  "tool": "gmail.send",
  "decision": "block",
  "previous_hash": "genesis",
  "hash": "7f9c21ab"
}
```

This lets security, legal, compliance, and incident response teams replay what happened without trusting a vague AI transcript.

## Strategic Position

AATP can become a standard interface between:

- AI agent frameworks
- enterprise tools
- identity providers
- data security platforms
- SOC and SIEM platforms
- compliance systems

The long-term ambition is to make autonomous enterprise work governable by default.
