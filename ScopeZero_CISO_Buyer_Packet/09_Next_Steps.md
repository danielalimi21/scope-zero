# ScopeZero Evaluation Next Steps

## Recommended First Meeting

Length: 30 minutes

Attendees:

- CISO or deputy CISO
- AI platform owner
- identity or cloud security lead
- SOC or detection engineering lead

Agenda:

1. Current and planned AI-agent workflows.
2. Tools agents can access today.
3. Highest-risk action types.
4. Existing control gaps.
5. ScopeZero proof walkthrough.
6. Pilot selection.

## Discovery Questions

- Which teams are deploying agents that call tools?
- Which tools create the most risk?
- Do agents currently have broad standing access?
- Can security block an agent action before execution?
- Can the SOC see why an agent action was allowed or blocked?
- Which actions would require human approval?
- What evidence would be required for audit or incident response?

## Recommended Pilot Decision

Pick one workflow where an agent can:

- read sensitive or operational data
- write to a business system
- post to communication tools
- create code changes
- trigger cloud or workflow actions

The best pilot workflow has both safe actions and dangerous actions to test.

## Success Definition

At the end of the pilot, the customer should be able to say:

> We routed agent actions through ScopeZero, allowed safe actions, blocked at least one dangerous action before execution, routed high-impact actions to approval, and produced evidence our security team could review.
