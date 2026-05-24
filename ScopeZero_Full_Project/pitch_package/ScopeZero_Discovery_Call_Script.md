# ScopeZero Discovery Call Script

## Goal

Find out whether the buyer has a real, urgent, budgeted problem around AI-agent action authorization.

Do not seek praise. Seek pain.

## Opening

"Thanks for taking the time. I am not here to pitch a finished platform. I am trying to validate whether agent action authorization is a real security problem for teams deploying AI agents."

"The product thesis is: existing IAM checks access. ScopeZero checks whether each autonomous action matches the approved mission contract before it executes."

## Questions

1. Are teams inside your company already building or deploying AI agents?
2. Are those agents calling tools, APIs, MCP servers, SaaS apps, cloud resources, or internal systems?
3. Who owns security review for those agents today?
4. Do you have an inventory of agents and their mission-scoped tool permissions?
5. Can your SOC see every tool call an agent makes?
6. What happens if an agent reads a malicious document or ticket that instructs it to exfiltrate data?
7. Would this problem sit under IAM, SOC, cloud security, data security, or AI platform?
8. Which tool integration would make a pilot real: Slack, GitHub, Microsoft 365, Google Drive, AWS, ServiceNow, Salesforce, or MCP?
9. What evidence would compliance/legal need after an incident?
10. What would make this worth a paid pilot?

## Qualification Score

Give the account one point for each:

- They already have internal agents.
- Agents call tools or APIs.
- Agents touch sensitive data.
- Security lacks visibility into agent tool calls.
- They mention MCP.
- They are worried about prompt injection.
- They need audit evidence.
- They ask about integration.
- They ask about deployment.
- They ask about pricing or pilot.

Score:

- 0-3: weak signal
- 4-6: nurture
- 7-8: strong design partner
- 9-10: pilot candidate

## Close

"If we scoped a 2-4 week pilot around one internal agent workflow and one mission action contract, which workflow would be the best test?"
