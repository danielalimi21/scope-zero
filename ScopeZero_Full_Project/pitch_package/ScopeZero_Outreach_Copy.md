# ScopeZero Outreach Copy

## Short Email

Subject: Action authorization for AI-agent tool calls

Hi [Name],

I am building ScopeZero, a vendor-neutral action authorization gateway for autonomous AI-agent tool calls.

The thesis is simple: AI agents are becoming delegated enterprise actors. Existing IAM can tell whether an agent has access, but not whether a specific autonomous action matches the approved mission contract.

Our core line is: the agent was authorized, the action was not.

I built a working alpha that shows an agent manipulated by a malicious document into attempting confidential data egress. ScopeZero rejects actions outside the mission contract at runtime and generates cryptographic evidence.

Would you be open to 20 minutes of blunt feedback on whether this maps to a real enterprise security problem?

Best,
[Your Name]

## Technical Buyer Email

Subject: MCP / agent action authorization

Hi [Name],

I am working on ScopeZero, a runtime authorization gateway for AI agents and MCP/tool-call workflows.

It sits between agents and tools, evaluates every tool call against agent identity, human delegation, signed mission action contract, data sensitivity, destination, prompt influence, and risk budget, then returns allow/block/redact/quarantine/approval decisions.

The first wedge is securing one internal agent workflow and exporting evidence to the security team.

I would value a blunt technical reaction:

- Are your teams deploying agents that call tools/APIs/MCP servers?
- Can security currently see and govern those tool calls?
- Would runtime mission-scoped action authorization be useful?

Would you be open to a 20-minute call?

Best,
[Your Name]

## LinkedIn Message

Hi [Name], I am building ScopeZero: mission-scoped action authorization for AI-agent tool calls. The core thesis is that IAM answers access, but agent security also needs runtime action control: "the agent was authorized, the action was not." I have a working alpha and would value 20 minutes of blunt feedback from someone thinking about enterprise AI security.

## Follow-Up 1

Hi [Name],

Quick follow-up. The reason I thought of you: ScopeZero is focused on the security gap that appears when AI agents move from chat to tool-using workflows.

The working alpha shows a prompt-injected agent attempting data egress, then being blocked at runtime with evidence generated for the SOC/compliance team.

Worth a quick look?

## Follow-Up 2

Hi [Name],

Closing the loop. If agent action authorization is not on your roadmap, no worries. If it is, I would be grateful for even a quick "wrong person / talk to X" redirect.

Best,
[Your Name]
