# ScopeZero Landing Site Pitch Notes

Use these as speaking notes while you record or present the landing site. Do not read the page word for word. The goal is to explain the story behind each section.

## 1. Hero: Action Authorization For AI Agents

ScopeZero is a security control for AI agents that can take real actions, not just chat. It sits between the agent backend and the tools the agent wants to use, and it decides whether each action should be allowed before it happens.

## 2. Live Authorization Stream

This shows the core idea in one glance: safe actions can continue, risky actions can be blocked, and high-impact actions can be sent to approval. ScopeZero is not trying to stop agents from working; it is making their work governable.

## 3. The Shift: AI Agents Are Becoming Backend Actors

The risk is changing because agents are starting to behave like automated employees or service accounts. They can open code changes, send messages, move data, call APIs, and change cloud settings, so security teams need action-level control.

## 4. Three Security Gaps

Traditional tools were built for humans, apps, and identities, not autonomous decision-makers. IAM says what the agent can access, SIEM shows what happened afterward, and prompt tools inspect language, but none of them fully answer whether this exact action should execute right now.

## 5. Where ScopeZero Sits

ScopeZero belongs in the backend path, not on employee laptops. Before the company service executes an agent tool call, it asks ScopeZero for a decision, and only approved actions continue to GitHub, Slack, AWS, SaaS tools, APIs, or MCP tools.

## 6. Backend Integration Pattern

The integration is simple: the backend sends ScopeZero the agent, mission, tool, method, data class, and destination. ScopeZero returns allow, block, approval, quarantine, redact, or pause, and the backend enforces that answer before calling the real tool.

## 7. Deterministic Decision Engine

ScopeZero does not need an LLM to “think.” It uses a deterministic authorization engine that checks mission scope, method, resource, data sensitivity, destination, prompt influence, privilege impact, risk, and policy rules.

## 8. Decision Inputs

This is the nerdy part: ScopeZero turns a messy agent action into a structured action descriptor. Once the action is normalized, the policy engine can consistently decide whether it matches the approved mission and security boundaries.

## 9. Proof Scenarios: Safe Work Continues

The GitHub example shows the positive side: if an agent is doing normal work inside its approved mission, ScopeZero allows it. The product is not a kill switch; it is a precise authorization layer.

## 10. Proof Scenarios: Dangerous Work Stops

The Slack example shows the business value clearly: the same agent may be allowed to work, but not allowed to send customer-confidential data to an external destination. ScopeZero blocks the action before Slack receives it.

## 11. Proof Scenarios: Human Approval

The AWS example shows that some actions are not simply good or bad. A cloud privilege change might be legitimate, but because it has high impact, ScopeZero routes it to human approval instead of letting the agent execute automatically.

## 12. Proof Scenarios: Prompt Influence

The MCP example shows why this matters for modern agents. If an agent reads untrusted content that tries to manipulate the next tool call, ScopeZero can quarantine the context before the agent acts on poisoned instructions.

## 13. Why ScopeZero Is Different

ScopeZero is not replacing IAM, DLP, SIEM, or prompt guardrails. Its position is different: it controls the autonomous action itself, before execution, which is the missing layer when agents start operating production tools.

## 14. Product Surface

This section shows ScopeZero as a real product platform, not just a demo. The important pieces are the gateway, mission contracts, policy engine, approval broker, evidence ledger, and connector layer.

## 15. Final Section: The Control Layer

The closing message is that enterprises will not be able to safely scale AI agents with trust alone. ScopeZero gives them a control layer that lets agents work across real systems without giving them unchecked authority.

## Short Recording Flow

Open with the problem: agents are moving from chat to action.

Then explain the control point: ScopeZero sits before tool execution.

Then explain the engine: every action becomes a structured authorization decision.

Then show the proof: allow safe GitHub work, block risky Slack data movement, require approval for AWS admin changes, and quarantine prompt-influenced MCP actions.

Close with the category: ScopeZero is the pre-execution control layer for autonomous enterprise agents.
