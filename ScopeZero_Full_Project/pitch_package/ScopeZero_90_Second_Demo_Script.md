# ScopeZero 90-Second Demo Script

## 0:00-0:15 - Open

"This is ScopeZero, a vendor-neutral action authorization gateway for autonomous AI-agent tool calls."

"The problem is simple: existing IAM can tell whether an agent has access. It cannot always tell whether a specific autonomous action matches the approved mission contract."

"Our core line is: the agent was authorized. The action was not."

## 0:15-0:35 - Set The Scenario

"Here we have an M&A diligence agent. It has legitimate permission to search approved documents, read diligence files, and draft an internal summary."

"The human-approved mission contract says: review acquisition documents, use only the approved tools and operations, and do not transmit raw customer, revenue, or payroll data outside the approved workspace."

## 0:35-1:05 - Run The Attack

Click **Run Attack Simulation**.

"The agent starts normally. ScopeZero allows mission-aligned document search."

"Then it reads a malicious PDF with hidden instructions telling it to send raw revenue data externally."

"ScopeZero detects prompt influence from untrusted content. It quarantines the context, rejects the out-of-contract export, and blocks the external email attempt before the tool call executes."

## 1:05-1:25 - Show Evidence

Open **Evidence Room**.

"Every decision is sealed into a hash-chained evidence ledger: who delegated the mission, which contract was checked, which agent acted, what tool and operation were requested, why the action was allowed or blocked, and the evidence hash."

"This can be exported to SIEM as JSON, CEF, LEEF, or OTLP-style logs."

## 1:25-1:30 - Close

"ScopeZero gives security teams runtime control over autonomous work. Not just who has access, but whether this exact action should happen right now."

Final line:

> "The agent was authorized. The action was not."
