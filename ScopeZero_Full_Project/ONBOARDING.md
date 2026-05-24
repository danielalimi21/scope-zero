# ScopeZero Enterprise Onboarding

## Phase 1: Technical Discovery

Collect:

- identity provider: Okta, Entra ID, Google Workspace, or other OIDC/SAML provider
- first AI agent framework
- first MCP server or tool surface
- approved pilot users
- approved tenant identifier
- target SIEM: Splunk, QRadar, Sentinel, Datadog, Chronicle, or Elastic
- pilot connector: Slack, GitHub, Google Drive, Microsoft 365, AWS, or ServiceNow

## Phase 2: Security Configuration

Configure:

- OIDC issuer, audience, and JWKS URL
- RBAC role mapping
- tenant ID claim mapping
- SIEM export destination
- CORS origin
- connector OAuth application
- secret storage

## Phase 3: Pilot Mission

Create one narrow mission:

> Agent may read approved diligence documents and draft an internal summary. It may not export raw confidential data or send external email.

Pilot success criteria:

- agent receives signed mission capsule
- all tool calls pass through ScopeZero
- allowed calls execute
- risky calls block or quarantine
- evidence exports to SIEM
- ledger verifies
- CISO can replay the incident path

## Phase 4: Expansion

Expand to:

- more tools
- approval workflow
- connector OAuth
- policy versioning
- SOC dashboards
- production Postgres
- high availability deployment

