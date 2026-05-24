# ScopeZero General Availability Checklist

## Product

- [ ] Production admin UI for policies, proposals, approvals, and evidence.
- [ ] Connector marketplace or connector manifest registry.
- [ ] At least two real production connectors.
- [ ] Customer tenant onboarding workflow.
- [ ] OpenAPI docs hosted with examples.
- [ ] SDK package published privately or publicly.

## Security

- [ ] Real enterprise IdP integration tested.
- [ ] SAML-to-OIDC bridge documented.
- [ ] Vault/KMS secret provider.
- [ ] Managed Postgres deployment.
- [ ] Append-only ledger storage.
- [ ] Distributed rate limiting.
- [ ] mTLS or service mesh policy for connector traffic.
- [ ] SBOM generated.
- [ ] Container image signing.
- [ ] Dependency scanning.
- [ ] External penetration test.

## Operations

- [ ] Hosted environment.
- [ ] CI/CD pipeline.
- [ ] Rollback plan.
- [ ] Backup and restore test.
- [ ] Monitoring dashboards.
- [ ] On-call process.
- [ ] Incident response process.
- [ ] Customer support process.

## Legal And Compliance

- [ ] Terms of service.
- [ ] Privacy policy.
- [ ] DPA template.
- [ ] Security whitepaper.
- [ ] SOC2 readiness plan.
- [ ] Responsible disclosure policy.

## Sales

- [ ] Pricing approved.
- [ ] Pilot agreement template.
- [ ] One-page product brief.
- [ ] 10-slide deck.
- [ ] Technical FAQ.
- [ ] Competitive positioning.
- [ ] Reference architecture.

## GA Decision

Do not call the product generally available until:

- one paid pilot succeeds
- one real connector runs in controlled customer environment
- evidence export is accepted by a security team
- production deployment has passed external review
