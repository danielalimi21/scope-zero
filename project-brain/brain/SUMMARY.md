# ScopeZero — Summary

## What This Project Was

ScopeZero was an authorization-and-containment system for AI agents that take real
actions. The pitch, in its final form: *the embeddable trust layer companies drop in so
their agents can move money, change cloud infrastructure, or send things outside without
ever exceeding what a human authorized — with a verifiable receipt for every action.*

Four layers (`REPOSITIONING.md`, `ARCHITECTURE.md`):

1. **Authority** — a human signs a scoped, time-boxed Ed25519 grant the agent can hold
   but cannot widen.
2. **Gate** — every attempted action is matched against the grant + policy before it
   runs; fail-closed. Irreversible actions (payment, privilege change, external send)
   are a non-overridable hard gate.
3. **Containment** — a kernel-enforced egress boundary (k8s NetworkPolicy or Docker
   internal network) so an injected agent that skips the SDK still physically can't reach
   an off-contract destination.
4. **Proof** — a hash-chained (HMAC-keyed) ledger; every decision is independently
   verifiable, including by the builder's own customer.

It was real and complete: 227–259 tests, Postgres with row-level security, a
multi-replica shared-sequencer ledger, admission webhooks, an MCP trust registry with
CVE-decay, a compliance matrix (SOC2 / EU AI Act / HIPAA), and a self-published
red-team log of 22 attacks. Not a slide deck — an executable product.

## Who It Was For

The final positioning targeted **builders of action-taking agents** (cloud/devops
copilots, fintech-ops, RPA-killers) via dev-led embed — a pivot away from the original
top-down enterprise-CISO buyer. See `POST_MORTEM.md` for why even that pivot didn't save
it.

## Why It Was Killed

Not a code failure — a **defensibility** failure. Each of the four layers is,
individually, an assembly of known parts: signed capability grants (macaroons / biscuit
territory), kernel egress rules (standard k8s primitives), a hash-chained ledger
(transparency-log territory), human co-sign (maker-checker). Well-built, but commodity.
The one genuinely *uncovered* thing — catching confidential data laundered into benign
prose and posted to an *allowed* host via session taint — was a single control, not a
platform. That control was extracted as **taintgate**. See `POST_MORTEM.md`.

## Current State

- **Archived.** Public repo, framed as portfolio/research (last commit:
  *"frame repo as portfolio/research, cross-link taintgate"*).
- No active development, no roadmap, no sprints. This brain has no `sprints/` directory
  on purpose.
- Living forward: `taintgate` (the extracted sliver) and the salvage candidates in
  `SALVAGE.md`.

## Why This Brain Exists

Two reasons: (1) capture the **post-mortem** so the "platform of commodity parts" trap
isn't repeated, and (2) run one honest **salvage** pass — is there a *second* taintgate
still buried in here? See `SALVAGE.md` for the verdict.
