# ScopeZero

> Archived. A full agent-authorization platform (Authority · Gate · Containment · Proof) that got commoditized as a whole. The one defensible sliver — session-taint egress — was extracted as [taintgate](https://github.com/danielalimi21/taintgate). This repo is now portfolio / research, not a product in flight.

---

## Quick Reference

- **Status:** dead as a business, kept as portfolio/research. No sprints, no active work. Last commit already framed it as portfolio and cross-linked taintgate.
- **What it was:** vendor-neutral pre-execution authorization gateway + embeddable SDK for AI agents taking irreversible actions. Ed25519-signed authority, fail-closed gate, kernel-enforced egress containment, hash-chained proof ledger.
- **Scale built:** ~24 strategy/arch docs, 227–259 tests, k8s/Docker lockdown, Postgres+RLS, compliance matrix, MCP trust registry. Real, complete, hardened.
- **Repo:** https://github.com/danielalimi21/scope-zero (public). Code lives under `ScopeZero_Full_Project/`.
- **Why archived:** each layer is individually commodity; only the anti-laundering session-taint egress catch was genuinely uncovered — and that's now taintgate. See `POST_MORTEM.md`.

---

## Brain Map

- `project-brain/brain/SUMMARY.md` — what ScopeZero was, who for, why it was killed, current status
- `project-brain/brain/POST_MORTEM.md` — what got built, why the platform commoditized, what taintgate carried out
- `project-brain/brain/SALVAGE.md` — the "anything else worth extracting?" pass; each remaining sliver judged like taintgate was

---

## What Matters Here

1. **This is an archive, not a codebase to extend.** Read to mine ideas, not to add features. If a salvage candidate proves worth building, it becomes its *own* new repo — the taintgate pattern — never a ScopeZero revival. See `SALVAGE.md`.
2. **The lesson is the asset.** The value left here is (a) the extractable slivers in `SALVAGE.md` and (b) the post-mortem on why a well-built platform of commodity parts isn't defensible. See `POST_MORTEM.md`.
3. **Honesty carried over to taintgate.** ScopeZero's `RED_TEAM.md` (22 attacks, self-published bypasses) and honest-scope framing are the DNA taintgate inherited. That posture is the reusable thing.

---

## Project-Specific Rules

- Treat as **read-only history.** Don't propose features, roadmaps, or "revival" work for ScopeZero itself — the decision to archive is settled.
- When mining a sliver, judge it on the taintgate bar: **defensible, uncovered, embeddable, honestly bounded.** If it fails that bar, say so plainly in `SALVAGE.md` rather than dressing it up.
- Actual code lives one level down in `ScopeZero_Full_Project/` — point there, don't duplicate it into the brain.

---

## Key Files to Start From

- `project-brain/brain/SUMMARY.md` — start here
- `project-brain/brain/SALVAGE.md` — the reason this brain exists: what else, if anything, is worth pulling out
- `ScopeZero_Full_Project/REPOSITIONING.md` — the last pivot (enterprise gateway → dev-embed SDK for irreversible actions)
- `ScopeZero_Full_Project/RED_TEAM.md` — 22 attacks with status; the honesty template taintgate inherited
- `ScopeZero_Full_Project/ARCHITECTURE.md` — the full four-layer engine, component by component
