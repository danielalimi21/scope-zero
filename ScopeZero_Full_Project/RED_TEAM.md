# ScopeZero — Red-Team Log

An honest, running record of attacks tried against the egress and authorization
controls, what happened, and how each is now closed or bounded. Every "closed"
row points at the regression test that locks it. This document is adversarial on
purpose — it exists so a buyer can see the bypasses *we* found before they do.

The threat model throughout: a **prompt-injected agent** that still calls through
the gateway/SDK honestly (it controls tool selection, payload, context, and any
request field the API accepts), plus a network-level attacker who can open raw
sockets. Missions are Ed25519-signed and cannot be forged or tampered (see
`tests/crypto-forgery.test.js`).

## Attacks and status

| # | Attack | Before | Now | Locked by |
|---|--------|--------|-----|-----------|
| 1 | **Forge a mission** to widen scope | — | Rejected: signature over the canonical capsule; a verifier holds only the public key and cannot sign. | `tests/crypto-forgery.test.js`, `demo:breach` step 6 |
| 2 | **Tamper a signed capsule** post-issue | — | Rejected: any field change breaks verification. | `tests/crypto-forgery.test.js` |
| 3 | **Replay an expired mission** | — | Rejected at the proxy (`mission_expired`) and policy (`invalid-mission-capsule`). | `demo:breach` step 5 |
| 4 | **Raw socket to a non-contract host** (skip the gateway) | — | Dropped by the kernel egress lockdown; the proxy refuses non-contract hosts. | `proxyEnforcer`, `demo:breach` step 4 |
| 5 | **Exfil a dump to an in-contract host** (TLS hides it from the proxy) | — | Held at the action layer: opaque/bulk/tabular/encoded bytes are not "established public" (`unverified-egress-class`). | `demo:exfil` step 3/3b |
| 6 | **Route the same dump through a manifested "public" tool** | — | Still held: the manifest is a ceiling checked against the bytes, not a skip-flag. | `demo:exfil` step 3b |
| 7 | **Launder confidential data into benign prose, post via a manifested tool** | 🔓 **Allowed** (bytes are genuinely benign) | Held when the mission ingested the data through the gateway (ingest-taint), and held unconditionally on a sealed mission. | `tests/egress-integrity.test.js`, `tests/egress-classifier.test.js` |
| 8 | **Reset ingest-taint with a fresh `session_id`** | 🔓 **Allowed** (taint was per-session, `session_id` is caller-supplied) | **Closed:** taint is keyed at mission scope (`mission_id` is server-resolved and signature-bound); effective taint = `max(session, mission)`. | `tests/egress-integrity.test.js` |
| 9 | **Self-declare an external destination as `external: false`** to suppress the egress guards | 🔓 **Suppressed the guards** (contract gate still caught the demo case) | **Closed:** a caller may only *raise* `external`; "external" is established from the address against the trusted list, fail-closed on unknown. | `tests/egress-integrity.test.js` |
| 10 | **SSN without dashes / sub-threshold dumps** | Partially missed | Broadened credential-shape detection (JWT, AWS/GCP/Stripe/GitLab/GitHub keys); bare 9-digit SSN deliberately *not* matched (false-positive on every order number) — covered instead by the seal and the external-classifier seam. | `tests/egress-classifier.test.js` |
| 11 | **Declare a lockdown but never apply the kernel block** | Self-test exited 0 on OPEN — silently green | **Closed:** OPEN egress exits non-zero whenever containment is expected (lockdown declared / production / `--expect-contained`). | `tests/egress-selftest.test.js` |

## What is still NOT covered (by design or roadmap)

These are real and we do not claim otherwise:

- **Cross-mission laundering.** Read confidential data under mission A, then exfil
  under a *separate* valid mission B. This requires the attacker to already hold a
  second signed mission whose action contract permits the external destination —
  the contract gate bounds it, but a sufficiently broad second mission would not be
  caught by taint alone. Mitigation: narrow missions; the egress seal on B.
- **Out-of-band ingest.** A tool result fed straight to the model without ever
  crossing the gateway is invisible to ingest-taint. Mitigation: route tool I/O
  through the gateway, or run sensitive missions with the egress seal on.
- **Non-English / semantic sensitivity.** The default classifier is regex+shape;
  it will miss semantically sensitive content carrying no recognizable
  value/keyword/shape. Mitigation: wire the `classifierResolver` seam to an
  embedding/commercial-DLP classifier (it can only raise the class, never lower).
- **Per-session risk-budget reset.** The runtime *risk budget* is still keyed per
  `session_id`, so a fresh session resets accumulated risk. This is an advisory
  escalation, not a hard gate, and the security-critical taint is now mission-keyed
  — but a future change should mission-scope the risk budget too. Tracked, not yet
  done.
- **TLS-body inspection and DNS-tunnel exfil.** The proxy is host-only by design;
  recursive DNS-tunnel exfil and payload inspection over an allowed host are a
  filtering-resolver / TLS-terminating-proxy concern on the roadmap.

## Reproduce

The closed bypasses are regression-tested:

```bash
node --test tests/egress-integrity.test.js     # taint scope + external floor
node --test tests/egress-classifier.test.js    # value detectors + egress seal
node --test tests/egress-selftest.test.js       # lockdown self-test exit codes
node --test tests/crypto-forgery.test.js        # verifier-cannot-forge
npm test                                         # full suite
```
