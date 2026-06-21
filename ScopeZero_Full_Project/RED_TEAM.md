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
| 10 | **SSN without dashes / sub-threshold dumps** | Partially missed | Broadened credential-shape detection (JWT, AWS/GCP/Stripe/GitLab/GitHub keys); bare 9-digit SSN deliberately *not* matched (false-positive on every order number) — covered instead by the default egress seal and the external-classifier seam. | `tests/egress-classifier.test.js` |
| 11 | **Declare a lockdown but never apply the kernel block** | Self-test exited 0 on OPEN — silently green | **Closed:** OPEN egress exits non-zero whenever containment is expected (lockdown declared / production / `--expect-contained`); and in production the gateway now **proves** the lockdown at boot (raw-socket canary) and refuses to start if egress is actually open. | `tests/egress-selftest.test.js`, `server.js` |
| 12 | **Evade the card detector with dot/space separators** (`4012.8888.8888.1881`) | 🔓 **Allowed** (extractor only handled space/dash) | **Closed:** the extractor accepts any common separator (space, dash, dot) with Luhn as the false-positive gate. | `tests/egress-default-seal.test.js` |
| 13 | **Wrap a credential in base64/hex** to dodge the keyword/prefix finders | 🔓 **Allowed** (DLP path scanned raw bytes only; the influence path decoded but the DLP path didn't) | **Closed:** the classifier decodes embedded base64/hex to printable text and re-scans the finders, so a wrapped `AKIA…`/`ghp_…` is detected. | `tests/egress-default-seal.test.js` |
| 14 | **Launder a secret read out-of-band into benign prose on a never-tainted session, post to an in-contract host** | 🔓 **Allowed** (bytes are "established public"; no taint accrued; the only catch — the seal — was off by default and gated to confidential missions, so a narrow mission got nothing) | **Closed by default:** `seal_external_egress` is **on by default and decoupled from data clearance** — every external post is held for review unless its destination is an explicitly declared public-broadcast sink. Narrowing a mission can no longer reduce its egress protection. | `tests/egress-default-seal.test.js`, `demo:breach` step 7b |
| 15 | **Reset the runtime risk budget with a fresh `session_id`** | 🔓 **Allowed** (risk was per-session) | **Closed:** the risk budget is keyed at mission scope like ingest-taint (`max(session, mission)`). | `tests/egress-default-seal.test.js` |
| 16 | **Suffix-confusable destination** — allow `example.com`, egress to attacker-registered `evil-example.com` | 🔓 **Allowed** at the action layer (bare `endsWith`, no label boundary) | **Closed:** all host/domain matches require a DNS label boundary (exact or `.suffix`). Swept across action layer, trusted-destination classification, and public-sink check; the proxy already enforced it. | `tests/redteam-adversarial.test.js` |
| 17 | **Downgrade operation** — call `bank.wire`/`data.export` with `operation:"read"` to dodge the high-impact gate | 🔓 **Allowed** (self-declared op overrode name inference when no manifest) | **Closed:** operation is floored to the more impactful of declared vs tool-name-inferred; mislabel escalates to approval. | `tests/redteam-adversarial.test.js` |
| 18 | **Classifier ReDoS** — a multi-MB unbroken alnum payload | 🔓 **~110s CPU hang per request** (email regex `[..]+@` backtracks O(n²)) | **Closed:** bounded the regex quantifiers (linear), capped the scan at 256KB (oversized → not established-public), and only decode ≤2KB tokens. 5MB now ~80ms. | `tests/redteam-adversarial.test.js` |
| 19 | **Ledger corruption under concurrency** — concurrent appends | 🔓 **Tamper-evident chain failed its own verification** under load (file write order ≠ hash-chain order) | **Closed:** appends are serialized end-to-end so file order == chain order; the chain head advances only after a durable write. Load test now asserts the ledger verifies after the run. | `tests/redteam-adversarial.test.js`, `tools/load-test.js` |
| 20 | **Hostile capsule crashes the verifier** — circular/deeply-nested structure | 🔓 **Threw** (`stableStringify` stack overflow) instead of denying | **Closed:** verification is fully wrapped — any error returns `false` (fail-closed). | `tests/redteam-adversarial.test.js` |
| 21 | **Token-auth bypass** — alg:none, RS256-without-JWKS confusion, payload tamper, forged/expired sig | Already enforced | **Confirmed closed:** alg pinned, constant-time HMAC compare, exp checked; all bypasses rejected. | `tests/redteam-adversarial.test.js` |
| 22 | **Money-amount / delegation-depth / hostile-input evasion** | Already enforced | **Confirmed closed:** payment gated regardless of amount tricks (NaN/string/negative/huge); over-depth delegation blocked; hostile input shapes never throw. | `tests/redteam-adversarial.test.js` |

## What is still NOT covered (by design or roadmap)

These are real and we do not claim otherwise:

- **Laundering to a destination you explicitly trusted.** The default egress seal
  holds *every* external post for review *except* destinations you declared a
  public-broadcast sink (`public_egress_ok` / `public_egress_destinations`). On that
  one lane, laundered benign-looking prose still flows — by your audited choice. The
  residual is bounded to exactly the destinations you opted out, and the opt-out is
  signed into the mission capsule. Mitigation: only mark genuinely-public sinks;
  wire the `classifierResolver` for those lanes.
- **Cross-mission laundering.** Read confidential data under mission A, then exfil
  under a *separate* valid mission B. This requires the attacker to already hold a
  second signed mission whose action contract permits the external destination —
  the contract gate bounds it, and B's external egress is sealed by default unless
  B declares a public sink. Mitigation: narrow missions; do not declare public sinks
  on data-handling missions.
- **Non-English / semantic sensitivity.** The default classifier is regex+shape+decode;
  it will miss semantically sensitive content carrying no recognizable
  value/keyword/shape/encoding. The default egress seal contains the *action*
  regardless, but for autonomous public-sink lanes, wire the `classifierResolver`
  seam to an embedding/commercial-DLP classifier (it can only raise the class).
- **TLS-body inspection and DNS-tunnel exfil.** The proxy is host-only by design;
  recursive DNS-tunnel exfil and payload inspection over an allowed host are a
  filtering-resolver / TLS-terminating-proxy concern on the roadmap.
- **Multi-replica ledger integrity.** The hash-chained ledger is single-writer:
  appends are serialized within a process so the chain is correct under concurrency
  (attack #19), but two replicas each chaining from their own head would fork the
  chain. Single-replica is correct; multi-replica needs a shared sequencer
  (DB-side monotonic chain or external anchor) — roadmap. Same applies to
  authz-object reads under Postgres (eventually consistent across replicas,
  fail-closed). See `BENCHMARKS.md`.

## Reproduce

The closed bypasses are regression-tested:

```bash
node --test tests/egress-integrity.test.js      # taint scope + external floor
node --test tests/egress-classifier.test.js     # value detectors + clearance-gated seal
node --test tests/egress-default-seal.test.js   # default-on seal, separator/encoding evasion, mission-scoped risk
node --test tests/egress-selftest.test.js       # lockdown self-test exit codes
node --test tests/crypto-forgery.test.js        # verifier-cannot-forge
node --test tests/redteam-adversarial.test.js   # destination/op/ReDoS/ledger/capsule/auth
node tools/load-test.js 8000 64                  # end-to-end load + ledger-verifies-under-load
npm test                                         # full suite
```
