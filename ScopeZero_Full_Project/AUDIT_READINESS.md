# ScopeZero — Security & Audit Readiness

What a technical buyer or auditor asks, answered honestly. This is the interim
posture *before* a paid external audit; it documents what is automated, what is
tested, what is bounded, and what is deliberately deferred.

## Automated security (runs in CI on every push)

| Control | Tool | Status |
| --- | --- | --- |
| SAST (deep) | CodeQL `security-extended` | ✅ in CI (`.github/workflows/scopezero-ci.yml`) |
| SAST (rulesets) | Semgrep `p/security-audit`, `p/owasp-top-ten`, `p/javascript`, `p/secrets` | ✅ in CI |
| Dependency vulns | `npm audit --omit=dev --audit-level=high` | ✅ in CI, **0 vulnerabilities** |
| SBOM | CycloneDX | ✅ in CI (artifact) |
| Image signing | cosign keyless (OIDC) | ⚙️ scaffolded; enable on registry wire-up |
| Secret hygiene | Semgrep `p/secrets` | ✅ in CI |

## Testing & adversarial coverage

- **278 automated tests**, green, run in CI (`npm test`).
- **Adversarial red-team suite** (`tests/redteam-adversarial.test.js`): destination
  label-boundary bypasses, capsule tamper/forgery, self-declared data-class and
  operation downgrade, ingest-taint reset, token-auth bypass (alg confusion /
  tamper / expiry), classifier ReDoS, **ledger integrity under concurrency**,
  hostile-input robustness, prototype pollution, money/delegation evasion.
- **End-to-end load gate** (`tools/load-test.js`, in CI): real HTTP, asserts
  0 errors, every dangerous action contained, and the **tamper-evident ledger
  verifies after concurrent load**.
- **Honest adversarial log**: [RED_TEAM.md](RED_TEAM.md) — every attack tried,
  before/after, and the test that locks it. Includes what is *not* covered.

## Threat model

A prompt-injected agent that still calls through the gateway/SDK honestly (it
controls tool, payload, context, and any request field), plus a network attacker
opening raw sockets. Missions are Ed25519-signed; a verifier holds only the
public key and cannot forge. The real controls are the deterministic contract
gates + kernel egress containment + human co-sign; the content classifier and
prompt-influence heuristics are advisory (they only raise risk / route to review,
never stand alone as the block). See [SECURITY_REVIEW.md](SECURITY_REVIEW.md).

## Hardening posture (boot-time, production)

`src/startupGate.js` fails closed at boot: refuses to start without an explicit
Ed25519 signing key, a non-default ledger secret, a declared egress lockdown,
auth required, and dev tokens off. Auth pins HS256/RS256 (no `alg:none`,
constant-time compare, expiry enforced). HTTP bodies capped (413). The classifier
and prompt-influence scan are input-bounded (no ReDoS). The in-memory rate limiter
is memory-bounded.

## Known boundaries (deferred, by design or roadmap)

- **External penetration test / audit** — not yet done. Planned at first paid
  pilot / funding. The automated SAST + red-team suite + dependency scanning are
  the interim; a human audit is the next bar and is budget-gated, not a blocker
  for early design-partner use.
- **Multi-replica** — single-replica is fully correct. The **ledger** is now
  multi-replica-safe on Postgres via a shared sequencer (advisory-lock-serialized
  appends + monotonic order; `src/postgresLedger.js`, `tests/postgres-ledger.test.js`).
  Remaining: authz-object reads under Postgres are eventually consistent across
  replicas and **fail closed** (read-through is roadmap). Hot security state (risk,
  taint, metrics) is read fresh per call and is cross-replica consistent. See
  [BENCHMARKS.md](BENCHMARKS.md).
- **TLS-body inspection / DNS-tunnel exfil** — the egress proxy is host-only by
  design; payload inspection over an allowed host and recursive DNS-tunnel
  prevention are a TLS-terminating-proxy / filtering-resolver concern (roadmap).
- **Semantic / non-English DLP** — the default classifier is regex + shape +
  decode; the `classifierResolver` seam accepts an embedding/commercial DLP for
  autonomous public-sink lanes (it can only raise the class).

## Production integration (seams implemented + tested; wire to your stack)

- **IdP**: OIDC/JWKS RS256 verification implemented (`src/auth.js`,
  `SCOPEZERO_OIDC_*`). A live Keycloak proof is in `deploy/integration/`.
- **Observability**: OpenTelemetry traces + OTLP export (`src/telemetry.js`,
  `OTEL_EXPORTER_OTLP_ENDPOINT`). A live OTLP collector proof is in
  `deploy/integration/`.
- **State**: managed Postgres with row-level security (`src/postgresStore.js`).
- **SIEM**: JSON/CEF/LEEF/OTLP export endpoints (`src/siem.js`).
- **Secrets**: encrypted local store; move to a customer vault in production.
