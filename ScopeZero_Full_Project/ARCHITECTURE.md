# ScopeZero Architecture

## What It Is

ScopeZero is a **vendor-neutral pre-execution authorization gateway for AI agents**. Before any agent calls GitHub, Slack, Gmail, AWS, or any API, ScopeZero evaluates a signed mission contract and returns one of five verdicts: `allow`, `block`, `redact`, `approval`, or `quarantine_context`. Every decision is written to a hash-chained, tamper-evident ledger. The core question it answers: *"Can you prove what your agent did last Tuesday and was it authorized?"*

---

## Where It Sits

```
┌─────────────────────────────────────────────────────────────┐
│  AI Agent (OpenAI / Anthropic / any loop)                   │
│    ↓  tool call                                             │
│  ScopeZero SDK wrapper  ──────────────────────────────────► │
│    ↓  POST /v1/tool-calls                                   │
│  ScopeZero Gateway  (port 8788)                             │
│    ↓  allow                                                  │
│  Real API (GitHub, Slack, Gmail, AWS…)                      │
└─────────────────────────────────────────────────────────────┘
```

**Network enforcement path** (Kubernetes):
```
Agent pod ──► [NetworkPolicy blocks direct egress]
          └──► ScopeZero proxy (HTTP CONNECT)
                  ↓ mission check
               Real API
```

The gateway runs as an HTTP server (`server.js`, port 8788). Agents integrate in one of three ways:
1. **SDK wrapper** (`sdk/wrappers/openai.js`, `sdk/wrappers/anthropic.js`) — 3-line wrap around any agent loop
2. **Direct API** — POST to `/v1/tool-calls` with mission context
3. **HTTP proxy** — set `HTTP_PROXY=http://scopezero:8788`; all outbound HTTP/HTTPS is intercepted

---

## Core Components

### 1. Mission Capsule (`src/capsules.js`)
The signed authorization token. Every tool call must reference an active capsule.

```json
{
  "id": "mission_abc123",
  "tenant_id": "tenant_contoso",
  "agent_id": "agent.ma-diligence.72f1",
  "delegated_by": "vp.strategy@contoso.example",
  "objective": "Review acquisition targets in healthcare sector",
  "allowed_tools": ["drive.search", "drive.read", "slack.draft"],
  "allowed_data_classes": ["public", "internal", "confidential"],
  "action_contracts": [...],
  "expires_at": "2025-06-02T00:00:00Z",
  "signature": "sz2.<ed25519-signature-base64>"
}
```

Capsules are **Ed25519-signed** (`src/crypto.js`, `src/capsules.js`). The private key signs at the gateway; verifiers — the CONNECT proxy, an external auditor — hold only the public key and can confirm authenticity without the power to forge. In production set `SCOPEZERO_SIGNING_PRIVATE_KEY` (PEM) so the key material never leaves the gateway; in dev/tests the keypair is derived deterministically from the shared secret so a single secret works end to end. The runtime verifies the signature and expiry on every request. A tampered or expired capsule forces a `block` verdict regardless of policy.

**Key rotation:** every capsule and cert is stamped with a `kid` (key fingerprint). The runtime verifies against a **keyset** — the current public key plus any retired public keys listed in `SCOPEZERO_SIGNING_PUBLIC_KEYS` — so rotating the signing key keeps live artifacts verifying until they expire. Generate a keypair with `node tools/gen-keys.js`.

### 2. Policy Engine (`src/policyEngine.js`)
Pure function: `evaluatePolicy(request, mission, agent, policy, ...) → verdict`

Two tiers of rule. **Deterministic gates block** (sound controls): capsule
validity, action-contract match `(tool, operation, data class, destination)`,
sensitive-egress, blocked action types, delegation depth. **Advisory signals
escalate** to human approval, never block on their own: keyword-overlap
intent-drift (`src/missionAlignment.js`), the prompt-influence heuristic
(`src/sensitiveData.js`). A blunt heuristic must not be sold as a guarantee, so
it routes to a human instead of silently deciding.

Notable controls:
- **Fail-closed on unknown egress** — outbound content whose data class can't be
  positively established *from the bytes* is held for human review rather than
  trusted as public. "Positively established" is decided by `classifyPayload`
  shape analysis (`src/sensitiveData.js`): a keyword hit establishes sensitivity,
  and at level 1 the class is established as public only when the payload has no
  bulk/tabular/encoded/large shape. A tool manifest's `data_out_classes` is a
  **verified ceiling, not a skip-flag** — if the payload classifies above the
  declared output class, the manifest is contradicted by the bytes and the call
  escalates. This is the control that catches exfiltration to an *in-contract*
  host through any tool (the host-only proxy cannot see it), and it cannot be
  dodged by routing the dump through a tool whose manifest claims "public output".
  Heuristic, not DLP: it catches bulk/encoded dumps, not low-volume values
  laundered inside prose.
- **Manifest-or-escalate** — any mutating/high-impact operation with no
  authoritative tool manifest is escalated, because the operation is otherwise
  whatever the agent declared it to be.
- **Ingest-taint / anti-laundering** — the gateway tracks a per-session
  high-water mark of the most sensitive class the session has been exposed to
  (`src/store.js` `sessions.ingested_class_rank`, classified from both the
  outbound payload and the inbound context). When a session that ingested
  `confidential`+ data later sends *lower-classed* content to an external
  destination, the egress routes to a human — because content laundered into
  benign-looking prose can't be caught by inspecting the outbound bytes, only by
  what the session has touched. The honest limit: this sees only material that
  passes through the gateway; a tool result returned straight to the agent and
  never shown to ScopeZero isn't tainted.
- **Value-shape classification + pluggable classifier** — `classifyPayload`
  (`src/sensitiveData.js`) flags sensitive *values* by structure (Luhn cards,
  IBAN, SSN, secret prefixes, high-entropy tokens) with no keyword present, and a
  `classifierResolver` seam lets an embedding/commercial-DLP classifier augment
  the regex default (it can only raise the class, never lower it).

Decisions compose (the strongest verdict wins), not first-rule-wins. Output: `{ decision, risk_score, risk_contribution, reasons[], controls[], matched_contract_id, safe_to_execute }`.

### 3. `evaluateToolCall` — the hot path (`src/runtime.js:~160`)
Full evaluation sequence per call:

```
 1. Look up policy, agent, mission from store
 2. Read prior session risk + session ingest-taint high-water mark
 3. Classify payload — keyword + structured-value (Luhn/IBAN/SSN/secret-prefix/
    entropy) + byte-shape; merge optional external classifier (ceiling-raiser)
 4. Classify inbound context (retrieved docs / prior tool output) → ingest rank
 5. Detect prompt influence (advisory)
 6. Describe action (tool manifest resolution or inference)
 7. Evaluate mission alignment (deterministic, server-side, advisory)
 8. Check decision cache (SHA-256 keyed on classification, taint, context, TTL)
 9. Run policy engine (with prior session taint)  →  verdict
10. Agent certificate verification (if cert_id provided)
11. Behavioral anomaly detection  →  risk_delta applied to verdict
12. Update behavior profile in store
13. Update session risk budget
14. Raise session ingest-taint high-water mark (after the decision)
15. If verdict = "approval": create approval record, fire Slack notification
16. Append evidence to hash-chained ledger
17. Record decision metrics
```

### 4. Ledger (`src/ledger.js`)
Append-only JSONL file (`data/ledger.jsonl`). Every entry:

```json
{
  "id": "evt_...",
  "time": "ISO",
  "previous_hash": "<sha256 of prior entry>",
  "record": { "event_type": "action_authorization.evaluated", ... },
  "hash": "<sha256 of this entry including previous_hash>"
}
```

Hash chain: each entry's `hash` covers its own body **plus** `previous_hash`. Tamper any entry and every subsequent hash breaks. When a secret is configured (`SCOPEZERO_LEDGER_SECRET`, else `SCOPEZERO_SIGNING_SECRET`) the chain hash is an **HMAC-SHA256** keyed by that secret — without the secret an attacker with write access to `ledger.jsonl` cannot recompute a valid chain after editing an entry, so a full rewrite is detected by `verify()` (plain SHA-256 fallback only when no secret is set). `GET /v1/ledger/verify` traverses the full chain and reports any break. Anchoring to an external witness endpoint is also supported (`src/ledgerAnchor.js`).

### 5. Store (`src/store.js`)
SQLite via `node:sqlite` (`DatabaseSync`). Core entities live in a JSON blob (`scopezero_state`) mirrored to normalized relational tables (tenants, agents, missions, approvals, policies, policy_versions) for SQL querying — the mirror is rebuilt per-table only when that collection changed (dirty-tracking), not on every write. The **hot-path** collections — `behavior_profiles`, `sessions`, `metrics` — written on every tool call, live in their **own row-keyed tables** with atomic upserts, *not* in the blob, so a tool call never reserializes all state (and, in Postgres, never takes the global write lock). Postgres adapter available (`src/postgresStore.js`) with tenant row-level security on every tenant table including the hot-path ones.

State / tables:
- `tenants`, `agents`, `missions`, `approvals`, `policies`, `policy_versions` — core entities (blob + mirror tables)
- `behavior_profiles` (table) — per `tenant:agent` behavioral baseline, per-row upsert
- `sessions` (table) — per `tenant:session`: risk budget (atomic increment capped at 100) and `ingested_class_rank` (monotonic ingest-taint high-water mark, atomic MAX)
- `metrics` (table) — global decision counters, atomic increment
- `mcp_servers`, `agent_certs` — MCP trust registry, issued identity certificates

---

## Enforcement Layers

### Layer 1: Pre-execution gateway (always)
Every tool call hits `/v1/tool-calls`. Policy engine runs. If `safe_to_execute = false`, the SDK wrapper blocks execution before any external API is called. This layer requires SDK integration.

### Layer 2: HTTP CONNECT proxy (network-level)
Agents set `HTTP_PROXY=http://scopezero:8788`. Outbound traffic routes through ScopeZero:
- **HTTPS** (`CONNECT`): before any tunnel opens, `evaluateProxyConnect` (`src/proxyEnforcer.js`) binds the connection to a mission and requires **all** of: valid signature (`verifyMissionCapsule`), unexpired, `status: active`, the requesting agent matches `mission.agent_id`, and the destination host is in `action_contracts[].destinations`. Any failure → `403` with a distinct reason, logged to the ledger. Only then is a TCP tunnel created via `node:net`. This means an expired or tampered mission cannot open a tunnel even to an otherwise-allowed host.
- **Plain HTTP**: not forwarded. Cleartext HTTP can't be bound to a mission the way `CONNECT` is, so it is refused explicitly (`403 scopezero_proxy_http_unsupported`) — fail closed. Use HTTPS.

**Enforcement granularity (honest scope):** the proxy enforces *destination host + live mission*, not per-request action — TLS bodies are opaque, so once a host is in-contract the tunnel carries any operation to it. Action/data-class/operation enforcement is the gateway/SDK layer's job (Layer 1); the proxy's job is fail-closed, mission-bound, audited egress allow-listing. The "an agent that skips the SDK is still contained" guarantee needs a kernel-level egress block — available **without Kubernetes**. Two tiers provide it: a **K8s NetworkPolicy** (strongest), or a **Docker internal network** that leaves the agent with no internet route except the proxy (see `deploy/docker-egress-lockdown.md` + `deploy/docker-compose.lockdown.yml`). Only the bare-SDK tier with no network lockdown is honor-system, since a raw socket can ignore `HTTP_PROXY`. `GET /v1/deployment/lockdown` returns Docker flags and K8s env patch. See `examples/breach-containment-demo.js` for an executable end-to-end proof.

### Layer 3: Kubernetes admission webhooks (enforcement at pod creation)
`GET /v1/deployment/k8s-manifests` returns four manifests applied together (two NetworkPolicies + two webhooks):

**NetworkPolicy** (two policies) — a namespace-wide `scopezero-default-deny-egress` (empty `podSelector`, so it selects **every** pod including unlabelled ones) plus a labelled `scopezero-enforce-proxy-egress`. Both permit egress only to the ScopeZero proxy service + DNS — and DNS is pinned to the in-cluster resolver (`kube-system` / `k8s-app: kube-dns`), not `0.0.0.0/0`, to close the open-DNS exfiltration channel (an injected agent can otherwise tunnel data out as queries to its own nameserver). All other TCP connections are dropped by the kernel. The default-deny policy means a pod that forgot the `scopezero.io/enforce: true` label is still boxed in rather than open. *(Full DNS-tunnel prevention also needs a filtering resolver that allow-lists names — pinning to kube-dns kills the direct-to-arbitrary-resolver path, not recursive exfil; on the roadmap.)*

**MutatingWebhookConfiguration** (`POST /v1/admission/mutate`) — K8s API server calls ScopeZero before any pod starts. JSON Patch injects `HTTP_PROXY`, `HTTPS_PROXY`, `http_proxy`, `https_proxy`, `NO_PROXY` into every container that's missing them. Developer forgets → automatically enforced.

**ValidatingWebhookConfiguration** (`POST /v1/admission/validate`) — runs after mutation. Rejects any pod where a container overrode or removed the proxy config. Both webhooks set `failurePolicy: Fail` — ScopeZero down → no new agent pods start (fail-closed).

---

## Action Contracts
Each mission capsule carries vendor-neutral action contracts that describe what the agent may do:

```json
{
  "id": "contract.drive.read",
  "tools": ["drive.read"],
  "operations": ["read"],
  "data_classes": ["public", "internal", "confidential"],
  "destinations": ["diligence-room.contoso.example"],
  "max_delegation_depth": 1,
  "effect": "allow"
}
```

The policy engine matches `(tool, operation, data_class, destination)` against contracts in order. No match → `block`. `effect: "approval"` → human approval required. Tool manifests (`src/toolManifest.js`) provide authoritative operation/risk metadata for known tools; inference fallback for unknown ones. For an unknown tool the operation/action_type is *inferred from the agent's self-declared input* — not ground truth — so a high-impact action on an unmanifested tool is escalated to approval (`require_manifest_for_high_impact`), never silently trusted.

---

## Behavioral Anomaly Detection (`src/behaviorAnalyzer.js`)
Per `(tenant, agent, tool)` profile stored in the behavior store. Analysis runs on every call **before** recording.

| Phase | Condition | Anomaly | Severity |
|---|---|---|---|
| No history | `total_calls = 0` | `new_tool_first_use` | low |
| Cold start | `1 ≤ calls < 20` | `cold_start_observation` | medium (low-risk tool) / high (send, export, delete, payment…) |
| Established | `calls ≥ 20` + UTC hour with 0 history | `off_hours_activity` | medium |
| Established | `≥ 10 calls in last 5 min` | `burst_absolute` | high |
| Established | `hourly rate > max(5, baseline × 3)` | `velocity_spike` | high |
| Any phase | `calls today ≥ daily cap` (500 default, 50 high-risk) | `sustained_volume` | high |

`high` severity + `allow` verdict → escalated to `approval`. Risk delta added to `verdict.risk_score`. Burst check fires even during cold start. The `sustained_volume` ceiling is **baseline-independent** — it closes the low-and-slow gap where an attacker drips calls under the burst/velocity thresholds, or first inflates the baseline so `baseline × 3` becomes huge. Caps are configurable per tenant (`behavior_daily_volume_cap`, `behavior_daily_volume_cap_high_risk`).

---

## MCP Trust Registry (`src/mcpTrustRegistry.js`)
ScopeZero as the security layer for the MCP ecosystem. Every external MCP server call goes through `/v1/mcp/evaluate`.

**Trust levels:**
| Level | Risk delta | Effect |
|---|---|---|
| `verified` | +0 | Allow (if policy allows) |
| `community` | +5 | Allow with risk note |
| `unverified` | +20 | Escalate `allow → approval` |
| `blocked` | +100 | Hard block, no policy evaluation |

**Trust decay:** verified servers not re-reviewed in 180 days auto-demote to `community`. Servers not refreshed in 90 days flagged `stale`.

**CVE signals:** `POST /v1/mcp/servers/:id/refresh` queries the OSV API (`api.osv.dev`) for the server's npm package. Results written to `server.trust_signals.{ known_cves, cve_ids, signal_summary }`. A background scheduler (`src/mcpRefreshScheduler.js`) refreshes every registered server that has a `package_name` on a fixed interval, configurable via `SCOPEZERO_MCP_REFRESH_INTERVAL_HOURS` (unset/0 = manual only), so newly disclosed CVEs surface without an operator triggering a refresh.

Pre-seeded well-known servers: GitHub MCP Server (verified), MCP Filesystem/PostgreSQL/Slack servers (community).

---

## Agent Identity Certificates (`src/agentCert.js`)
Cryptographic identity bound to a registered agent at deployment time.

**Structure:** `cert_id`, `version`, `tenant_id`, `agent_id`, `capabilities.allowed_tools`, `issued_at`, `expires_at` (default 90 days), `fingerprint` (SHA-256 of body), `signature` (Ed25519 over `fingerprint:agent_id:tenant_id:expires_at`, verified with the public key).

**Verification in `evaluateToolCall`:** if `input.agent_cert_id` is present, the runtime verifies signature, expiry, revocation status, and identity match. Result written to `verdict.cert_verification`. Invalid cert + `policy.require_agent_cert = true` → hard block. Valid cert → `agent_cert_verified` added to `verdict.controls`.

Revocation: `POST /v1/certs/:certId/revoke` marks cert as revoked with reason; ledger event written. Revoked certs fail verification even with a valid signature.

---

## Multi-Agent Chain Tracking (`src/agentChain.js`)
Sub-agents spawn child missions via `parent_mission_id`. The runtime enforces:
- No cycles (same agent cannot appear twice in a chain)
- Depth ≤ `policy.max_delegation_depth`
- Parent mission must be active and unexpired

`GET /v1/chains` returns the full mission forest across all active missions. `GET /v1/missions/:id/chain` returns the chain for a specific mission.

---

## Compliance Report (`src/complianceReport.js`)
`GET /v1/compliance/report?format=html` generates a print-ready audit report mapping ScopeZero controls to:
- **SOC 2** Type II controls (CC6, CC7, CC8)
- **EU AI Act** (Article 9 risk management, Article 13 transparency)
- **HIPAA** (§164.312 access controls, audit controls)

Evidence pulled live from the ledger and store metrics. Renders as HTML with page-break CSS for printing.

---

## API Surface (45 routes)

| Area | Key endpoints |
|---|---|
| Core | `POST /v1/tool-calls`, `POST /v1/missions`, `POST /v1/agents` |
| Approvals | `POST /v1/approvals/:id/approve`, `POST /v1/approvals/:id/deny` |
| Policy | `GET/PUT /v1/policy`, `POST /v1/policy/proposals` |
| Ledger | `GET /v1/ledger`, `GET /v1/ledger/verify` |
| MCP trust | `GET/POST /v1/mcp/servers`, `POST /v1/mcp/evaluate`, `POST /v1/mcp/servers/:id/refresh` |
| Certs | `POST /v1/agents/:id/certs`, `POST /v1/certs/:id/revoke` |
| Behavior | `GET /v1/agents/:id/behavior` |
| Chains | `GET /v1/chains`, `GET /v1/missions/:id/chain` |
| Enforcement | `GET /v1/deployment/lockdown`, `GET /v1/deployment/k8s-manifests` |
| Webhooks | `POST /v1/admission/mutate`, `POST /v1/admission/validate` |
| Compliance | `GET /v1/compliance/report`, `GET /v1/compliance/controls` |
| MCP server | `POST /mcp` (ScopeZero exposes itself as an MCP server) |

---

## Data Flow: Single Tool Call

```
Agent → POST /v1/tool-calls
  { tenant_id, agent_id, mission_id, tool: "gmail.send",
    action: "Send summary to CFO", payload: {...},
    destination: { address: "cfo@contoso.com" },
    agent_cert_id: "cert_abc" }

Runtime:
  1. getPolicy(tenant_id)          → policy object
  2. getAgent(tenant_id, agent_id) → agent record
  3. getMission(mission_id)        → capsule (Ed25519 verified)
  4. classifyPayload(payload)      → { label: "confidential", findings: [...],
                                       established: true, egress_shape: null }
  5. detectPromptInfluence(context)→ { influenced: false }
  6. describeActionRequest(...)    → { tool, operation: "external_send",
                                       action_type: "external_send",
                                       data_class: "confidential",
                                       destination: { address: "cfo@contoso.com", external: true } }
  7. evaluateMissionAlignment(...) → { aligned: true, score: 0.8 }
  8. readDecisionCache(key)        → null (miss)
  9. evaluatePolicy(...)           → { decision: "allow", risk_score: 25, ... }
 10. verifyCert("cert_abc")        → { valid: true }    → adds "agent_cert_verified" control
 11. analyzeToolCallBehavior(...)  → cold_start_observation (high) → decision escalates to "approval"
 12. updateBehaviorProfile(...)
 13. updateSessionRisk(+3)
 14. addApproval(...)              → approval record created
 15. notifySlack(approval)         → Block Kit message sent
 16. ledger.append(evidence)       → hash-chained entry written
 17. recordDecision(verdict)       → metrics incremented

Response:
  { decision: "approval", safe_to_execute: false,
    verdict: { reasons: [...], controls: [...], cert_verification: {...},
               behavioral_anomalies: [{code: "cold_start_observation", ...}] },
    approval: { id: "approval_xyz", status: "pending" },
    evidence_hash: "sha256:..." }
```

---

## Production Hardening (fail-closed boot)

`src/startupGate.js` runs before the gateway starts. In `NODE_ENV=production` it
**refuses to boot** when a security-critical setting is missing, instead of
silently using a dev default:

- `SCOPEZERO_SIGNING_PRIVATE_KEY` unset → fatal (no deriving the signing key from
  a shared secret in prod).
- `SCOPEZERO_SIGNING_SECRET` missing/default → fatal (it keys the ledger chain).
- `SCOPEZERO_EGRESS_LOCKDOWN` not `k8s`/`docker` → fatal (declare the kernel
  egress block; verify it with `node tools/lockdown-selftest.js`, which opens a
  raw off-path socket and reports contained/open).
- `SCOPEZERO_REQUIRE_AUTH != true` or `SCOPEZERO_ALLOW_DEV_TOKEN != false` → fatal.

`GET /v1/ready` reports posture live: `egress_lockdown`, `require_proxy_path`,
`signing_key_explicit`, `signing_kid`. Optional `SCOPEZERO_REQUIRE_PROXY_PATH`
makes the gateway reject tool calls that didn't traverse the enforced ingress
(catches a skipped SDK/proxy; the kernel lockdown still owns raw-socket egress).

Supply chain: CI (`.github/workflows/scopezero-ci.yml`) runs `npm run audit`
(high+ fails the build), generates a CycloneDX SBOM, and has a keyless-cosign
image-signing job. Performance is gated by the benchmarks (see `BENCHMARKS.md`).

## Tech Stack
- **Runtime:** Node.js ES modules, `node --test` (no external test framework)
- **Storage:** SQLite (`node:sqlite`, `DatabaseSync`) local; Postgres with RLS in production
- **Crypto:** `node:crypto` — Ed25519 for mission-capsule and agent-cert signatures (private key signs, public key verifies and is safe to distribute; `SCOPEZERO_SIGNING_PRIVATE_KEY` in prod, derived from the shared secret in dev), HMAC-SHA256 for the keyed ledger chain (constant-time comparison), SHA-256 for fingerprints
- **Auth:** JWT (HS256 pinned / RS256 OIDC), dev token endpoint, OIDC/JWKS support
- **Tests:** 227 tests, 0 failures
- **No runtime dependencies** beyond Node.js builtins for the core gateway
