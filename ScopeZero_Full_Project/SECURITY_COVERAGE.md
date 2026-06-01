# ScopeZero — Security Coverage Map

How ScopeZero maps to the two standard AI-security threat catalogs: the **OWASP
Top 10 for LLM Applications (2025)** and **MITRE ATLAS**. ScopeZero is a runtime
*authorization and egress* control — it governs what an agent is allowed to *do*,
not how the model is trained or what it generates. Coverage is rated honestly:

- **Strong** — a primary control directly prevents or contains the threat.
- **Partial** — meaningfully reduced, but not eliminated, by ScopeZero alone.
- **Out of scope** — a different layer's job (training, RAG store, model quality); ScopeZero still leaves a forensic trail.

Every "covered" claim points at a concrete control so it can be verified, not taken on faith.

## OWASP Top 10 for LLM Applications (2025)

| # | Risk | Coverage | ScopeZero control |
|---|------|----------|-------------------|
| LLM01 | Prompt Injection | **Strong** | Evasion-resistant prompt-injection detection (`src/sensitiveData.js`; homoglyph/spacing/leet/base64 — 100% recall on `tests/prompt-injection-corpus.test.js`) → `quarantine_context`; deterministic mission-alignment. The model may still be *influenced*, but the resulting **action** is contained at the gateway and the network. |
| LLM02 | Sensitive Information Disclosure | **Strong** | Server-side data classification + `sensitive_egress_guard`, `redact` verdict, and mission-bound destination contracts; HTTPS egress allow-listed at the proxy + kernel (K8s NetworkPolicy), DNS pinned to the cluster resolver. |
| LLM03 | Supply Chain | **Partial** | MCP trust registry with OSV CVE signals + scheduled refresh + trust decay (`src/mcpTrustRegistry.js`); agent identity certificates. Covers MCP-server provenance/CVE; does not scan model weights. |
| LLM04 | Data and Model Poisoning | **Out of scope** | Training-time concern. ScopeZero is runtime; the hash-chained ledger provides forensic evidence after the fact. |
| LLM05 | Improper Output Handling | **Partial** | Vendor-neutral action contracts gate `(tool, operation, data_class, destination)`; `redact` and approval gates on high-impact actions. Downstream sanitization of model output in the consuming app remains the app's responsibility. |
| LLM06 | Excessive Agency | **Strong** | The core of the product: HMAC-signed, time-boxed **mission capsules** (least-privilege tools/data/destinations), delegation-depth limits with cycle detection, approval gates, behavioral anomaly detection. An over-reaching action is blocked or escalated before execution. |
| LLM07 | System Prompt Leakage | **Partial** | `secret_exfiltration` injection signal + egress control block attempts to exfiltrate prompts/secrets; storing secrets out of the prompt is still the integrator's job. |
| LLM08 | Vector and Embedding Weaknesses | **Out of scope** | RAG store internals. Not addressed (egress control still constrains what a poisoned retrieval can cause the agent to *do*). |
| LLM09 | Misinformation | **Out of scope** | Content-quality concern. Mission-alignment catches gross intent drift, not factual accuracy. |
| LLM10 | Unbounded Consumption | **Strong** | Per-session risk budget; behavioral burst, velocity-spike, and baseline-independent daily-volume ceilings (`src/behaviorAnalyzer.js`); per-route rate limiting. Bounds *action* volume; does not cap model token/$ spend. |

## MITRE ATLAS (selected techniques)

| Technique | Coverage | ScopeZero control |
|-----------|----------|-------------------|
| AML.T0051 LLM Prompt Injection | **Strong** | Detection + `quarantine_context` + downstream action containment. |
| AML.T0053 LLM Plugin Compromise | **Partial** | MCP trust registry (blocked/unverified levels escalate or deny) + action contracts. |
| AML.T0057 LLM Data Leakage | **Strong** | Data classification + sensitive-egress guard + mission destination allow-list + kernel egress block. |
| AML.T0048 External Harms / Exfiltration | **Strong** | Fail-closed, mission-bound egress at the proxy + K8s NetworkPolicy; every attempt written to the tamper-evident ledger. |
| AML.T0025 Exfiltration via Cyber Means | **Strong** | DNS pinned to cluster resolver; only in-contract destinations reachable; raw sockets dropped by NetworkPolicy. |

## The honest boundary

ScopeZero is the **runtime authorization and egress layer**. It does not train
or fine-tune models, validate factual output, or secure the RAG/vector store —
those are adjacent layers. What it guarantees is that, however the model is
influenced, the agent's *actions* are bound to a signed mission, contained
fail-closed at the kernel when it tries to reach the network, and provable in a
tamper-evident ledger. That is the slice of the AI-security problem ScopeZero
owns, and within it the coverage above is real and test-backed.
