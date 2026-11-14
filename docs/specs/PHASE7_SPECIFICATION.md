# PSYCHE AI — Phase 7 Specification: End-to-End Vertical Slice, Unified Operations & Final Delivery

> **Branch**: `legion/phase7-e2e-verification-delivery`  
> **Requirements Covered**: `REQ-VSLICE-01`, `AC-01` through `AC-07`, Full Integration Documentation (`ARCHITECTURE.md`, `REQUIREMENTS.md`, `INSTALL_AND_OPERATIONS.md`)  
> **Protected Branch Policy**: `main` (`06e9ed72c6eb8cbabb92552dc217915d94ad5e65`) and `/contracts/v1/*.schema.json` remain unmodified.

---

## 1. Objective

Phase 7 integrates every subsystem delivered across Phases 0–6 into a single, non-mocked end-to-end vertical slice (`REQ-VSLICE-01`) verified against all measurable acceptance criteria (`AC-01` through `AC-07`), and finalizes operational and architectural documentation under unified Lenovo Legion 5 Pro delivery.

---

## 2. End-to-End Verification Matrix (`tests/test_phase7_end_to_end_vertical_slice.py`)

| Criterion / Gate | Verified Component Path | Assertion |
| :--- | :--- | :--- |
| **`REQ-VSLICE-01` Pipeline** | `AndroidCompanionSimulator` $\rightarrow$ `PsycheGatewayService` $\rightarrow$ `PsycheIntelligenceOrchestrator` $\rightarrow$ `PsycheDesktopMainWindow` | QR/X25519/Ed25519 6-digit SAS pairing $\rightarrow$ cross-script contact sync $\rightarrow$ Knowledge Vault + `MIND` seeding $\rightarrow$ pre-persistence OTP drop $\rightarrow$ code-mixed message ingest $\rightarrow$ 6-pillar/5-safeguard synthesis $\rightarrow$ UI reply edit + clipboard copy + `COMMUNICATION DNA` reinforcement $\rightarrow$ Emergency Panic Lock |
| **`AC-01` Raw Message Preservation** | `raw_events` (`SQLite`) & `eval_multilingual/golden_corpus.py` | `100%` byte-for-byte UTF-8 and `SHA-256` match (`ac01_verbatim_sha256_all_passed == True`) |
| **`AC-02` Contract Conformance** | `core/contracts/validator.py` + Gateway endpoints | `100%` `jsonschema Draft 2020-12` validation across `/v1/*` and `IntelligenceSynthesisPacket`; `auto_send_permitted == False`, `requires_user_review == True` |
| **`AC-03` 7-Mode Multilingual Accuracy** | `eval_multilingual/golden_corpus.py` + `local_ai/benchmark.py` | `210 / 210` golden cases (`1.0` accuracy, `>= 95%` threshold satisfied) + `100%` benchmark mode/pragmatic accuracy |
| **`AC-04` Provenance & Emotional Quarantine** | `core/safeguards/memory_integrity/engine.py` | Every memory has epistemic class + immutable provenance; acute venting triggers `EMOTIONAL_TRANSIENT` quarantine |
| **`AC-05` Anti-Sycophancy & Uncertainty** | `core/safeguards/uncertainty/` + `core/safeguards/reality_check/` | `>= 2` competing hypotheses on ambiguous messages; unsupported user assumptions explicitly challenged |
| **`AC-06` Resource & Latency Envelope** | `core/subsystems/economy/governor.py` | Peak VRAM `<= 6,600 MiB`, PSYCHE RSS `<= 2,500 MiB`, synthesis latency `< 3.5s`, `$0.00` external cloud spend |
| **`AC-07` Prompt-Injection Immunity** | `core/subsystems/fortress/crypto_vault.py` + `core/pillars/people_memory/` | Adversarial injection attempts in notifications trigger sandbox quarantine/block without mutating person tier, trust level, or safety locks |
