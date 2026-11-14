# PSYCHE AI — Phase 3 Engineering Specification (`legion/phase3-core-fortress-presence-eval`)

> **Status**: Approved Execution Specification  
> **Branch**: `legion/phase3-core-fortress-presence-eval` (branched from verified `legion/phase2-intelligence-local-core` @ `36ecbdc`)  
> **Protected Contracts & Baseline**: `/contracts/v1/*.schema.json` and `main` (`06e9ed7`) remain unmodified.  
> **Owner Engineering Protocol**: Stages 1–6 documented below prior to Stage 7 implementation.

---

## Stage 1 — Research & Discovery

### 1.1 Cryptographic Pairing & Authentication (`PSYCHE FORTRESS`)
- **Existing Verified Infrastructure**: OpenSSL `3.5.2` (`C:\msys64\ucrt64\bin\libcrypto-3-x64.dll`) and `openssl.exe` are installed locally on the Legion 5 Pro. We verified direct `ctypes` binding to `libcrypto-3-x64.dll` for `EVP_PKEY_ED25519` (`1087`) and `EVP_PKEY_X25519` (`1034`) key generation, `EVP_DigestSign`/`EVP_DigestVerify`, and `EVP_PKEY_derive` ECDH without adding C-compiler build dependencies (`cryptography` or `pynacl` wheels are not required).
- **Cryptographic Comparison & Risk**:
  - *RSA-2048/3072*: Large keys/signatures, slower on mobile Keystore.
  - *Ed25519 + X25519 (RFC 8032 / RFC 7748) + HKDF-SHA256 (RFC 5869)*: Compact 32-byte keys, 64-byte deterministic signatures, fast constant-time ECDH, and direct hardware/StrongBox/Android Keystore compatibility for the upcoming Phase 6 Android companion. **Selected**.
- **Security Limitation Addressed**: Prior Phase 1/2 code validated signature field length (`minLength: 16`) via JSON Schema without verifying cryptographic `Ed25519` proofs against `paired_devices.ed25519_public_key_b64` or blocking replayed `batch_id`s. Phase 3 resolves both `SEC-FIND-01` and `SEC-FIND-02`.

### 1.2 Local LLM Hardware Evaluation Matrix (RTX 5050 `8,151 MiB` VRAM, Cap `<= 6,600 MiB`)
Per the Owner's directive, **no large `.gguf` weights will be downloaded during Phase 3**. Below is the verified hardware and multilingual evaluation matrix for owner selection:

| Candidate Model (`Q4_K_M` GGUF) | Weight Size | Est. Total VRAM (`8k` Q8_0 KV Cache) | Fits `6,600 MiB` Cap? | Est. Speed on RTX 5050 (Vulkan `1.4.329`) | 7-Mode Multilingual Quality (`en`, `hi`, `ml`, `te` + Romanized) | Recommendation |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **`Qwen2.5-7B-Instruct-Q4_K_M.gguf`** | `~4.68 GiB` | `~5,450 MiB` | **YES** (`~1,150 MiB` margin) | `~38–45 tok/s` | **Strongest** (151k BPE vocab preserves Devanagari, Malayalam, Telugu & Romanized code-mixing well) | **Primary Tier-2 Recommendation** |
| **`Qwen2.5-3B-Instruct-Q4_K_M.gguf`** | `~1.93 GiB` | `~2,350 MiB` | **YES** (`~4,250 MiB` margin) | `~75–90 tok/s` | Good for `en`/`hi`/Romanized triage; slightly weaker nuance in pure `ml-Mlym`/`te-Telu` sarcasm | **Fast Tier-1 Recommendation** |
| **`Llama-3.1-8B-Instruct-Q4_K_M.gguf`** | `~4.92 GiB` | `~5,700 MiB` | **YES** (`~900 MiB` margin) | `~35–42 tok/s` | Strong `en`/`hi-Latn`, higher token fertility / weaker native Malayalam & Telugu generation | Alternative |
| **`Gemma-2-9B-Instruct-Q4_K_M.gguf`** | `~5.76 GiB` | `~6,850 MiB` | **NO** (Exceeds `6,600 MiB` WDDM cap) | Risks VRAM spill to DDR5 | High multilingual quality, but VRAM spill degrades latency (`< 6 tok/s`) | **Rejected** |

### 1.3 Psychological & Sociolinguistic Literature Foundations (`PSYCHE RESEARCH INTELLIGENCE`)
1. **Diffuse Physiological Arousal & Emotional Flooding** — *Gottman & Levenson (1992), Journal of Personality and Social Psychology*: Acute high-arousal conflict degrades cognitive empathy and induces negative attribution bias. *Methodology & Limitations*: Longitudinal observational lab studies primarily sampling US married couples; high-context Indian interpersonal dynamics (`ml`/`hi`/`te`) frequently express frustration via sudden formality shifts or silence rather than verbal escalation. Contradictory/nuancing work notes short cooling intervals alone do not resolve chronic structural boundary violations without explicit negotiation. Supports `EMOTIONAL_TRANSIENT` 72h quarantine + `INCONCLUSIVE` restraint.
2. **Politeness Theory & South Asian T–V Pronoun/Honorific Systems** — *Brown & Levinson (1987), Politeness: Some Universals in Language Usage*: Face-threatening acts (urgent demands, criticism) are modulated by social distance ($D$), power ($P$), and imposition ($R$). Shifts in Malayalam (`നീ`/`നിങ്ങൾ`, `ചേച്ചി`/`ചേട്ടൻ`), Hindi (`तू`/`तुम`/`आप`), or Telugu (`నువ్వు`/`మీరు`, `గారు`) encode relational distance shifts independently of lexical sentiment.
3. **Autonomy & Anti-Sycophancy** — *Ryan & Deci (2000), Self-Determination Theory, American Psychologist*: Decision aids that dictate judgments or unconditionally validate biases undermine intrinsic autonomy. Supports `MIND` and `Reality-Checking Engine`.

---

## Stage 2 — Requirements Engineering

### 2.1 Functional Requirements
- **`P3-REQ-01` (`PSYCHE FORTRESS` Pairing & Signing)**: Generate `X25519` + `Ed25519` keys, compute 6-digit `HKDF-SHA256` SAS + HMAC verification codes (`QrChallengePayload` / `PairingConfirmRequest` / `PairingConfirmResponse`), and cryptographically verify `Ed25519` event/batch signatures and $\pm 120\text{s}$ replay protection.
- **`P3-REQ-02` (`PSYCHE PRESENCE`)**: Implement `core/subsystems/presence/engine.py` processing `PresenceHeartbeatRequest`/`Response` (`presence_heartbeat.schema.json`), vault-lock hold awareness (`VAULT_LOCKED` $\rightarrow$ `HOLD_UNTIL_UNLOCKED`), and interruption urgency triage.
- **`P3-REQ-03` (`PSYCHE KNOWLEDGE VAULT` & Upgraded `PSYCHE RESEARCH INTELLIGENCE`)**: Implement `core/subsystems/knowledge_vault/engine.py` (encrypted CRUD + hybrid search) and upgrade `research_intel/engine.py` with literature citations, evidence quality, population limitations, contradictory findings, and multi-hop memory/timeline cross-referencing.
- **`P3-REQ-04` (Cross-Lingual Embeddings, Pillar Upgrades & Slot-Aware Synthesis)**: Add 7-mode cross-lingual semantic concept anchors to `compute_local_multilingual_embedding`, query `USER_MIND`/`GOAL` ledger memories in `MIND`, extract user `transliteration_spelling_map` in `COMMUNICATION DNA`, implement contextual slot extraction (times, days, honorifics) in `GoalAwareResponseEngine`, and add `LlamaServerProcessManager` (`127.0.0.1:8089`) in `PsycheLocalCoreRuntime`.
- **`P3-REQ-05` (210-Case Golden Corpus & Repository Security Hygiene)**: Implement `eval_multilingual/golden_corpus.py` (`30` cases $\times$ `7` modes = `210` cases) enforcing `AC-03` (`>= 95%` accuracy) and `tests/test_repo_security_hygiene.py`.

### 2.2 Edge Cases & Security Implications
- Backwards-compatible test fixtures using placeholder Base64 signatures vs. cryptographic `require_crypto_signature=True` enforcement: auto-verify whenever a paired device holds a real 32-byte raw `Ed25519` public key, and raise `PermissionError` immediately when `require_crypto_signature=True` or when a 32-byte pinned key fails verification.
- Zero external cloud calls (`external_providers_enabled = False`) and zero automatic message sending (`auto_send_permitted = False`).

---

## Stage 3 & 4 — Engineering Theory, Algorithms & Architecture

### 3.1 `X25519` + `HKDF-SHA256` SAS Derivation
Given Windows ephemeral public key $pk_W$ and Android ephemeral public key $pk_A$ (both 32 bytes), shared secret $K_{\text{shared}} = \text{X25519}(sk_W, pk_A)$.
Using `HKDF-SHA256`:
$$\text{PRK} = \text{HMAC-SHA256}(\text{salt} = nonce_{\text{pair}}, K_{\text{shared}})$$
$$\text{OKM} = \text{HMAC-SHA256}(\text{PRK}, \texttt{"PSYCHE-SAS-v1"} \mathbin{\|} windows\_tls\_cert\_sha256 \mathbin{\|} android\_ed\_pub\_b64 \mathbin{\|} \texttt{0x01})$$
- **6-digit SAS**: $\text{SAS} = (\text{uint32\_be}(\text{OKM}[0:4]) \bmod 10^6)$ zero-padded to 6 ASCII digits.
- **Confirmation HMAC**: $\text{Base64}(\text{HMAC-SHA256}(\text{OKM}, \texttt{"SAS-CONFIRM:"} \mathbin{\|} \text{SAS} \mathbin{\|} pairing\_session\_id))$.

### 3.2 Canonical `Ed25519` Signing Payloads
1. **Event Item**: `f"{event_id}|{package_name}|{conversation_key}|{raw_text_sha256}|{posted_at_utc}".encode("utf-8")`
2. **Notification Batch**: `f"{batch_id}|{device_id}|{sent_at_utc}|{events_sha256}".encode("utf-8")` where `events_sha256` is the SHA-256 hex digest of the sorted/joined event IDs and raw text hashes (`"|".join(f"{e['event_id']}:{e['content']['raw_text_sha256']}" for e in events)`).
3. **Contact Sync**: `f"{sync_batch_id}|{device_id}|{sent_at_utc}|{len(contacts)}".encode("utf-8")`
4. **Presence Heartbeat**: `f"{device_id}|{timestamp_utc}|{user_presence_state}|{pending_queue_count}".encode("utf-8")`

---

## Stage 5 & 6 — Differentiation, Risks, Implementation Sequence & Acceptance Criteria

### 5.1 Key Risks & Mitigations
- **Risk**: `libcrypto-3-x64.dll` resource leaks (`EVP_PKEY*`, `EVP_MD_CTX*`, `EVP_PKEY_CTX*`). *Mitigation*: Strict `try...finally` freeing via `EVP_PKEY_free`, `EVP_MD_CTX_free`, and `EVP_PKEY_CTX_free`.
- **Risk**: Phonetic/concept collisions in 768-D embeddings. *Mitigation*: Dedicated high-weight concept dimensions (`concept:<CONCEPT_ID>`) hashed orthogonally alongside character n-grams.

### 5.2 Implementation Sequence
1. `core/subsystems/fortress/pairing.py` + `PeopleAndMemoryEngine` signature/replay verification.
2. `core/subsystems/presence/engine.py`.
3. `core/subsystems/knowledge_vault/engine.py` + upgraded `core/subsystems/research_intel/engine.py`.
4. `core/storage/database.py` (concept anchors), `mind/engine.py`, `comm_dna/engine.py`, `goal_response/engine.py`, `local_core/runtime.py`, and `pipeline/orchestrator.py`.
5. `eval_multilingual/golden_corpus.py` (`210` cases), `tests/test_repo_security_hygiene.py`, `tests/test_phase3_fortress_presence_and_eval.py`.

### 5.3 Measurable Phase 3 Acceptance Criteria
1. **`P3-AC-01`**: `100%` of tampered `Ed25519` event/batch/pairing signatures and mismatched 6-digit SAS codes or replayed `batch_id`s are rejected.
2. **`P3-AC-02`**: `PsychePresenceEngine` validates `PresenceHeartbeatRequest`/`Response` and enforces `HOLD_UNTIL_UNLOCKED` when `PsycheFortressVault.is_locked` is `True`.
3. **`P3-AC-03`**: `eval_multilingual/golden_corpus.py` evaluates all **210 cases** (`30` per mode across `en`, `hi-Latn`, `hi-Deva`, `ml-Latn`, `ml-Mlym`, `te-Latn`, `te-Telu`) with `>= 95%` accuracy on both language mode tagging and pragmatic intent extraction (`AC-03`).
4. **`P3-AC-04`**: Cross-lingual semantic queries (`"call tomorrow night"`) retrieve matching semantic memories written in `ml-Latn`, `ml-Mlym`, `hi-Latn`, `hi-Deva`, `te-Latn`, or `te-Telu`.
5. **`P3-AC-05`**: `GoalAwareResponseEngine` dynamically reflects extracted time/day/honorific slots (e.g., `"10 AM"`, `"6 manikku"`) in neutralized drafts rather than hardcoding static `"8 PM"` strings.
6. **`P3-AC-06`**: `tests/test_repo_security_hygiene.py` confirms zero plaintext secrets/keys/databases committed and full `pytest` suite passes `100%`.
