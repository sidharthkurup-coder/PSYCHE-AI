# PSYCHE AI — Master Requirements & Traceability Specification

> **Status**: Approved Baseline (`v1.0.0`)  
> **Scope**: Complete functional, safeguard, multilingual, hardware, security, and cross-laptop integration requirements for PSYCHE AI.

---

## 1. Six Core Intelligence Pillars (`REQ-PIL-*`)

| ID | Pillar | Mandatory Capabilities | Verification Artifact / Contract |
| :--- | :--- | :--- | :--- |
| **`REQ-PIL-01`** | **1. HUMAN (Psychology Intelligence)** | Analyze emotional tone, stress/fatigue markers, defense mechanisms, attachment styles, and interpersonal dynamics in incoming messages and user drafts. | `contracts/v1/intelligence_synthesis.schema.json` (`pillar_assessments.human`) |
| **`REQ-PIL-02`** | **2. REALITY (Message & Interaction Intelligence)** | Decode pragmatic intent vs. literal words, identify subtext, sarcasm, urgency, social obligations, and situational context. | `contracts/v1/intelligence_synthesis.schema.json` (`pillar_assessments.reality`) |
| **`REQ-PIL-03`** | **3. MIND (Personal Intelligence)** | Model the user's values, long-term personal objectives, cognitive patterns, emotional triggers, and decision history while preserving **independent thinking**. | `contracts/v1/intelligence_synthesis.schema.json` (`pillar_assessments.mind`) |
| **`REQ-PIL-04`** | **4. COMMUNICATION DNA (Personal Writing Intelligence)** | Extract and maintain recipient-specific and language-specific writing fingerprints (syntax, greetings, punctuation, code-mixing ratio, transliteration spelling preferences, length, directness). | `DATA_MODEL.md` (`comm_dna_profiles`), `contracts/v1/intelligence_synthesis.schema.json` |
| **`REQ-PIL-05`** | **5. PEOPLE AND MEMORY (Relationship Intelligence)** | Maintain canonical contact entities across scripts/platforms, relationship tiers, trust levels, historical commitments, boundaries, and provenance-linked memories. | `contracts/v1/contact_sync.schema.json`, `contracts/v1/memory_record.schema.json` |
| **`REQ-PIL-06`** | **6. INFLUENCE AND MENTOR (Communication Strategy & Personal Development)** | Provide strategic communication framing (de-escalation, boundary setting, negotiation, high-empathy support) and constructive mentorship aligned with the user's growth. | `contracts/v1/intelligence_synthesis.schema.json` (`pillar_assessments.influence_and_mentor`) |

---

## 2. Eight Supporting Subsystems (`REQ-SUB-*`)

| ID | Subsystem | Mandatory Capabilities | Verification Artifact / Contract |
| :--- | :--- | :--- | :--- |
| **`REQ-SUB-01`** | **PSYCHE KNOWLEDGE VAULT** | Store and index encrypted user notes, personal reference documents, and verified domain facts with provenance and hybrid search. | `DATA_MODEL.md` (`knowledge_vault_items`) |
| **`REQ-SUB-02`** | **PSYCHE RESEARCH INTELLIGENCE** | Perform multi-step analytical retrieval and evidence synthesis across `PEOPLE AND MEMORY`, `Conversation Timeline Engine`, and `PSYCHE KNOWLEDGE VAULT`. | `ARCHITECTURE.md` (Section 3) |
| **`REQ-SUB-03`** | **PSYCHE LOCAL CORE** | Manage local daemon lifecycle, offline-first operation, deterministic state persistence, and hardware health monitoring. | `ARCHITECTURE.md` (Section 3, 7) |
| **`REQ-SUB-04`** | **MODEL NEUTRALIZER AND IDENTITY LOCK** | Strip generic AI assistant phrasing, sycophantic filler, and moralizing disclaimers; enforce user-authentic voice matching `COMMUNICATION DNA`. | `contracts/v1/intelligence_synthesis.schema.json` (`neutralizer_audit`) |
| **`REQ-SUB-05`** | **PSYCHE ECONOMY** | Enforce RTX 5050 VRAM cap (`<= 6,600 MiB`), system RAM cap (`<= 2,500 MiB`), latency budgets, and strict authorization gates on any external provider calls. | `ARCHITECTURE.md` (Section 7), `SECURITY.md` (Section 2.9) |
| **`REQ-SUB-06`** | **PSYCHE PRESENCE** | Track cross-device availability, focus/DND state, and notification interruption urgency between Android and Windows Companion. | `contracts/v1/presence_heartbeat.schema.json` |
| **`REQ-SUB-07`** | **PSYCHE FORTRESS** | Enforce mTLS 1.3 + QR/SAS pairing, DPAPI/Keystore encryption at rest, untrusted-input sandboxing (prompt-injection firewall), and Panic Lock. | `SECURITY.md`, `contracts/v1/device_pairing.schema.json` |
| **`REQ-SUB-08`** | **Functionality & Quality Assurance** | Automated contract validation, 7-language-mode evaluation, memory recovery testing, and sycophancy/hallucination audits. | `REQUIREMENTS.md` (Section 7) |

---

## 3. Five Mandatory Engineering Safeguards & Core Integrity (`REQ-SAFE-*`)

| ID | Safeguard | Mandatory Engineering Rules | Verification Artifact / Contract |
| :--- | :--- | :--- | :--- |
| **`REQ-SAFE-01`** | **A. Contextual Uncertainty Engine** | 1. Distinguish objective facts from subjective interpretations.<br>2. Generate $\ge 2$ plausible alternative explanations for ambiguous messages.<br>3. Surface contradictory evidence.<br>4. Output calibrated confidence $\in [0.0, 1.0]$.<br>5. Explicitly permit `INCONCLUSIVE` conclusions when evidence is insufficient. | `contracts/v1/intelligence_synthesis.schema.json` (`uncertainty_audit`) |
| **`REQ-SAFE-02`** | **B. Memory Integrity Engine** | 1. Classify every memory into exactly one epistemic class: `VERIFIED_FACT`, `USER_REPORT`, `OBSERVATION`, or `AI_HYPOTHESIS`.<br>2. Record immutable provenance and UTC timestamps.<br>3. Detect and link contradictory memories.<br>4. Support non-destructive corrections, versioned history, crash recovery, and deletion.<br>5. Quarantine temporary emotional reactions (`EMOTIONAL_TRANSIENT`) so acute frustration never becomes a permanent assumption. | `contracts/v1/memory_record.schema.json`, `DATA_MODEL.md` |
| **`REQ-SAFE-03`** | **C. Conversation Timeline Engine** | 1. Reconstruct chronological interactions across messages.<br>2. Identify and track unanswered questions and unresolved situations (`open_loops`).<br>3. Detect shifts in communication cadence, latency, length, or script usage.<br>4. Strictly separate `OBSERVED_EVENT` from `INFERRED_EVENT`. | `contracts/v1/timeline_state.schema.json`, `DATA_MODEL.md` |
| **`REQ-SAFE-04`** | **D. Goal-Aware Response Engine** | 1. Align drafts with the user's explicit communication goal, relationship boundaries, and `COMMUNICATION DNA`.<br>2. Request user clarification **only** when unresolved ambiguity would materially change the response strategy. | `contracts/v1/intelligence_synthesis.schema.json` (`goal_aware_recommendations`) |
| **`REQ-SAFE-05`** | **E. Reality-Checking Engine** | 1. Challenge unsupported assumptions made by **both** the user and the AI.<br>2. Separate emotional feelings from factual conclusions.<br>3. Never automatically agree with the user when factual evidence is missing or contrary. | `contracts/v1/intelligence_synthesis.schema.json` (`reality_check_audit`) |
| **`REQ-SAFE-06`** | **Intelligent Memory Retrieval** | Combine semantic vector similarity, `FTS5` lexical match, `PEOPLE` graph proximity, and temporal recency; always co-retrieve linked contradictions alongside any retrieved memory. | `DATA_MODEL.md` (Section 4) |
| **`REQ-SAFE-07`** | **Error Correction & Recovery** | Propagate user corrections to `PEOPLE`, `MEMORY`, and `Conversation Timeline Engine` immediately while preserving an auditable revision trail and recovering cleanly from power/process interruptions. | `DATA_MODEL.md` (Section 3) |
| **`REQ-SAFE-08`** | **Independent-Thinking Preservation** | Present transparent evidence, trade-offs, and competing interpretations so the user retains autonomous judgment rather than passive reliance on AI decrees. | `contracts/v1/intelligence_synthesis.schema.json` |

---

## 4. Exact Language & Multilingual Scope (`REQ-LANG-*`)

| ID | Requirement | Specification |
| :--- | :--- | :--- |
| **`REQ-LANG-01`** | **Authorized Language & Script Modes (Exact 7 Modes)** | Support **only**:<br>1. `en` — English<br>2. `hi-Latn` — Hindi typed in English letters<br>3. `hi-Deva` — Hindi typed in Devanagari (`हिन्दी`)<br>4. `ml-Latn` — Malayalam typed in English letters<br>5. `ml-Mlym` — Malayalam typed in Malayalam script (`മലയാളം`)<br>6. `te-Latn` — Telugu typed in English letters<br>7. `te-Telu` — Telugu typed in Telugu script (`తెలుగు`) |
| **`REQ-LANG-02`** | **Intra-Message Code-Mixing** | Accurately parse and reason over natural combinations of the 7 modes within the same sentence or conversation (e.g., Manglish + English, Tenglish + English, Hinglish + Devanagari). |
| **`REQ-LANG-03`** | **Transliteration & Colloquial Variance** | Handle non-standard Romanized spellings, vowel elongation/dropping, colloquial expressions, regional idioms, honorifics, informal grammar, and sarcasm across all 4 languages. |
| **`REQ-LANG-04`** | **Verbatim Original Message Preservation** | Preserve the exact original UTF-8 string (`raw_text`) and its `SHA-256` digest without modification, normalization overwrite, or destructive translation. |
| **`REQ-LANG-05`** | **Scope Lock** | Do not add any other languages or scripts without explicit Principal Owner approval. |

---

## 5. Two-Laptop Platform & Functional Requirements

### 5.1 Lenovo LOQ — Android & Mobile QA Responsibilities (`REQ-AND-*`)
- **`REQ-AND-01 (Notification Acquisition)`**: Capture incoming messaging notifications via Android `NotificationListenerService`, extracting sender metadata, conversation/group context, timestamps, and verbatim message text while deduplicating summary updates.
- **`REQ-AND-02 (Contact Identification)`**: Resolve notification senders against Android `ContactsContract`, normalize phone numbers (salted SHA-256 / E.164), and sync contact alias candidates to `PEOPLE AND MEMORY`.
- **`REQ-AND-03 (Android Security & Permissions)`**: Enforce principle of least privilege, user-configurable app allowlists, automatic exclusion of OTP/banking alerts, and Android Keystore hardware-backed encryption for offline queues.
- **`REQ-AND-04 (Encrypted Companion Sync)`**: Implement mTLS 1.3 + QR/SAS pairing and reliable batch synchronization (`contracts/v1/notification_ingest.schema.json`, `contracts/v1/contact_sync.schema.json`) with the Windows Companion.
- **`REQ-AND-05 (Multilingual Evaluation & Device QA)`**: Maintain and execute on-device and emulator QA suites covering all 7 language modes, code-mixing, and edge-case notification formats.

### 5.2 Legion 5 Pro — Primary Orchestrator & Windows Companion Responsibilities (`REQ-WIN-*` / `REQ-AI-*`)
- **`REQ-WIN-01 (Windows Desktop Companion)`**: Provide a native Windows 11 desktop application (`PySide6 6.12.0`) featuring live notification/timeline review, epistemic uncertainty & reality-check inspector, memory provenance/correction editor, and reply drafting studio.
- **`REQ-WIN-02 (Zero Auto-Send Enforcement)`**: The Windows Companion and Android Companion must have **zero automated message-sending pathways**; user review and manual copy/confirm action is mandatory.
- **`REQ-AI-01 (Local AI Execution & Benchmarking)`**: Execute primary reasoning and multilingual understanding locally on the Legion 5 Pro (Ryzen 7 260 + RTX 5050 8 GB VRAM) within a `6,600 MiB` VRAM ceiling.

---

## 6. First Working Vertical Slice (`REQ-VSLICE-01`)

The first end-to-end deliverable must demonstrate the complete, non-mocked pipeline:
1. **Android Notification** captured on device/emulator $\rightarrow$
2. **Message Extraction** (preserving verbatim text + `SHA-256`) $\rightarrow$
3. **Contact Identification** (matching Android contact + cross-script `PEOPLE` alias) $\rightarrow$
4. **Relevant Memory Retrieval** (`Memory Integrity Engine` + `Conversation Timeline Engine`) $\rightarrow$
5. **Language Understanding** (across the 7 authorized modes + code-mixing) $\rightarrow$
6. **Contextual Reasoning** (6 Pillars + `Contextual Uncertainty Engine` + `Reality-Checking Engine`) $\rightarrow$
7. **Personalized Reply Recommendation** (`Goal-Aware Response Engine` + `COMMUNICATION DNA` + `MODEL NEUTRALIZER`) $\rightarrow$
8. **User Review** in the Windows Desktop Companion.

---

## 7. Measurable Acceptance Criteria

| Criterion ID | Metric | Target Threshold |
| :--- | :--- | :--- |
| **`AC-01`** | **Raw Message Preservation** | `100%` byte-for-byte `SHA-256` match between Android `StatusBarNotification` payload and stored `raw_events.raw_text_immutable`. |
| **`AC-02`** | **Contract Conformance** | `100%` of cross-device API requests and responses validate against `/contracts/v1/*.schema.json` using `jsonschema Draft 2020-12`. |
| **`AC-03`** | **7-Mode Multilingual Accuracy** | `>= 95%` accuracy on language-mode tagging and pragmatic intent extraction across the 210-case golden corpus (`en`, `hi-Latn`, `hi-Deva`, `ml-Latn`, `ml-Mlym`, `te-Latn`, `te-Telu` + code-mixed). |
| **`AC-04`** | **Epistemic Provenance & Quarantine** | `100%` of stored memories have a valid `epistemic_class` and provenance record; `100%` of simulated acute venting inputs are flagged `EMOTIONAL_TRANSIENT`. |
| **`AC-05`** | **Anti-Sycophancy & Uncertainty Calibration** | `>= 2` competing hypotheses generated on all ambiguous test cases; `100%` of unsupported user assumptions challenged by `Reality-Checking Engine`. |
| **`AC-06`** | **Hardware Resource Envelope (Legion 5 Pro)** | Peak RTX 5050 VRAM `<= 6,600 MiB`; PSYCHE process tree RAM `<= 2,500 MiB`; end-to-end vertical slice latency `< 3.5 seconds`. |
| **`AC-07`** | **Prompt-Injection Immunity** | `0%` unauthorized state mutation or instruction override across the adversarial notification injection test suite. |
