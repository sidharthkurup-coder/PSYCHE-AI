# PSYCHE AI — Phase 6 Specification: Native Android Companion & Cryptographic Simulator

> **Branch**: `legion/phase6-android-companion`  
> **Requirements Covered**: `REQ-AND-01`, `REQ-AND-02`, `REQ-AND-03`, `REQ-AND-04`, `REQ-SEC-01`, `REQ-SEC-04`, `REQ-SEC-06`  
> **Non-Negotiable Safety Gates**: `requires_user_review = true`, `auto_send_permitted = false`, zero forbidden permissions (`SEND_SMS`, `READ_SMS`, `CALL_PHONE`, `BIND_ACCESSIBILITY_SERVICE`), pre-persistence OTP/banking drop, cleartext traffic prohibited (`usesCleartextTraffic="false"`).

---

## 1. Architecture Overview

Phase 6 delivers the complete Android ingestion surface in two coordinated layers:

1. **Native Kotlin + Jetpack Compose Android Project (`/android-app/`)**:
   - Strict zero-backup, zero-cleartext manifest (`allowBackup="false"`, `fullBackupContent="false"`, `usesCleartextTraffic="false"`, `data_extraction_rules.xml`, `network_security_config.xml`).
   - `SensitiveNotificationFilter.kt`: synchronous pre-persistence OTP/2FA/UPI/banking/Aadhaar drop executed inside `PsycheNotificationListenerService.kt` *before* touching SQLite or network queues.
   - `FortressKeystoreManager.kt`: Android Keystore `AES/GCM/NoPadding` hardware-backed queue key protection + X25519/Ed25519 pairing and canonical payload signatures.
   - `EncryptedOfflineQueue.kt`: SQLite queue storing only AES-256-GCM ciphertext (`ciphertext_b64`) and 12-byte IVs (`iv_b64`), bounded capacity, holding batches in `HOLD_UNTIL_UNLOCKED` when desktop returns `VAULT_LOCKED` (`423`/`503`).
   - `ContactResolver.kt`: `ContactsContract` display name, SHA-256 E.164 phone hashing, and cross-script alias extraction (`en`, `hi-Latn`, `hi-Deva`, `ml-Latn`, `ml-Mlym`, `te-Latn`, `te-Telu`).
   - `CompanionSyncClient.kt`: strict `TLSv1.3` mTLS client matching `/v1/*` gateway endpoints.
   - `MainActivity.kt`: Jetpack Compose UI for QR/SAS 6-digit pairing confirmation, package allowlist & sensitive filter telemetry, offline queue & presence status, and manual fallback analyzer with **clipboard-only** reply draft copying (`auto_send_permitted = false`).

2. **Python Cryptographic Android Companion Simulator (`android_app_simulator/client.py`)**:
   - Exercises the live Windows Companion Gateway (`PsycheGatewayService`) using real X25519 ECDH, 6-digit SAS verification, Ed25519 event/batch/heartbeat/contact signatures, pre-persistence OTP dropping (`is_sensitive_or_otp_notification`), AES-256-GCM encrypted SQLite `offline_queue`, `VAULT_LOCKED` `HOLD_UNTIL_UNLOCKED` buffering, and post-unlock automatic flush.

---

## 2. Verification Plan (`tests/test_phase6_android_companion_and_simulator.py`)

1. Static security & completeness audit across `/android-app/` (Manifest flags, XML rules, absence of forbidden permissions, presence of all Kotlin components, clipboard-only / `auto_send_permitted = false` guarantees).
2. End-to-end cryptographic simulator lifecycle against `PsycheGatewayService`: QR/SAS pairing, signed cross-script contact sync, pre-persistence OTP drop (verified absent in both simulator SQLite and desktop DB), multilingual notification ingestion, and synthesis verification.
3. Offline AES-256-GCM encrypted SQLite queue verification during desktop panic lock (`423 VAULT_LOCKED` -> `HOLD_UNTIL_UNLOCKED`), verifying zero plaintext leaks in SQLite and successful flush after `db.vault.unlock()`.
