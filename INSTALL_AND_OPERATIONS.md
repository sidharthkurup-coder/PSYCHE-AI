# PSYCHE AI — Installation, Operations & Security Runbook

> **Primary Machine**: Lenovo Legion 5 Pro (Windows 11, Ryzen 7 260, RTX 5050 8 GB VRAM, 16 GB DDR5)  
> **Runtime Baseline**: Python `3.14.5`, PySide6 `6.12.0`, Starlette `1.8.0`, Uvicorn `0.54.0`, Websockets `17.2`, SQLite `3.50.4`, NumPy `2.5.4`, `jsonschema 4.26.0`, OpenSSL CLI (`C:\msys64\ucrt64\bin\openssl.exe`)

---

## 1. Local-First Environment Verification

1. Clone the repository into your workspace root (`PSYCHE-AI`) and run the complete automated verification suite from outside or inside the sandbox with explicit `pyproject.toml`:

```powershell
python -m pytest -c pyproject.toml tests -v
```

2. Verify the 210-case 7-mode multilingual corpus and Tier-0 analytical benchmark:

```powershell
python -c "from eval_multilingual import evaluate_golden_corpus; print(evaluate_golden_corpus()['accuracy'], evaluate_golden_corpus()['passed_cases'])"
python -c "from local_ai.benchmark import run_multilingual_benchmark; print(run_multilingual_benchmark()['language_mode_accuracy_pct'], run_multilingual_benchmark()['contract_schema_compliance_pct'])"
```

---

## 2. Cryptographic Storage & mTLS 1.3 Gateway Startup

1. **DPAPI Vault & Encrypted SQLite (`PsycheFortressVault` + `PsycheDatabase`)**:
   - Store keys, SQLite database files, and NumPy `.npy` vector embeddings **outside** the Git repository (for example under `%LOCALAPPDATA%\PsycheAI\vault\`). Never commit `.key`, `.dpapi`, `.pem`, `.crt`, `.sqlite3`, `.npy`, or `.gguf` files inside the repository (`tests/test_repo_security_hygiene.py` enforces this rule).
   - `PsycheFortressVault(key_file_path=...)` automatically seals the 256-bit AES-GCM master key with Windows DPAPI (`crypt32.dll`) on first boot and unseals only in protected RAM buffers.

2. **ECDSA P-256 Mutual-TLS 1.3 Certificates (`windows_companion/gateway/mtls_certs.py`)**:
   - Call `provision_mtls_certificates(cert_dir)` to generate Root CA, Windows server cert/key, and Android client cert/key with 64-char SHA-256 fingerprints.
   - `create_mtls_ssl_context(bundle, require_client_cert=True)` enforces `ssl.TLSVersion.TLSv1_3` and `ssl.CERT_REQUIRED`.

3. **Running the Windows Local Companion Gateway (`windows_companion/gateway/server.py`)**:
   - `create_gateway_app(db=db, windows_tls_cert_sha256=bundle["server_cert_sha256"], enforce_clock_skew=True)` exposes:
     - `GET /v1/health`
     - `POST /v1/pair/init`, `POST /v1/pair/confirm`
     - `POST /v1/contacts/sync`
     - `POST /v1/notifications/ingest`
     - `POST /v1/presence/heartbeat`
     - `POST /v1/syntheses/{event_id}`, `POST /v1/syntheses/{synthesis_id}/review`
     - `WS /v1/ws/events`

---

## 3. Windows 11 Desktop Companion UI (`windows_companion/ui/app.py`)

- Launch the desktop window using `launch_desktop_companion(db=db)` or embed `PsycheDesktopMainWindow(db=db)`.
- Key operator controls:
  - **Privacy Blur Toggle**: Masks contact names, timeline text, open loops, and memories via `mask_pii_text`.
  - **Idle Timeout Auto-Lock**: Configurable `QTimer` automatically locks the vault and displays the locked overlay after inactivity.
  - **Memory Integrity Ledger**: Release `EMOTIONAL_TRANSIENT` quarantine after review, create superseding `v2` corrections without destroying provenance, or delete a memory (zeroizing vectors).
  - **Reply Review Studio**: Always enforces `requires_user_review = True` and `auto_send_permitted = False`. Editing and clicking `Approve / Edit & Copy to Clipboard` updates `COMMUNICATION DNA` and copies to clipboard for manual pasting.
  - **EMERGENCY PANIC LOCK**: Immediately calls `db.vault.panic_lock()`, zeroes key buffers and RAM vector arrays (`0.0`), hides UI contents, and causes the Gateway to return `423 VAULT_LOCKED`.

---

## 4. Local AI Runtime & Optional GGUF LLM Upgrade (`core/subsystems/local_core/runtime.py`)

- **Default Tier-0 Engine (Active Offline)**: `local/psyche-analytical-core-v1` runs in-process at `< 50 ms` latency with `$0.00` cloud spend and `external_providers_enabled = False`.
- **Optional Tier-1/Tier-2 `llama-server.exe` Upgrade**:
  - Evaluated candidate GGUF models for the RTX 5050 (`8,151 MiB` total VRAM, `6,600 MiB` PSYCHE cap):
    - Primary: `Qwen2.5-7B-Instruct-Q4_K_M` (`4,680 MiB` weights + `900 MiB` KV cache)
    - Secondary fast tier: `Qwen2.5-3B-Instruct-Q4_K_M` (`2,050 MiB` weights + `450 MiB` KV cache)
  - Note: `.gguf` downloads remain `PENDING_OWNER_APPROVAL`. Once approved and downloaded locally outside the repo, start `llama-server.exe` bound strictly to `http://127.0.0.1:8089`.

---

## 5. Android Companion App (`android-app/`) & Cryptographic Simulator (`android_app_simulator/`)

- **Cryptographic Python Simulator**: `android_app_simulator.AndroidCompanionSimulator` performs real X25519 ECDH, 6-digit SAS verification, Ed25519 signing, pre-persistence OTP filtering, and AES-256-GCM encrypted SQLite queueing (`HOLD_UNTIL_UNLOCKED` on `423`/`503 VAULT_LOCKED`).
- **Native Kotlin + Jetpack Compose Project (`android-app/`)**:
  - Static security audit runs in `tests/test_phase6_android_companion_and_simulator.py`.
  - To compile an `.apk` on Android build tooling, install JDK 17 + Android SDK Platform 35 + Android Gradle Plugin `8.7.2` and run `./gradlew assembleDebug` inside `android-app/`.
  - Forbidden permissions (`SEND_SMS`, `READ_SMS`, `CALL_PHONE`, `BIND_ACCESSIBILITY_SERVICE`) are excluded from `AndroidManifest.xml`, and `cleartextTrafficPermitted="false"` is enforced.
