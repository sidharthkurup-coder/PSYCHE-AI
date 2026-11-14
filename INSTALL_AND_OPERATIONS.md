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

- Launch the desktop window using `launch_desktop_companion(db=db)` or embed `PsycheDesktopMainWindow(db=db, orchestrator=service.orchestrator, gateway_service=service)`. Passing `gateway_service` registers an automatic live event listener so incoming Android syncs, ingested notifications, and new syntheses update all desktop panes without manual reloads.
- Key operator controls:
  - **Privacy Blur Toggle**: Masks contact names, detail headers, timeline text, open loops, memories, `pillars_view`, `uncertainty_view`, `reality_check_view`, and `reply_editor` via `mask_pii_text` and `[HIDDEN BY PRIVACY BLUR — SHA-256 VERIFIED]`.
  - **Idle Timeout Auto-Lock**: Configurable `QTimer` automatically locks the vault and displays the locked overlay after inactivity.
  - **Memory Integrity Ledger**: Release `EMOTIONAL_TRANSIENT` quarantine after review, create superseding `v2` corrections without destroying provenance, or delete a memory (zeroizing vectors). Quarantined records (`EMOTIONAL_TRANSIENT`, `IDENTITY_AMBIGUOUS`, `SUSPECTED_INJECTION`) are isolated from unquarantined `verified_facts` and confidence boosts.
  - **Reply Review Studio**: Always enforces `requires_user_review = True` and `auto_send_permitted = False`. Renders competing alternative explanations (`hypothesis_id`, `plausibility_score`, `explanation`), reality check prompts (`feelings_vs_facts_distinction`, `challenged_ai_assumptions`, `independent_thinking_prompt`), and strategy-labeled candidates (`strategy_label`, `comm_dna_match_score`). Editing and clicking `Approve / Edit & Copy to Clipboard` updates `COMMUNICATION DNA` and copies to clipboard for manual pasting.
  - **EMERGENCY PANIC LOCK**: Immediately calls `db.vault.panic_lock()`, zeroes key buffers and RAM vector arrays (`0.0`), hides UI contents, and causes the Gateway to return `423 VAULT_LOCKED`.

---

## 4. Local AI Runtime & Optional GGUF LLM Upgrade (`core/subsystems/local_core/runtime.py`)

- **Default Tier-0 Engine (Active Offline)**: `local/psyche-analytical-core-v1` runs in-process at `~15.7 ms` mean latency (`max ~60.3 ms`) with `47.95 MiB` RSS, `$0.00` cloud spend, and `external_providers_enabled = False`.
- **Optional Tier-1/Tier-2 `llama-server.exe` Upgrade**:
  - Loopback connections (`http://127.0.0.1:8089`) explicitly bypass Windows HTTP proxies using `urllib.request.ProxyHandler({})` (`_LOOPBACK_OPENER`), and skip local LLM inference whenever `detect_prompt_injection_attempt` flags untrusted input.
  - When `prefer_llama_server_if_online=True` and a loopback `/v1/chat/completions` JSON response is returned, `PsycheIntelligenceOrchestrator` refines `pragmatic_subtext` and `emotional_state_summary` and neutralizes any `R3_LLAMA` reply candidate through `ModelNeutralizerAndIdentityLock` and `CommunicationDnaPillarEngine`.
  - Evaluated candidate GGUF models for the RTX 5050 (`8,151 MiB` total VRAM, `~6,434 MiB` free VRAM, `6,600 MiB` PSYCHE cap, `16 GB` RAM):
    - Primary Tier-2: `Qwen2.5-7B-Instruct-Q4_K_M` (`4,680 MiB` weights + `900 MiB` KV cache = `5,580 MiB` VRAM, `620 MiB` system RAM overhead, `~793–854 MiB` VRAM headroom)
    - Secondary Fast Tier-1: `Qwen2.5-3B-Instruct-Q4_K_M` (`2,050 MiB` weights + `450 MiB` KV cache = `2,500 MiB` VRAM, `350 MiB` RAM)
  - Note: Both `llama-server.exe` and `.gguf` model weights remain `PENDING_OWNER_APPROVAL` and are not downloaded automatically.

---

## 5. Android Companion App (`android-app/`), Simulator (`android_app_simulator/`) & Known Limitations

- **Cryptographic Python Simulator**: `android_app_simulator.AndroidCompanionSimulator` performs real X25519 ECDH, 6-digit SAS verification, Ed25519 signing, pre-persistence OTP filtering, and AES-256-GCM encrypted SQLite queueing (`HOLD_UNTIL_UNLOCKED` on `423`/`503 VAULT_LOCKED`).
- **Native Kotlin + Jetpack Compose Project (`android-app/`)**:
  - Static security audit runs in `tests/test_phase6_android_companion_and_simulator.py`.
  - Forbidden permissions (`SEND_SMS`, `READ_SMS`, `CALL_PHONE`, `BIND_ACCESSIBILITY_SERVICE`) are excluded from `AndroidManifest.xml`, and `cleartextTrafficPermitted="false"` is enforced.
  - **Missing Local Android Build Tooling (Owner Approval Required to Install)**: On this Legion 5 Pro environment, `java`/`javac` (JDK 17), `gradle` / `gradlew.bat`, and the Android SDK (`ANDROID_HOME`, `sdkmanager`, `adb`, Platform 35) are currently absent (`NOT_FOUND`), and `android-app/gradle/wrapper/` is not yet generated.
  - Exact setup commands once approved (~1.8 GB total disk space + Gradle wrapper generation):
    1. Install JDK 17 (~320 MB): `winget install --id Microsoft.OpenJDK.17 -e`
    2. Install Android Studio Command-Line Tools (`cmdline-tools`) and SDK packages (~1.4 GB): `sdkmanager "platform-tools" "platforms;android-35" "build-tools;35.0.0"`
    3. Generate Gradle wrapper inside `android-app/` and build debug APK: `gradle wrapper --gradle-version 8.9 && .\gradlew.bat assembleDebug`
- **Known Limitations**:
  - Real `llama-server.exe` + `.gguf` neural inference weights are not downloaded or benchmarked against live transformer generation until owner approval is granted.
  - Native Android `.apk` compilation and on-device `NotificationListenerService` verification on physical Android hardware remain pending JDK 17 / Android SDK setup and Gradle wrapper generation.
  - `FortressKeystoreManager.kt` uses standard `KeyPairGenerator.getInstance("Ed25519")` / `"X25519"`, which natively targets Android API 33+ unless a compatibility provider is bundled for API 29–32 (`minSdk = 29`).
  - No background OS Windows Service / tray daemon autostart script is registered yet; the Gateway and PySide6 Workbench launch programmatically (`launch_desktop_companion` / `create_gateway_app`).
