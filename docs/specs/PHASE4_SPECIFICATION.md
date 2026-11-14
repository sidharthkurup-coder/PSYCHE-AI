# PSYCHE AI — Phase 4 Engineering Specification (`legion/phase4-windows-gateway-mtls`)

> **Phase**: 4 — Windows Local HTTPS/mTLS Companion Gateway  
> **Branch**: `legion/phase4-windows-gateway-mtls` (from `legion/phase3-core-fortress-presence-eval` @ `46b84c5`)  
> **Protected Baseline**: `main` (`06e9ed7`) & `/contracts/v1/*.schema.json` remain strictly unmodified.

---

## Stage 1 — Research & Discovery

1. **Mutual TLS 1.3 & Certificate Pinning on Local Wi-Fi / Loopback**:
   - RFC 8446 (TLS 1.3) mandates forward secrecy (`ECDHE`/`X25519`), AEAD ciphersuites (`TLS_AES_256_GCM_SHA384`), and single-round-trip handshake with mutual client certificate verification (`ssl.CERT_REQUIRED`).
   - Pairing binds both **X.509 DER SHA-256 certificate pinning** (`windows_tls_cert_sha256` / `android_tls_cert_sha256`) and **Ed25519 application-layer message signing**, giving defense-in-depth so even if TLS terminates locally on `127.0.0.1` or LAN, every batch, contact sync, event, and heartbeat carries an independent `Ed25519` proof.
2. **Starlette + Uvicorn ASGI Transport (`Starlette 1.8.0` / `Uvicorn 0.54.0`)**:
   - Exposes asynchronous REST endpoints (`/v1/*`) and real-time WebSocket stream (`/v1/ws/events`) over local `127.0.0.1` / LAN interfaces.
   - Note: `starlette.testclient.TestClient` requires an unbundled `httpx2` dependency in this environment, so `windows_companion/gateway/server.py` includes a self-contained, zero-external-dependency `AsgiTestClient` executing real Starlette ASGI scopes directly via `asyncio.run`.

---

## Stage 2 — Requirements Traceability Matrix

| Req ID | Requirement Summary | Target Module | Acceptance Criteria |
| :--- | :--- | :--- | :--- |
| **`REQ-AND-04`** | Mutual TLS 1.3 gateway with QR/SAS pairing, signed contact sync, signed notification batch ingest, and replay/skew rejection | `windows_companion/gateway/mtls_certs.py`, `windows_companion/gateway/server.py` | 1. All REST payloads strictly validate against `/contracts/v1/*.schema.json`.<br>2. Forged/missing signatures return HTTP `401`; replayed `batch_id` or `>120s` clock skew return HTTP `409`. |
| **`REQ-SUB-06` / `07`** | `PSYCHE FORTRESS` vault lock isolation + `PSYCHE PRESENCE` heartbeat continuation while locked | `windows_companion/gateway/server.py` | When vault is `panic_lock()`ed, `/v1/contacts/sync` & `/v1/notifications/ingest` return HTTP `423 Locked`, while `/v1/presence/heartbeat` verifies cached Ed25519 key and returns `200 OK` (`VAULT_LOCKED`, `HOLD_UNTIL_UNLOCKED`). |
| **`REQ-VSLICE-01`** | Live synthesis + user review feedback endpoints & WebSocket stream | `windows_companion/gateway/server.py` | `/v1/syntheses/{event_id}` and `/v1/syntheses/{synthesis_id}/review` invoke `PsycheIntelligenceOrchestrator` and preserve `requires_user_review = True`, `auto_send_permitted = False`. |

---

## Stage 3 & Stage 4 — Architecture & Security Mapping

- **Certificate Authority Hierarchy (`mtls_certs.py`)**:
  - Uses `C:\msys64\ucrt64\bin\openssl.exe` (`OpenSSL 3.5.2`) to provision a local ECDSA/RSA Root CA (`ca.key`/`ca.crt`), Windows Gateway server cert (`server.crt` with SAN `IP:127.0.0.1,DNS:localhost`, EKU `serverAuth`), and Android Companion client cert (`client.crt`, EKU `clientAuth`), computing exact lowercase 64-char hex SHA-256 fingerprints over X.509 DER bytes.
- **Deterministic HTTP Error Mapping**:
  - `VaultLockedError` $\rightarrow$ `423 Locked` (`VAULT_LOCKED`)
  - `PermissionError` $\rightarrow$ `401 Unauthorized` (`SIGNATURE_OR_DEVICE_UNAUTHORIZED`)
  - `ContractValidationError` (`REPLAY_BATCH_DETECTED`, `CLOCK_SKEW_EXCEEDED`) $\rightarrow$ `409 Conflict`
  - `ContractValidationError` (schema/hash/OTP violations) $\rightarrow$ `422 Unprocessable Entity`
  - `KeyError` $\rightarrow$ `404 Not Found` / `ValueError` $\rightarrow$ `400 Bad Request`

---

## Stage 5 — Differentiation

Unlike generic REST webhooks using static bearer tokens, PSYCHE's Windows Gateway enforces dual-layer **TLS 1.3 client certificate authentication + per-payload Ed25519 signatures**, **strict JSON Schema 2020-12 contract enforcement**, **`+-120s` replay defense**, and **fail-closed `423 Vault Locked`** enforcement while still issuing `HOLD_UNTIL_UNLOCKED` presence directives.
