# PSYCHE AI — Companion API Contracts & Schema Specification (`v1.0.0`)

> **Owner**: Legion 5 Pro Principal Orchestrator  
> **Consumers**: Lenovo LOQ Android Companion (`/android-app/`) & Legion 5 Pro Windows Desktop Companion (`/windows-companion/`)  
> **Schema Standard**: JSON Schema Draft 2020-12 (`https://json-schema.org/draft/2020-12/schema`)

---

## 1. Contract Inventory

| File | Schema ID | Purpose |
| :--- | :--- | :--- |
| [`common.schema.json`](./common.schema.json) | `https://psyche.local/contracts/v1/common.schema.json` | Shared primitives (`UuidV7`, `TimestampUtc`, `Sha256Hex`, `Base64Signature`), strict 7-mode `LanguageMode` enum, 4-tier `EpistemicClass` enum, `QuarantineStatus`, and `RelationshipTier`. |
| [`device_pairing.schema.json`](./device_pairing.schema.json) | `https://psyche.local/contracts/v1/device_pairing.schema.json` | Out-of-band QR challenge + 6-digit SAS mutual TLS 1.3 and Ed25519 certificate pinning handshake (`PSYCHE FORTRESS`). |
| [`notification_ingest.schema.json`](./notification_ingest.schema.json) | `https://psyche.local/contracts/v1/notification_ingest.schema.json` | Android $\rightarrow$ Windows batch notification ingestion, verbatim `raw_text_immutable` preservation, `SHA-256` verification, and per-event durable ACKs. |
| [`contact_sync.schema.json`](./contact_sync.schema.json) | `https://psyche.local/contracts/v1/contact_sync.schema.json` | Synchronizes Android `ContactsContract` lookup keys, salted E.164 phone hashes, and cross-script aliases with `PEOPLE AND MEMORY`. |
| [`memory_record.schema.json`](./memory_record.schema.json) | `https://psyche.local/contracts/v1/memory_record.schema.json` | `Memory Integrity Engine` record format (`VERIFIED_FACT`, `USER_REPORT`, `OBSERVATION`, `AI_HYPOTHESIS`), provenance, contradictions, emotional quarantine, and revision chains. |
| [`timeline_state.schema.json`](./timeline_state.schema.json) | `https://psyche.local/contracts/v1/timeline_state.schema.json` | `Conversation Timeline Engine` state (`OBSERVED_EVENT` vs. `INFERRED_EVENT`, `open_loops`, and communication pattern anomalies). |
| [`intelligence_synthesis.schema.json`](./intelligence_synthesis.schema.json) | `https://psyche.local/contracts/v1/intelligence_synthesis.schema.json` | Complete 6-Pillar + 5-Safeguard + `MODEL NEUTRALIZER` synthesis output with mandatory `requires_user_review: true` and `auto_send_permitted: false`. |
| [`presence_heartbeat.schema.json`](./presence_heartbeat.schema.json) | `https://psyche.local/contracts/v1/presence_heartbeat.schema.json` | `PSYCHE PRESENCE` cross-device availability, DND status, and sync mode negotiation. |

---

## 2. Companion Transport & REST/WebSocket Endpoints

All endpoints are hosted locally on the Legion 5 Pro Windows Desktop Companion gateway (default port `8443` over **TLS 1.3 with Mutual Certificate Authentication**). Cleartext HTTP is never permitted.

### 2.1 Mandatory Request Headers (Post-Pairing)
- `Content-Type: application/json; charset=utf-8`
- `X-Psyche-Schema-Version: 1.0.0`
- `X-Psyche-Device-Id: <UuidV7>`
- `X-Psyche-Client-Cert-Sha256: <Sha256Hex>`

### 2.2 Endpoint Table

| Method & Path | Request Schema `$defs` | Response Schema `$defs` | Description |
| :--- | :--- | :--- | :--- |
| `POST /api/v1/pairing/confirm` | `device_pairing.schema.json#/$defs/PairingConfirmRequest` | `device_pairing.schema.json#/$defs/PairingConfirmResponse` | Completes QR + 6-digit SAS pairing and pins Ed25519 + mTLS certificates. |
| `POST /api/v1/ingest/notifications` | `notification_ingest.schema.json#/$defs/NotificationIngestRequest` | `notification_ingest.schema.json#/$defs/NotificationIngestResponse` | Ingests 1–100 captured Android notifications and returns durable SQLite WAL ACKs. |
| `POST /api/v1/contacts/sync` | `contact_sync.schema.json#/$defs/ContactSyncRequest` | `contact_sync.schema.json#/$defs/ContactSyncResponse` | Syncs Android contacts and cross-script aliases; returns canonical `person_id` mappings. |
| `POST /api/v1/presence/heartbeat` | `presence_heartbeat.schema.json#/$defs/PresenceHeartbeatRequest` | `presence_heartbeat.schema.json#/$defs/PresenceHeartbeatResponse` | Exchanges mobile/desktop presence state and sync throttling directives. |

---

## 3. Lenovo LOQ Implementation Checklist

When implementing `/android-app/` on the Lenovo LOQ:
1. **Strict Language Tagging**: Use only the 8 enum values defined in `common.schema.json#/$defs/LanguageMode` (`en`, `hi-Latn`, `hi-Deva`, `ml-Latn`, `ml-Mlym`, `te-Latn`, `te-Telu`, `out_of_scope`).
2. **Verbatim Preservation**: Compute `raw_text_sha256` directly over the UTF-8 bytes of `raw_text_immutable` before queueing. Never trim, lowercase, or transliterate `raw_text_immutable`.
3. **Security Flags**: Every `NotificationEventItem` must set `security.untrusted_external_input = true` and `security.otp_or_sensitive_filtered = true`.
4. **Offline Queue Retention**: Retain events in the encrypted Android SQLite queue until their `event_id` is returned in `NotificationIngestResponse.acked_event_ids` or `duplicate_event_ids`.
