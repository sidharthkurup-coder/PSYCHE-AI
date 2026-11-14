"""Cryptographic Python Android Companion Simulator exercising live Gateway & Fortress contracts."""

from __future__ import annotations

import base64
from datetime import datetime, timezone
import json
from pathlib import Path
import secrets
import sqlite3
from typing import Any

from core.contracts.validator import (
    compute_sha256_hex,
    detect_language_modes_and_spans,
    is_sensitive_or_otp_notification,
)
from core.storage.database import generate_uuidv7
from core.subsystems.fortress.crypto_vault import AES256GCMCipher
from core.subsystems.fortress.pairing import (
    canonical_batch_bytes,
    canonical_contact_sync_bytes,
    canonical_event_bytes,
    canonical_pairing_confirm_bytes,
    canonical_presence_heartbeat_bytes,
    derive_sas_6digit_and_hmac,
    ed25519_sign,
    generate_ed25519_keypair,
    generate_x25519_keypair,
    x25519_derive_shared_secret,
)

DEFAULT_ALLOWED_PACKAGES: frozenset[str] = frozenset(
    {
        "com.whatsapp",
        "org.telegram.messenger",
        "org.thoughtcrime.securesms",
        "com.google.android.apps.messaging",
        "com.instagram.android",
    }
)


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _resp_text(resp: Any) -> str:
    if hasattr(resp, "text"):
        return str(resp.text)
    raw = getattr(resp, "body", b"")
    if isinstance(raw, (bytes, bytearray)):
        return bytes(raw).decode("utf-8", errors="replace")
    return str(raw)


def _safe_json(resp: Any) -> dict[str, Any]:
    txt = _resp_text(resp).strip()
    if not txt:
        return {}
    return json.loads(txt)


def _normalize_phone(phone: str) -> str:
    cleaned: list[str] = []
    for idx, ch in enumerate(phone.strip()):
        if ch.isdigit() or (idx == 0 and ch == "+"):
            cleaned.append(ch)
    return "".join(cleaned)


class AndroidCompanionSimulator:
    """Simulates the Android Companion device cryptographically against PsycheGatewayService."""

    def __init__(
        self,
        *,
        gateway_client: Any,
        queue_db_path: Path,
        windows_tls_cert_sha256: str,
        android_tls_cert_sha256: str,
        device_name: str = "Pixel 9 Companion",
        windows_host_endpoint: str = "https://127.0.0.1:8443",
        allowlisted_packages: set[str] | frozenset[str] | None = None,
    ) -> None:
        self.gateway = gateway_client
        self.queue_db_path = Path(queue_db_path)
        self.windows_tls_cert_sha256 = windows_tls_cert_sha256
        self.android_tls_cert_sha256 = android_tls_cert_sha256
        self.device_name = device_name
        self.windows_host_endpoint = windows_host_endpoint
        self.allowlisted_packages = (
            frozenset(allowlisted_packages)
            if allowlisted_packages is not None
            else DEFAULT_ALLOWED_PACKAGES
        )

        self._ed_priv, self._ed_pub = generate_ed25519_keypair()
        self.android_ed25519_pub_b64 = base64.b64encode(self._ed_pub).decode("ascii")
        self.device_id: str | None = None
        self.last_sas_6digit: str | None = None

        self.dropped_otp_count: int = 0
        self.ignored_package_count: int = 0

        key_ba = bytearray(secrets.token_bytes(32))
        try:
            self._queue_cipher = AES256GCMCipher(key_ba)
        finally:
            for i in range(len(key_ba)):
                key_ba[i] = 0

        self.queue_db_path.parent.mkdir(parents=True, exist_ok=True)
        self._queue_conn = sqlite3.connect(str(self.queue_db_path))
        self._queue_conn.row_factory = sqlite3.Row
        self._queue_conn.execute(
            """
            CREATE TABLE IF NOT EXISTS offline_queue (
                batch_id TEXT PRIMARY KEY,
                nonce_b64 TEXT NOT NULL,
                ciphertext_b64 TEXT NOT NULL,
                sync_state TEXT NOT NULL,
                created_at_utc TEXT NOT NULL
            )
            """
        )
        self._queue_conn.commit()

    def close(self) -> None:
        self._queue_cipher.zeroize_and_lock()
        self._queue_conn.close()

    def pair_with_windows(self) -> dict[str, Any]:
        """Executes ephemeral X25519 ECDH + 6-digit SAS derivation + Ed25519 confirmation."""
        init_resp = self.gateway.post(
            "/v1/pair/init",
            json_body={
                "windows_host_endpoint": self.windows_host_endpoint,
                "windows_tls_cert_sha256": self.windows_tls_cert_sha256,
                "ttl_seconds": 300,
            },
        )
        if init_resp.status_code != 200:
            raise RuntimeError(f"/v1/pair/init failed ({init_resp.status_code}): {_resp_text(init_resp)}")
        qr = init_resp.json()

        ax_priv, ax_pub = generate_x25519_keypair()
        shared = x25519_derive_shared_secret(
            ax_priv, base64.b64decode(qr["windows_x25519_ephemeral_pub_b64"])
        )
        sas_6digit, sas_hmac_b64 = derive_sas_6digit_and_hmac(
            shared_secret=shared,
            pairing_nonce=base64.b64decode(qr["pairing_nonce_b64"]),
            windows_tls_cert_sha256=self.windows_tls_cert_sha256,
            android_ed25519_pub_b64=self.android_ed25519_pub_b64,
            pairing_session_id=qr["pairing_session_id"],
        )

        device_id = generate_uuidv7()
        req = {
            "schema_version": "1.0.0",
            "pairing_session_id": qr["pairing_session_id"],
            "device_id": device_id,
            "device_name": self.device_name,
            "android_ed25519_pub_b64": self.android_ed25519_pub_b64,
            "android_x25519_ephemeral_pub_b64": base64.b64encode(ax_pub).decode("ascii"),
            "android_tls_cert_sha256": self.android_tls_cert_sha256,
            "sas_verification_code_hmac_b64": sas_hmac_b64,
            "ed25519_signature": "",
            "requested_at_utc": _utc_now_iso(),
        }
        req["ed25519_signature"] = base64.b64encode(
            ed25519_sign(self._ed_priv, canonical_pairing_confirm_bytes(req))
        ).decode("ascii")

        confirm_resp = self.gateway.post(
            "/v1/pair/confirm",
            json_body=req,
            headers={"X-User-Confirmed-SAS": sas_6digit},
        )
        if confirm_resp.status_code != 200:
            raise RuntimeError(
                f"/v1/pair/confirm failed ({confirm_resp.status_code}): {_resp_text(confirm_resp)}"
            )
        payload = confirm_resp.json()
        self.device_id = device_id
        self.last_sas_6digit = sas_6digit
        payload["sas_6digit"] = sas_6digit
        return payload

    def sync_contacts(self, contacts: list[dict[str, Any]]) -> dict[str, Any]:
        """Normalizes phone hashes, signs ContactSyncRequest, and posts to /v1/contacts/sync."""
        if not self.device_id:
            raise RuntimeError("Device must pair_with_windows() before syncing contacts")

        now_utc = _utc_now_iso()
        normalized_contacts: list[dict[str, Any]] = []
        for idx, c in enumerate(contacts):
            lookup = c.get("android_contact_lookup_key") or f"sim-contact-{idx}-{generate_uuidv7()[:8]}"
            display_name = c["display_name"]

            phone_hashes = list(c.get("normalized_phone_hashes") or [])
            for raw_num in c.get("phone_numbers", []):
                norm = _normalize_phone(raw_num)
                if norm:
                    phone_hashes.append(compute_sha256_hex(norm))

            aliases = []
            for al in c.get("aliases", []):
                if isinstance(al, dict):
                    aliases.append(
                        {
                            "alias_text": al["alias_text"],
                            "language_mode": al.get("language_mode")
                            or detect_language_modes_and_spans(al["alias_text"])[0][0],
                            "match_confidence": float(al.get("match_confidence", 0.98)),
                        }
                    )
                elif isinstance(al, str):
                    modes, _ = detect_language_modes_and_spans(al)
                    aliases.append(
                        {
                            "alias_text": al,
                            "language_mode": modes[0],
                            "match_confidence": 0.95,
                        }
                    )

            normalized_contacts.append(
                {
                    "android_contact_lookup_key": lookup,
                    "display_name": display_name,
                    "normalized_phone_hashes": phone_hashes,
                    "aliases": aliases,
                    "starred_on_android": bool(c.get("starred_on_android", False)),
                    "updated_at_utc": c.get("updated_at_utc") or now_utc,
                }
            )

        req = {
            "schema_version": "1.0.0",
            "sync_batch_id": generate_uuidv7(),
            "device_id": self.device_id,
            "sent_at_utc": now_utc,
            "ed25519_signature": "",
            "contacts": normalized_contacts,
        }
        req["ed25519_signature"] = base64.b64encode(
            ed25519_sign(self._ed_priv, canonical_contact_sync_bytes(req))
        ).decode("ascii")

        resp = self.gateway.post("/v1/contacts/sync", json_body=req)
        if resp.status_code != 200:
            raise RuntimeError(f"/v1/contacts/sync failed ({resp.status_code}): {_resp_text(resp)}")
        return resp.json()

    def _enqueue_encrypted_batch(self, batch: dict[str, Any], sync_state: str = "PENDING") -> None:
        batch_id = batch["batch_id"]
        raw_json = json.dumps(batch, ensure_ascii=False).encode("utf-8")
        envelope = self._queue_cipher.encrypt(raw_json, aad=batch_id.encode("utf-8"))
        # _ENVELOPE_MAGIC is 8 bytes followed by 12-byte AES-GCM nonce
        nonce_b64 = base64.b64encode(envelope[8:20]).decode("ascii")
        ciphertext_b64 = base64.b64encode(envelope).decode("ascii")
        self._queue_conn.execute(
            """
            INSERT OR REPLACE INTO offline_queue (
                batch_id, nonce_b64, ciphertext_b64, sync_state, created_at_utc
            ) VALUES (?, ?, ?, ?, ?)
            """,
            (batch_id, nonce_b64, ciphertext_b64, sync_state, batch["sent_at_utc"]),
        )
        self._queue_conn.commit()

    def queue_count(self) -> int:
        row = self._queue_conn.execute("SELECT COUNT(*) FROM offline_queue").fetchone()
        return int(row[0]) if row else 0

    def get_queue_states(self) -> list[dict[str, str]]:
        rows = self._queue_conn.execute(
            "SELECT batch_id, sync_state FROM offline_queue ORDER BY created_at_utc ASC, rowid ASC"
        ).fetchall()
        return [{"batch_id": r["batch_id"], "sync_state": r["sync_state"]} for r in rows]

    def capture_notification(
        self,
        *,
        package_name: str,
        raw_title: str,
        raw_text: str,
        conversation_key: str,
        android_contact_lookup_key: str | None = None,
        phone_number: str | None = None,
        is_group_conversation: bool = False,
        group_title: str | None = None,
        notification_category: str = "msg",
        auto_flush: bool = True,
        posted_at_utc: str | None = None,
    ) -> dict[str, Any]:
        """Simulates NotificationListenerService ingestion with pre-persistence OTP/banking drop."""
        if not self.device_id:
            raise RuntimeError("Device must pair_with_windows() before capturing notifications")

        if package_name not in self.allowlisted_packages:
            self.ignored_package_count += 1
            return {"status": "IGNORED_PACKAGE", "event_id": None}

        # CRITICAL SECURITY INVARIANT: Drop sensitive OTP/banking notifications BEFORE SQLite or network
        if is_sensitive_or_otp_notification(raw_text, package_name):
            self.dropped_otp_count += 1
            return {"status": "DROPPED_SENSITIVE_OR_OTP", "event_id": None}

        now_utc = posted_at_utc or _utc_now_iso()
        modes, spans = detect_language_modes_and_spans(raw_text)
        phone_sha = (
            compute_sha256_hex(_normalize_phone(phone_number)) if phone_number else None
        )
        ev_id = generate_uuidv7()
        ev = {
            "event_id": ev_id,
            "package_name": package_name,
            "notification_category": notification_category,
            "conversation_key": conversation_key,
            "is_group_conversation": is_group_conversation,
            "group_title": group_title if is_group_conversation else None,
            "direction": "INBOUND",
            "sender": {
                "raw_title": raw_title,
                "android_contact_lookup_key": android_contact_lookup_key,
                "normalized_phone_sha256": phone_sha,
                "candidate_person_ids": [],
                "identity_ambiguity": False,
            },
            "content": {
                "raw_text_immutable": raw_text,
                "raw_text_sha256": compute_sha256_hex(raw_text),
                "detected_language_modes": modes,
                "token_language_spans": spans,
            },
            "posted_at_utc": now_utc,
            "security": {
                "untrusted_external_input": True,
                "otp_or_sensitive_filtered": True,
                "ed25519_event_signature": "",
            },
        }
        ev["security"]["ed25519_event_signature"] = base64.b64encode(
            ed25519_sign(self._ed_priv, canonical_event_bytes(ev))
        ).decode("ascii")

        batch_id = generate_uuidv7()
        batch = {
            "schema_version": "1.0.0",
            "batch_id": batch_id,
            "device_id": self.device_id,
            "sent_at_utc": now_utc,
            "batch_ed25519_signature": "",
            "events": [ev],
        }
        batch["batch_ed25519_signature"] = base64.b64encode(
            ed25519_sign(self._ed_priv, canonical_batch_bytes(batch))
        ).decode("ascii")

        self._enqueue_encrypted_batch(batch, sync_state="PENDING")
        if not auto_flush:
            return {"status": "QUEUED_ENCRYPTED", "event_id": ev_id, "batch_id": batch_id}

        flush_res = self.flush_offline_queue()
        if flush_res["status"] == "HOLD_UNTIL_UNLOCKED":
            return {
                "status": "HOLD_UNTIL_UNLOCKED",
                "event_id": ev_id,
                "batch_id": batch_id,
                "http_status": flush_res.get("http_status"),
            }
        if flush_res["flushed_batches"] >= 1:
            return {
                "status": "DELIVERED",
                "event_id": ev_id,
                "batch_id": batch_id,
                "gateway_responses": flush_res["gateway_responses"],
            }
        return {"status": "QUEUED_ENCRYPTED", "event_id": ev_id, "batch_id": batch_id}

    def flush_offline_queue(self) -> dict[str, Any]:
        """Decrypts and transmits pending encrypted batches; transitions to HOLD_UNTIL_UNLOCKED on VAULT_LOCKED."""
        if not self.device_id:
            raise RuntimeError("Device must pair_with_windows() before flushing offline queue")

        rows = self._queue_conn.execute(
            "SELECT batch_id, ciphertext_b64 FROM offline_queue ORDER BY created_at_utc ASC, rowid ASC"
        ).fetchall()
        flushed = 0
        responses: list[dict[str, Any]] = []

        for r in rows:
            batch_id = r["batch_id"]
            envelope = base64.b64decode(r["ciphertext_b64"])
            plaintext_bytes = self._queue_cipher.decrypt(envelope, aad=batch_id.encode("utf-8"))
            batch = json.loads(plaintext_bytes.decode("utf-8"))

            # Re-stamp outer transmission timestamp and batch signature at actual delivery time
            batch["sent_at_utc"] = _utc_now_iso()
            batch["batch_ed25519_signature"] = base64.b64encode(
                ed25519_sign(self._ed_priv, canonical_batch_bytes(batch))
            ).decode("ascii")

            resp = self.gateway.post("/v1/notifications/ingest", json_body=batch)
            resp_json = _safe_json(resp)
            if resp.status_code == 200:
                self._queue_conn.execute("DELETE FROM offline_queue WHERE batch_id = ?", (batch_id,))
                self._queue_conn.commit()
                flushed += 1
                responses.append(resp_json)
            elif resp.status_code in (423, 503) or resp_json.get("error_code") == "VAULT_LOCKED":
                self._queue_conn.execute("UPDATE offline_queue SET sync_state = 'HOLD_UNTIL_UNLOCKED'")
                self._queue_conn.commit()
                return {
                    "status": "HOLD_UNTIL_UNLOCKED",
                    "flushed_batches": flushed,
                    "pending_count": self.queue_count(),
                    "http_status": resp.status_code,
                    "gateway_responses": responses,
                }
            else:
                return {
                    "status": "FLUSH_ERROR",
                    "flushed_batches": flushed,
                    "pending_count": self.queue_count(),
                    "http_status": resp.status_code,
                    "error": resp_json,
                }

        return {
            "status": "FLUSHED_ALL",
            "flushed_batches": flushed,
            "pending_count": self.queue_count(),
            "gateway_responses": responses,
        }

    def send_presence_heartbeat(
        self,
        *,
        user_presence_state: str = "ACTIVE_MOBILE",
        dnd_active: bool = False,
        battery_percent: int = 85,
    ) -> dict[str, Any]:
        """Signs and sends /v1/presence/heartbeat reflecting encrypted offline queue depth."""
        if not self.device_id:
            raise RuntimeError("Device must pair_with_windows() before sending heartbeat")
        hb = {
            "schema_version": "1.0.0",
            "device_id": self.device_id,
            "timestamp_utc": _utc_now_iso(),
            "user_presence_state": user_presence_state,
            "dnd_active": dnd_active,
            "pending_queue_count": self.queue_count(),
            "battery_percent": battery_percent,
            "ed25519_signature": "",
        }
        hb["ed25519_signature"] = base64.b64encode(
            ed25519_sign(self._ed_priv, canonical_presence_heartbeat_bytes(hb))
        ).decode("ascii")
        resp = self.gateway.post("/v1/presence/heartbeat", json_body=hb)
        if resp.status_code != 200:
            raise RuntimeError(
                f"/v1/presence/heartbeat failed ({resp.status_code}): {_resp_text(resp)}"
            )
        return resp.json()

    def request_synthesis(
        self,
        event_id: str,
        *,
        user_explicit_assumption: str | None = None,
        reference_now_utc: str | None = None,
    ) -> dict[str, Any]:
        """Requests an IntelligenceSynthesisPacket for an ingested event via Gateway."""
        body: dict[str, Any] = {}
        if user_explicit_assumption is not None:
            body["user_explicit_assumption"] = user_explicit_assumption
        if reference_now_utc is not None:
            body["reference_now_utc"] = reference_now_utc
        resp = self.gateway.post(f"/v1/syntheses/{event_id}", json_body=body)
        if resp.status_code != 200:
            raise RuntimeError(
                f"/v1/syntheses/{event_id} failed ({resp.status_code}): {_resp_text(resp)}"
            )
        return resp.json()
