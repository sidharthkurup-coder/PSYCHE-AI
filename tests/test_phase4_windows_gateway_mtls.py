"""Phase 4 Verification Tests — Windows Local HTTPS/mTLS Companion Gateway."""

from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
import hashlib
from pathlib import Path
import ssl

from core.contracts.validator import compute_sha256_hex, detect_language_modes_and_spans
from core.storage.database import PsycheDatabase, generate_uuidv7
from core.subsystems.fortress.crypto_vault import PsycheFortressVault
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
from windows_companion.gateway import (
    AsgiTestClient,
    create_gateway_app,
    create_mtls_ssl_context,
    provision_mtls_certificates,
)


def _make_unlocked_db(tmp_path: Path, name: str = "gw") -> PsycheDatabase:
    vault = PsycheFortressVault(key_file_path=tmp_path / f"{name}.key.dpapi")
    return PsycheDatabase(
        db_path=tmp_path / f"{name}.sqlite3",
        vault=vault,
        vector_path=tmp_path / f"{name}.npy",
    )


def _pair_via_gateway(
    client: AsgiTestClient,
    *,
    windows_tls_sha256: str,
    android_tls_sha256: str,
) -> tuple[str, bytes, str]:
    init_resp = client.post(
        "/v1/pair/init",
        json_body={
            "windows_host_endpoint": "https://127.0.0.1:8443",
            "windows_tls_cert_sha256": windows_tls_sha256,
            "ttl_seconds": 300,
        },
    )
    assert init_resp.status_code == 200
    qr = init_resp.json()

    ed_priv, ed_pub = generate_ed25519_keypair()
    ax_priv, ax_pub = generate_x25519_keypair()
    shared = x25519_derive_shared_secret(
        ax_priv, base64.b64decode(qr["windows_x25519_ephemeral_pub_b64"])
    )
    android_ed_pub_b64 = base64.b64encode(ed_pub).decode("ascii")
    sas_6digit, sas_hmac_b64 = derive_sas_6digit_and_hmac(
        shared_secret=shared,
        pairing_nonce=base64.b64decode(qr["pairing_nonce_b64"]),
        windows_tls_cert_sha256=windows_tls_sha256,
        android_ed25519_pub_b64=android_ed_pub_b64,
        pairing_session_id=qr["pairing_session_id"],
    )

    device_id = generate_uuidv7()
    req = {
        "schema_version": "1.0.0",
        "pairing_session_id": qr["pairing_session_id"],
        "device_id": device_id,
        "device_name": "Pixel 9 Companion",
        "android_ed25519_pub_b64": android_ed_pub_b64,
        "android_x25519_ephemeral_pub_b64": base64.b64encode(ax_pub).decode("ascii"),
        "android_tls_cert_sha256": android_tls_sha256,
        "sas_verification_code_hmac_b64": sas_hmac_b64,
        "ed25519_signature": "",
        "requested_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    req["ed25519_signature"] = base64.b64encode(
        ed25519_sign(ed_priv, canonical_pairing_confirm_bytes(req))
    ).decode("ascii")

    # Wrong SAS must return 403 REJECTED_SAS_MISMATCH without consuming valid retry flow?
    # Note: confirm_pairing preserves session on REJECTED_SAS_MISMATCH so correct SAS can confirm cleanly
    wrong_sas = "000000" if sas_6digit != "000000" else "999999"
    bad_resp = client.post(
        "/v1/pair/confirm",
        json_body=req,
        headers={"X-User-Confirmed-SAS": wrong_sas},
    )
    assert bad_resp.status_code == 403
    assert bad_resp.json()["status"] == "REJECTED_SAS_MISMATCH"

    ok_resp = client.post(
        "/v1/pair/confirm",
        json_body=req,
        headers={"X-User-Confirmed-SAS": sas_6digit},
    )
    assert ok_resp.status_code == 200
    assert ok_resp.json()["status"] == "PAIRED"
    return device_id, ed_priv, sas_6digit


def test_mtls_certificate_provisioning_and_tls13_ssl_context(tmp_path: Path) -> None:
    bundle = provision_mtls_certificates(tmp_path / "mtls")
    for key in ("ca_cert_path", "server_cert_path", "server_key_path", "client_cert_path", "client_key_path"):
        assert Path(bundle[key]).exists()
    for fp_key in ("ca_cert_sha256", "server_cert_sha256", "client_cert_sha256"):
        assert len(bundle[fp_key]) == 64

    ctx = create_mtls_ssl_context(bundle, require_client_cert=True)
    assert ctx.minimum_version == ssl.TLSVersion.TLSv1_3
    assert ctx.verify_mode == ssl.CERT_REQUIRED


def test_gateway_full_lifecycle_pairing_sync_ingest_synthesis_review_and_ws(tmp_path: Path) -> None:
    bundle = provision_mtls_certificates(tmp_path / "mtls_gw")
    db = _make_unlocked_db(tmp_path, "gw_e2e")
    try:
        app, service = create_gateway_app(
            db=db,
            windows_tls_cert_sha256=bundle["server_cert_sha256"],
            enforce_clock_skew=True,
        )
        client = AsgiTestClient(app)

        # 1. Health & WebSocket probe
        h = client.get("/v1/health")
        assert h.status_code == 200
        assert h.json()["external_providers_enabled"] is False
        assert h.json()["vault_locked"] is False

        ws_frames = client.websocket_probe("/v1/ws/events", send_text="PING")
        assert len(ws_frames) >= 2
        assert ws_frames[0]["event_type"] == "GATEWAY_CONNECTED"
        assert ws_frames[1]["event_type"] == "PONG"

        # 2. QR/SAS pairing
        dev_id, ed_priv, _ = _pair_via_gateway(
            client,
            windows_tls_sha256=bundle["server_cert_sha256"],
            android_tls_sha256=bundle["client_cert_sha256"],
        )

        # 3. Signed contact sync
        now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        cs_req = {
            "schema_version": "1.0.0",
            "sync_batch_id": generate_uuidv7(),
            "device_id": dev_id,
            "sent_at_utc": now_utc,
            "ed25519_signature": "",
            "contacts": [
                {
                    "android_contact_lookup_key": "c-meera",
                    "display_name": "Meera Krishnan",
                    "normalized_phone_hashes": [compute_sha256_hex("+919845001122")],
                    "aliases": [
                        {"alias_text": "മീര", "language_mode": "ml-Mlym", "match_confidence": 0.99}
                    ],
                    "starred_on_android": True,
                    "updated_at_utc": now_utc,
                }
            ],
        }
        cs_req["ed25519_signature"] = base64.b64encode(
            ed25519_sign(ed_priv, canonical_contact_sync_bytes(cs_req))
        ).decode("ascii")
        cs_resp = client.post("/v1/contacts/sync", json_body=cs_req)
        assert cs_resp.status_code == 200
        assert len(cs_resp.json()["resolved_mappings"]) == 1

        # 4. Signed notification ingest
        raw_msg = "Eda nale rathri 8:30 PM vilikkamo?"
        modes, spans = detect_language_modes_and_spans(raw_msg)
        ev_id = generate_uuidv7()
        ev = {
            "event_id": ev_id,
            "package_name": "com.whatsapp",
            "notification_category": "msg",
            "conversation_key": "conv-meera",
            "is_group_conversation": False,
            "group_title": None,
            "direction": "INBOUND",
            "sender": {
                "raw_title": "Meera Krishnan",
                "android_contact_lookup_key": "c-meera",
                "normalized_phone_sha256": compute_sha256_hex("+919845001122"),
                "candidate_person_ids": [],
                "identity_ambiguity": False,
            },
            "content": {
                "raw_text_immutable": raw_msg,
                "raw_text_sha256": compute_sha256_hex(raw_msg),
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
            ed25519_sign(ed_priv, canonical_event_bytes(ev))
        ).decode("ascii")
        batch_req = {
            "schema_version": "1.0.0",
            "batch_id": generate_uuidv7(),
            "device_id": dev_id,
            "sent_at_utc": now_utc,
            "batch_ed25519_signature": "",
            "events": [ev],
        }
        batch_req["batch_ed25519_signature"] = base64.b64encode(
            ed25519_sign(ed_priv, canonical_batch_bytes(batch_req))
        ).decode("ascii")
        ing_resp = client.post("/v1/notifications/ingest", json_body=batch_req)
        assert ing_resp.status_code == 200
        assert ing_resp.json()["acked_event_ids"] == [ev_id]

        # 5. Synthesize via gateway
        syn_resp = client.post(f"/v1/syntheses/{ev_id}", json_body={"reference_now_utc": now_utc})
        assert syn_resp.status_code == 200
        packet = syn_resp.json()
        assert packet["safety_execution_locks"]["requires_user_review"] is True
        assert packet["safety_execution_locks"]["auto_send_permitted"] is False
        assert "8:30" in packet["goal_aware_recommendations"]["reply_candidates"][0]["draft_text"]

        # 6. User review edits reply & trains COMMUNICATION DNA
        rev_resp = client.post(
            f"/v1/syntheses/{packet['synthesis_id']}/review",
            json_body={
                "decision": "EDITED_AND_APPROVED",
                "user_final_edited_text": "sheri machane 8:30 PM nu vilikam",
            },
        )
        assert rev_resp.status_code == 200
        assert rev_resp.json()["user_review_decision"] == "EDITED_BY_USER"
        dna = service.orchestrator.people_memory.get_comm_dna_profile(packet["person_id"])
        assert dna is not None
        assert dna["transliteration_spelling_map"].get("vilikkam") == "vilikam"
    finally:
        db.close()


def test_gateway_security_rejections_replay_skew_and_panic_lock(tmp_path: Path) -> None:
    db = _make_unlocked_db(tmp_path, "gw_sec")
    try:
        win_sha = hashlib.sha256(b"win-cert").hexdigest()
        and_sha = hashlib.sha256(b"and-cert").hexdigest()
        app, _ = create_gateway_app(
            db=db,
            windows_tls_cert_sha256=win_sha,
            enforce_clock_skew=True,
        )
        client = AsgiTestClient(app)
        dev_id, ed_priv, _ = _pair_via_gateway(
            client,
            windows_tls_sha256=win_sha,
            android_tls_sha256=and_sha,
        )

        now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        msg = "Hello tomorrow 5 PM?"
        modes, spans = detect_language_modes_and_spans(msg)
        ev = {
            "event_id": generate_uuidv7(),
            "package_name": "com.whatsapp",
            "notification_category": "msg",
            "conversation_key": "conv-1",
            "is_group_conversation": False,
            "group_title": None,
            "direction": "INBOUND",
            "sender": {
                "raw_title": "Test Contact",
                "android_contact_lookup_key": "c-1",
                "normalized_phone_sha256": None,
                "candidate_person_ids": [],
                "identity_ambiguity": False,
            },
            "content": {
                "raw_text_immutable": msg,
                "raw_text_sha256": compute_sha256_hex(msg),
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
            ed25519_sign(ed_priv, canonical_event_bytes(ev))
        ).decode("ascii")

        # 1. Forged batch signature -> 401
        forged_batch = {
            "schema_version": "1.0.0",
            "batch_id": generate_uuidv7(),
            "device_id": dev_id,
            "sent_at_utc": now_utc,
            "batch_ed25519_signature": base64.b64encode(b"\xff" * 64).decode("ascii"),
            "events": [ev],
        }
        r_forged = client.post("/v1/notifications/ingest", json_body=forged_batch)
        assert r_forged.status_code == 401
        assert r_forged.json()["error_code"] == "SIGNATURE_OR_DEVICE_UNAUTHORIZED"

        # 2. Stale timestamp (> 120s clock skew) -> 409 CLOCK_SKEW_EXCEEDED
        stale_utc = (datetime.now(timezone.utc) - timedelta(minutes=10)).strftime("%Y-%m-%dT%H:%M:%SZ")
        stale_batch = {
            "schema_version": "1.0.0",
            "batch_id": generate_uuidv7(),
            "device_id": dev_id,
            "sent_at_utc": stale_utc,
            "batch_ed25519_signature": "",
            "events": [ev],
        }
        stale_batch["batch_ed25519_signature"] = base64.b64encode(
            ed25519_sign(ed_priv, canonical_batch_bytes(stale_batch))
        ).decode("ascii")
        r_skew = client.post("/v1/notifications/ingest", json_body=stale_batch)
        assert r_skew.status_code == 409
        assert r_skew.json()["error_code"] == "CLOCK_SKEW_EXCEEDED"

        # 3. Valid batch succeeds, then duplicate batch_id replay -> 409 REPLAY_BATCH_DETECTED
        valid_batch = {
            "schema_version": "1.0.0",
            "batch_id": generate_uuidv7(),
            "device_id": dev_id,
            "sent_at_utc": now_utc,
            "batch_ed25519_signature": "",
            "events": [ev],
        }
        valid_batch["batch_ed25519_signature"] = base64.b64encode(
            ed25519_sign(ed_priv, canonical_batch_bytes(valid_batch))
        ).decode("ascii")
        assert client.post("/v1/notifications/ingest", json_body=valid_batch).status_code == 200
        r_replay = client.post("/v1/notifications/ingest", json_body=valid_batch)
        assert r_replay.status_code == 409
        assert r_replay.json()["error_code"] == "REPLAY_BATCH_DETECTED"

        # 4. Panic lock isolates vault (423 VAULT_LOCKED) while heartbeat reports HOLD_UNTIL_UNLOCKED
        db.vault.panic_lock()
        assert client.post("/v1/pair/init", json_body={}).status_code == 423
        assert client.post("/v1/notifications/ingest", json_body=valid_batch).status_code == 423

        hb = {
            "schema_version": "1.0.0",
            "device_id": dev_id,
            "timestamp_utc": now_utc,
            "user_presence_state": "ACTIVE_MOBILE",
            "dnd_active": False,
            "pending_queue_count": 3,
            "battery_percent": 75,
            "ed25519_signature": "",
        }
        hb["ed25519_signature"] = base64.b64encode(
            ed25519_sign(ed_priv, canonical_presence_heartbeat_bytes(hb))
        ).decode("ascii")
        hb_resp = client.post("/v1/presence/heartbeat", json_body=hb)
        assert hb_resp.status_code == 200
        assert hb_resp.json()["desktop_presence_state"] == "VAULT_LOCKED"
        assert hb_resp.json()["recommended_sync_mode"] == "HOLD_UNTIL_UNLOCKED"
    finally:
        db.close()
