"""Phase 6 Verification Tests — Native Android Companion Static Audit & Cryptographic Simulator."""

from __future__ import annotations

from pathlib import Path
import sqlite3

from core.storage.database import PsycheDatabase
from core.subsystems.fortress.crypto_vault import PsycheFortressVault
from windows_companion.gateway import AsgiTestClient, create_gateway_app, provision_mtls_certificates
from android_app_simulator import AndroidCompanionSimulator

REPO_ROOT = Path(__file__).resolve().parent.parent
ANDROID_ROOT = REPO_ROOT / "android-app"


def _make_unlocked_db(tmp_path: Path, name: str = "phase6") -> PsycheDatabase:
    vault = PsycheFortressVault(key_file_path=tmp_path / f"{name}.key.dpapi")
    return PsycheDatabase(
        db_path=tmp_path / f"{name}.sqlite3",
        vault=vault,
        vector_path=tmp_path / f"{name}.npy",
    )


def test_native_android_project_manifest_and_security_audit() -> None:
    required_files = [
        ANDROID_ROOT / "settings.gradle.kts",
        ANDROID_ROOT / "build.gradle.kts",
        ANDROID_ROOT / "gradle.properties",
        ANDROID_ROOT / "app" / "build.gradle.kts",
        ANDROID_ROOT / "app" / "src" / "main" / "AndroidManifest.xml",
        ANDROID_ROOT / "app" / "src" / "main" / "res" / "xml" / "data_extraction_rules.xml",
        ANDROID_ROOT / "app" / "src" / "main" / "res" / "xml" / "network_security_config.xml",
        ANDROID_ROOT / "app" / "src" / "main" / "java" / "com" / "psycheai" / "companion" / "security" / "SensitiveNotificationFilter.kt",
        ANDROID_ROOT / "app" / "src" / "main" / "java" / "com" / "psycheai" / "companion" / "security" / "FortressKeystoreManager.kt",
        ANDROID_ROOT / "app" / "src" / "main" / "java" / "com" / "psycheai" / "companion" / "notifications" / "PsycheNotificationListenerService.kt",
        ANDROID_ROOT / "app" / "src" / "main" / "java" / "com" / "psycheai" / "companion" / "contacts" / "ContactResolver.kt",
        ANDROID_ROOT / "app" / "src" / "main" / "java" / "com" / "psycheai" / "companion" / "storage" / "EncryptedOfflineQueue.kt",
        ANDROID_ROOT / "app" / "src" / "main" / "java" / "com" / "psycheai" / "companion" / "sync" / "CompanionSyncClient.kt",
        ANDROID_ROOT / "app" / "src" / "main" / "java" / "com" / "psycheai" / "companion" / "ui" / "MainActivity.kt",
    ]
    for path in required_files:
        assert path.exists(), f"Missing native Android component: {path}"

    manifest_xml = (ANDROID_ROOT / "app" / "src" / "main" / "AndroidManifest.xml").read_text(encoding="utf-8")
    assert 'android:allowBackup="false"' in manifest_xml
    assert 'android:fullBackupContent="false"' in manifest_xml
    assert 'android:usesCleartextTraffic="false"' in manifest_xml
    assert "@xml/data_extraction_rules" in manifest_xml
    assert "@xml/network_security_config" in manifest_xml
    assert "BIND_NOTIFICATION_LISTENER_SERVICE" in manifest_xml

    for forbidden_perm in ("SEND_SMS", "READ_SMS", "CALL_PHONE", "BIND_ACCESSIBILITY_SERVICE"):
        assert forbidden_perm not in manifest_xml

    net_sec = (
        ANDROID_ROOT / "app" / "src" / "main" / "res" / "xml" / "network_security_config.xml"
    ).read_text(encoding="utf-8")
    assert 'cleartextTrafficPermitted="false"' in net_sec

    main_activity = (
        ANDROID_ROOT
        / "app"
        / "src"
        / "main"
        / "java"
        / "com"
        / "psycheai"
        / "companion"
        / "ui"
        / "MainActivity.kt"
    ).read_text(encoding="utf-8")
    assert "AUTO_SEND_PERMITTED = false" in main_activity
    assert "REQUIRES_USER_REVIEW = true" in main_activity
    assert "ClipboardManager" in main_activity


def test_android_simulator_pairing_contacts_otp_drop_and_multilingual_sync(tmp_path: Path) -> None:
    bundle = provision_mtls_certificates(tmp_path / "mtls")
    db = _make_unlocked_db(tmp_path, "sim_e2e")
    sim: AndroidCompanionSimulator | None = None
    try:
        app, _service = create_gateway_app(
            db=db,
            windows_tls_cert_sha256=bundle["server_cert_sha256"],
            enforce_clock_skew=True,
        )
        client = AsgiTestClient(app)
        sim = AndroidCompanionSimulator(
            gateway_client=client,
            queue_db_path=tmp_path / "android_queue.sqlite3",
            windows_tls_cert_sha256=bundle["server_cert_sha256"],
            android_tls_cert_sha256=bundle["client_cert_sha256"],
        )

        # 1. Pair with SAS verification
        pair_res = sim.pair_with_windows()
        assert pair_res["status"] == "PAIRED"
        assert len(pair_res["sas_6digit"]) == 6

        # 2. Cross-script contact sync (English + Devanagari)
        cs_res = sim.sync_contacts(
            [
                {
                    "android_contact_lookup_key": "c-rohan",
                    "display_name": "Rohan Varma",
                    "phone_numbers": ["+91-9876543210"],
                    "aliases": ["रोहन वर्मा"],
                    "starred_on_android": True,
                }
            ]
        )
        assert len(cs_res["resolved_mappings"]) == 1
        person_id = cs_res["resolved_mappings"][0]["person_id"]

        # 3. Pre-persistence OTP drop MUST reject BEFORE SQLite or Gateway
        otp_text = "948271 is your HDFC Bank OTP for UPI payment. Do not share with anyone."
        otp_res = sim.capture_notification(
            package_name="com.google.android.apps.messaging",
            raw_title="HDFCBANK",
            raw_text=otp_text,
            conversation_key="conv-hdfc",
        )
        assert otp_res["status"] == "DROPPED_SENSITIVE_OR_OTP"
        assert sim.dropped_otp_count == 1
        assert sim.queue_count() == 0

        # Also prove OTP text never entered desktop raw_events
        desktop_otp_rows = db.connection.execute(
            "SELECT COUNT(*) FROM raw_events WHERE raw_text_immutable LIKE '%948271%'"
        ).fetchone()[0]
        assert desktop_otp_rows == 0

        # 4. Multilingual notification capture -> Gateway -> Synthesis
        msg = "Bro meeting 8 PM-nu shift cheyyamo? Mujhe urgent kaam aaya"
        cap_res = sim.capture_notification(
            package_name="com.whatsapp",
            raw_title="रोहन वर्मा",
            raw_text=msg,
            conversation_key="conv-rohan",
            android_contact_lookup_key="c-rohan",
            phone_number="+919876543210",
        )
        assert cap_res["status"] == "DELIVERED"
        assert sim.queue_count() == 0

        packet = sim.request_synthesis(cap_res["event_id"])
        assert packet["person_id"] == person_id
        assert packet["safety_execution_locks"]["requires_user_review"] is True
        assert packet["safety_execution_locks"]["auto_send_permitted"] is False
    finally:
        if sim is not None:
            sim.close()
        db.close()


def test_android_simulator_encrypted_offline_queue_hold_and_flush_on_unlock(tmp_path: Path) -> None:
    bundle = provision_mtls_certificates(tmp_path / "mtls_off")
    db = _make_unlocked_db(tmp_path, "sim_off")
    queue_db_path = tmp_path / "offline_queue.sqlite3"
    sim: AndroidCompanionSimulator | None = None
    try:
        app, _service = create_gateway_app(
            db=db,
            windows_tls_cert_sha256=bundle["server_cert_sha256"],
            enforce_clock_skew=True,
        )
        client = AsgiTestClient(app)
        sim = AndroidCompanionSimulator(
            gateway_client=client,
            queue_db_path=queue_db_path,
            windows_tls_cert_sha256=bundle["server_cert_sha256"],
            android_tls_cert_sha256=bundle["client_cert_sha256"],
        )
        sim.pair_with_windows()

        # Lock desktop vault (simulates Panic Lock or screen lock on Windows 11)
        db.vault.panic_lock()

        secret_msg = "Confidential salary negotiation tomorrow 6 PM — hold privately"
        cap_res = sim.capture_notification(
            package_name="com.whatsapp",
            raw_title="Ananya Rao",
            raw_text=secret_msg,
            conversation_key="conv-ananya",
        )
        assert cap_res["status"] == "HOLD_UNTIL_UNLOCKED"
        assert cap_res["http_status"] in (423, 503)
        assert sim.queue_count() == 1
        assert sim.get_queue_states()[0]["sync_state"] == "HOLD_UNTIL_UNLOCKED"

        # Verify SQLite offline_queue contains AES-GCM ciphertext & zero plaintext
        raw_conn = sqlite3.connect(str(queue_db_path))
        row = raw_conn.execute("SELECT nonce_b64, ciphertext_b64, sync_state FROM offline_queue").fetchone()
        raw_conn.close()
        assert row is not None
        assert len(row[0]) >= 16
        assert "salary negotiation" not in row[1]
        assert "salary negotiation" not in queue_db_path.read_bytes().decode("latin-1", errors="ignore")

        # Presence heartbeat sees desktop VAULT_LOCKED -> HOLD_UNTIL_UNLOCKED with queue depth = 1
        hb_locked = sim.send_presence_heartbeat()
        assert hb_locked["desktop_presence_state"] == "VAULT_LOCKED"
        assert hb_locked["recommended_sync_mode"] == "HOLD_UNTIL_UNLOCKED"

        # Unlock Windows vault -> simulator flushes encrypted queue seamlessly
        db.vault.unlock()
        flush_res = sim.flush_offline_queue()
        assert flush_res["status"] == "FLUSHED_ALL"
        assert flush_res["flushed_batches"] == 1
        assert sim.queue_count() == 0

        # Confirm event is now persisted & decrypted in desktop vault
        desktop_ev = db.connection.execute(
            "SELECT raw_text_immutable FROM raw_events WHERE event_id = ?",
            (cap_res["event_id"],),
        ).fetchone()
        assert desktop_ev is not None
        assert desktop_ev["raw_text_immutable"] == secret_msg
    finally:
        if sim is not None:
            sim.close()
        db.close()
