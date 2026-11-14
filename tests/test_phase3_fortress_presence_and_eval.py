"""Comprehensive Phase 3 Verification Tests.

Covers:
1. PSYCHE FORTRESS native cryptographic pairing (X25519 + HKDF-SHA256 SAS + Ed25519 signatures,
   tamper rejection, SAS mismatch rejection, expired sessions, replay/clock-skew enforcement).
2. PSYCHE PRESENCE (`PresenceHeartbeatRequest`/`Response`, `VAULT_LOCKED` hold override, interruption triage).
3. PSYCHE KNOWLEDGE VAULT & Stage 3 PSYCHE RESEARCH INTELLIGENCE (CRUD, vector zeroization, hybrid search,
   scientific citations/limitations, multi-hop cross-referencing across memories & timeline).
4. Cross-lingual concept embeddings across all 7 authorized modes (`en`, `hi-Latn`, `hi-Deva`,
   `ml-Latn`, `ml-Mlym`, `te-Latn`, `te-Telu`).
5. MIND ledger integration, COMMUNICATION DNA transliteration spelling preference learning,
   slot-aware dynamic `GoalAwareResponseEngine` synthesis, and end-to-end orchestrator wiring.
6. `LlamaServerProcessManager` CLI construction & RTX 5050 candidate model evaluation without downloading weights.
7. 210-case Golden Multilingual Evaluation Suite (`AC-01` + `AC-03 >= 95%` accuracy).
"""

from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
import hashlib
from pathlib import Path
import time

import numpy as np
import pytest

from core.contracts.validator import (
    ContractValidationError,
    ContractValidator,
    compute_sha256_hex,
    detect_language_modes_and_spans,
)
from core.pipeline.orchestrator import PsycheIntelligenceOrchestrator
from core.pillars.people_memory.engine import PeopleAndMemoryEngine
from core.safeguards.goal_response.engine import extract_contextual_slots
from core.safeguards.memory_integrity.engine import MemoryIntegrityEngine
from core.storage.database import PsycheDatabase, compute_local_multilingual_embedding, generate_uuidv7
from core.subsystems.fortress.crypto_vault import PsycheFortressVault
from core.subsystems.fortress.pairing import (
    FortressPairingManager,
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
from core.subsystems.knowledge_vault import PsycheKnowledgeVaultEngine
from core.subsystems.local_core.runtime import (
    LlamaServerProcessManager,
    evaluate_candidate_models_for_hardware,
)
from core.subsystems.presence import PsychePresenceEngine
from core.subsystems.research_intel.engine import PsycheResearchIntelligenceEngine
from eval_multilingual import GOLDEN_MULTILINGUAL_CORPUS, evaluate_golden_corpus


def _make_unlocked_db(tmp_path: Path, name: str = "phase3_test") -> PsycheDatabase:
    vault = PsycheFortressVault(key_file_path=tmp_path / f"{name}.key.dpapi")
    db = PsycheDatabase(
        db_path=tmp_path / f"{name}.sqlite3",
        vault=vault,
        vector_path=tmp_path / f"{name}.npy",
    )
    return db


def _perform_real_cryptographic_pairing(
    db: PsycheDatabase,
    *,
    device_id: str | None = None,
) -> tuple[FortressPairingManager, str, bytes]:
    """Completes a real X25519 + HKDF-SAS + Ed25519 pairing flow and returns (mgr, device_id, ed_priv)."""
    mgr = FortressPairingManager(db=db)
    win_tls = hashlib.sha256(b"windows-mtls-cert").hexdigest()
    and_tls = hashlib.sha256(b"android-mtls-cert").hexdigest()
    dev_id = device_id or generate_uuidv7()

    qr = mgr.initiate_pairing_session(
        windows_host_endpoint="https://192.168.1.50:8443",
        windows_tls_cert_sha256=win_tls,
    )
    ed_priv, ed_pub = generate_ed25519_keypair()
    ax_priv, ax_pub = generate_x25519_keypair()

    win_xpub = base64.b64decode(qr["windows_x25519_ephemeral_pub_b64"])
    nonce = base64.b64decode(qr["pairing_nonce_b64"])
    shared = x25519_derive_shared_secret(ax_priv, win_xpub)
    and_ed_b64 = base64.b64encode(ed_pub).decode("ascii")
    sas_6, sas_hmac_b64 = derive_sas_6digit_and_hmac(
        shared_secret=shared,
        pairing_nonce=nonce,
        windows_tls_cert_sha256=win_tls,
        android_ed25519_pub_b64=and_ed_b64,
        pairing_session_id=qr["pairing_session_id"],
    )

    now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    confirm_req = {
        "schema_version": "1.0.0",
        "pairing_session_id": qr["pairing_session_id"],
        "device_id": dev_id,
        "device_name": "Motorola Edge 40 Pro (Sim)",
        "android_ed25519_pub_b64": and_ed_b64,
        "android_x25519_ephemeral_pub_b64": base64.b64encode(ax_pub).decode("ascii"),
        "android_tls_cert_sha256": and_tls,
        "sas_verification_code_hmac_b64": sas_hmac_b64,
        "ed25519_signature": "",
        "requested_at_utc": now_utc,
    }
    confirm_req["ed25519_signature"] = base64.b64encode(
        ed25519_sign(ed_priv, canonical_pairing_confirm_bytes(confirm_req))
    ).decode("ascii")

    resp = mgr.confirm_pairing(confirm_req, user_confirmed_sas_6digit=sas_6)
    assert resp["status"] == "PAIRED"
    assert resp["pinned_windows_tls_cert_sha256"] == win_tls
    return mgr, dev_id, ed_priv


def test_fortress_x25519_hkdf_sas_and_ed25519_pairing_lifecycle(tmp_path: Path) -> None:
    db = _make_unlocked_db(tmp_path, "pairing")
    try:
        mgr, dev_id, _ = _perform_real_cryptographic_pairing(db)
        row = db.connection.execute(
            "SELECT * FROM paired_devices WHERE device_id = ?", (dev_id,)
        ).fetchone()
        assert row is not None
        assert row["trust_status"] == "ACTIVE"

        # 1. SAS mismatch must be rejected
        win_tls = hashlib.sha256(b"win2").hexdigest()
        qr2 = mgr.initiate_pairing_session(
            windows_host_endpoint="https://192.168.1.50:8443",
            windows_tls_cert_sha256=win_tls,
        )
        ed2_priv, ed2_pub = generate_ed25519_keypair()
        ax2_priv, ax2_pub = generate_x25519_keypair()
        shared2 = x25519_derive_shared_secret(
            ax2_priv, base64.b64decode(qr2["windows_x25519_ephemeral_pub_b64"])
        )
        sas2, hmac2 = derive_sas_6digit_and_hmac(
            shared_secret=shared2,
            pairing_nonce=base64.b64decode(qr2["pairing_nonce_b64"]),
            windows_tls_cert_sha256=win_tls,
            android_ed25519_pub_b64=base64.b64encode(ed2_pub).decode("ascii"),
            pairing_session_id=qr2["pairing_session_id"],
        )
        wrong_sas = "000000" if sas2 != "000000" else "999999"
        req2 = {
            "schema_version": "1.0.0",
            "pairing_session_id": qr2["pairing_session_id"],
            "device_id": generate_uuidv7(),
            "device_name": "Evil Spoof Phone",
            "android_ed25519_pub_b64": base64.b64encode(ed2_pub).decode("ascii"),
            "android_x25519_ephemeral_pub_b64": base64.b64encode(ax2_pub).decode("ascii"),
            "android_tls_cert_sha256": hashlib.sha256(b"and2").hexdigest(),
            "sas_verification_code_hmac_b64": hmac2,
            "ed25519_signature": "",
            "requested_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
        req2["ed25519_signature"] = base64.b64encode(
            ed25519_sign(ed2_priv, canonical_pairing_confirm_bytes(req2))
        ).decode("ascii")
        resp2 = mgr.confirm_pairing(req2, user_confirmed_sas_6digit=wrong_sas)
        assert resp2["status"] == "REJECTED_SAS_MISMATCH"

        # 2. Tampered Ed25519 signature must also reject pairing
        qr3 = mgr.initiate_pairing_session(
            windows_host_endpoint="https://192.168.1.50:8443",
            windows_tls_cert_sha256=win_tls,
        )
        ed3_priv, ed3_pub = generate_ed25519_keypair()
        ax3_priv, ax3_pub = generate_x25519_keypair()
        shared3 = x25519_derive_shared_secret(
            ax3_priv, base64.b64decode(qr3["windows_x25519_ephemeral_pub_b64"])
        )
        sas3, hmac3 = derive_sas_6digit_and_hmac(
            shared_secret=shared3,
            pairing_nonce=base64.b64decode(qr3["pairing_nonce_b64"]),
            windows_tls_cert_sha256=win_tls,
            android_ed25519_pub_b64=base64.b64encode(ed3_pub).decode("ascii"),
            pairing_session_id=qr3["pairing_session_id"],
        )
        req3 = {
            "schema_version": "1.0.0",
            "pairing_session_id": qr3["pairing_session_id"],
            "device_id": generate_uuidv7(),
            "device_name": "Tampered Sig Phone",
            "android_ed25519_pub_b64": base64.b64encode(ed3_pub).decode("ascii"),
            "android_x25519_ephemeral_pub_b64": base64.b64encode(ax3_pub).decode("ascii"),
            "android_tls_cert_sha256": hashlib.sha256(b"and3").hexdigest(),
            "sas_verification_code_hmac_b64": hmac3,
            "ed25519_signature": base64.b64encode(b"\x01" * 64).decode("ascii"),
            "requested_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
        resp3 = mgr.confirm_pairing(req3, user_confirmed_sas_6digit=sas3)
        assert resp3["status"] == "REJECTED_SAS_MISMATCH"

        # 3. Expired session must return EXPIRED
        qr4 = mgr.initiate_pairing_session(
            windows_host_endpoint="https://192.168.1.50:8443",
            windows_tls_cert_sha256=win_tls,
            ttl_seconds=60,
        )
        future_utc = (datetime.now(timezone.utc) + timedelta(minutes=10)).strftime("%Y-%m-%dT%H:%M:%SZ")
        req4 = {
            "schema_version": "1.0.0",
            "pairing_session_id": qr4["pairing_session_id"],
            "device_id": generate_uuidv7(),
            "device_name": "Late Phone",
            "android_ed25519_pub_b64": base64.b64encode(ed3_pub).decode("ascii"),
            "android_x25519_ephemeral_pub_b64": base64.b64encode(ax3_pub).decode("ascii"),
            "android_tls_cert_sha256": hashlib.sha256(b"and4").hexdigest(),
            "sas_verification_code_hmac_b64": hmac3,
            "ed25519_signature": base64.b64encode(b"\x02" * 64).decode("ascii"),
            "requested_at_utc": future_utc,
        }
        resp4 = mgr.confirm_pairing(req4, reference_now_utc=future_utc)
        assert resp4["status"] == "EXPIRED"
    finally:
        db.close()


def test_signed_ingest_replay_and_clock_skew_enforcement(tmp_path: Path) -> None:
    db = _make_unlocked_db(tmp_path, "ingest_sig")
    try:
        _, dev_id, ed_priv = _perform_real_cryptographic_pairing(db)
        pm = PeopleAndMemoryEngine(db=db, memory_integrity=MemoryIntegrityEngine(db=db))
        now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        # 1. Signed ContactSyncRequest succeeds
        contact_req = {
            "schema_version": "1.0.0",
            "sync_batch_id": generate_uuidv7(),
            "device_id": dev_id,
            "sent_at_utc": now_utc,
            "ed25519_signature": "",
            "contacts": [
                {
                    "android_contact_lookup_key": "c-rahul",
                    "display_name": "Rahul Nair",
                    "normalized_phone_hashes": [compute_sha256_hex("+919847001122")],
                    "aliases": [
                        {"alias_text": "Rahul", "language_mode": "en", "match_confidence": 1.0}
                    ],
                    "starred_on_android": True,
                    "updated_at_utc": now_utc,
                }
            ],
        }
        contact_req["ed25519_signature"] = base64.b64encode(
            ed25519_sign(ed_priv, canonical_contact_sync_bytes(contact_req))
        ).decode("ascii")
        c_resp = pm.sync_android_contacts(contact_req, require_crypto_signature=True)
        assert len(c_resp["resolved_mappings"]) == 1

        # 2. Signed NotificationIngestRequest succeeds
        msg = "Eda nale 8 manikku vilikkamo?"
        ev = {
            "event_id": generate_uuidv7(),
            "package_name": "com.whatsapp",
            "notification_category": "msg",
            "conversation_key": "conv-rahul",
            "is_group_conversation": False,
            "group_title": None,
            "direction": "INBOUND",
            "sender": {
                "raw_title": "Rahul Nair",
                "android_contact_lookup_key": "c-rahul",
                "normalized_phone_sha256": compute_sha256_hex("+919847001122"),
                "candidate_person_ids": [],
                "identity_ambiguity": False,
            },
            "content": {
                "raw_text_immutable": msg,
                "raw_text_sha256": compute_sha256_hex(msg),
                "detected_language_modes": ["ml-Latn"],
                "token_language_spans": [],
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

        batch_id = generate_uuidv7()
        batch_req = {
            "schema_version": "1.0.0",
            "batch_id": batch_id,
            "device_id": dev_id,
            "sent_at_utc": now_utc,
            "events": [ev],
            "batch_ed25519_signature": "",
        }
        batch_req["batch_ed25519_signature"] = base64.b64encode(
            ed25519_sign(ed_priv, canonical_batch_bytes(batch_req))
        ).decode("ascii")

        i_resp = pm.ingest_notification_batch(
            batch_req,
            require_crypto_signature=True,
            enforce_clock_skew=True,
            reference_now_utc=now_utc,
        )
        assert len(i_resp["acked_event_ids"]) == 1

        # 3. Replaying the same batch_id fails with REPLAY_BATCH_DETECTED
        with pytest.raises(ContractValidationError) as replay_err:
            pm.ingest_notification_batch(
                batch_req,
                require_crypto_signature=True,
                enforce_clock_skew=True,
                reference_now_utc=now_utc,
            )
        assert replay_err.value.error_code == "REPLAY_BATCH_DETECTED"

        # 4. Stale clock skew (> +-120s) fails with CLOCK_SKEW_EXCEEDED
        stale_utc = (datetime.now(timezone.utc) - timedelta(minutes=10)).strftime("%Y-%m-%dT%H:%M:%SZ")
        ev_stale = {
            **ev,
            "event_id": generate_uuidv7(),
            "security": dict(ev["security"]),
        }
        ev_stale["security"]["ed25519_event_signature"] = base64.b64encode(
            ed25519_sign(ed_priv, canonical_event_bytes(ev_stale))
        ).decode("ascii")
        stale_req = {
            "schema_version": "1.0.0",
            "batch_id": generate_uuidv7(),
            "device_id": dev_id,
            "sent_at_utc": stale_utc,
            "events": [ev_stale],
            "batch_ed25519_signature": "",
        }
        stale_req["batch_ed25519_signature"] = base64.b64encode(
            ed25519_sign(ed_priv, canonical_batch_bytes(stale_req))
        ).decode("ascii")
        with pytest.raises(ContractValidationError) as skew_err:
            pm.ingest_notification_batch(
                stale_req,
                require_crypto_signature=True,
                enforce_clock_skew=True,
                reference_now_utc=now_utc,
            )
        assert skew_err.value.error_code == "CLOCK_SKEW_EXCEEDED"
    finally:
        db.close()


def test_psyche_presence_heartbeat_vault_lock_and_triage(tmp_path: Path) -> None:
    db = _make_unlocked_db(tmp_path, "presence")
    try:
        _, dev_id, ed_priv = _perform_real_cryptographic_pairing(db)
        presence = PsychePresenceEngine(db=db)
        now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        hb = {
            "schema_version": "1.0.0",
            "device_id": dev_id,
            "timestamp_utc": now_utc,
            "user_presence_state": "ACTIVE_MOBILE",
            "dnd_active": False,
            "pending_queue_count": 0,
            "battery_percent": 82,
            "ed25519_signature": "",
        }
        hb["ed25519_signature"] = base64.b64encode(
            ed25519_sign(ed_priv, canonical_presence_heartbeat_bytes(hb))
        ).decode("ascii")
        resp = presence.process_heartbeat(hb, require_crypto_signature=True)
        assert resp["desktop_presence_state"] == "ACTIVE_DESKTOP"
        assert resp["recommended_sync_mode"] == "REALTIME_STREAM"

        # FOCUS_LOCKED batches low-priority strangers but allows INNER_CIRCLE coordination
        presence.set_desktop_presence_state("FOCUS_LOCKED")
        triage_colleague = presence.evaluate_interruption_urgency(
            relationship_tier="COLLEAGUE",
            speech_acts=["CONVERSATIONAL_STATEMENT"],
            device_id=dev_id,
        )
        assert triage_colleague["surface_action"] == "BATCH_QUIETLY"

        triage_family = presence.evaluate_interruption_urgency(
            relationship_tier="FAMILY",
            speech_acts=["SCHEDULING_COORDINATION"],
            device_id=dev_id,
        )
        assert triage_family["surface_action"] == "SURFACE_IMMEDIATELY"

        # Locking vault overrides desktop_presence_state to VAULT_LOCKED and HOLD_UNTIL_UNLOCKED
        db.vault.panic_lock()
        assert presence.desktop_presence_state == "VAULT_LOCKED"
        hb2 = dict(hb)
        hb2["ed25519_signature"] = base64.b64encode(
            ed25519_sign(ed_priv, canonical_presence_heartbeat_bytes(hb2))
        ).decode("ascii")
        resp2 = presence.process_heartbeat(hb2, require_crypto_signature=True)
        assert resp2["desktop_presence_state"] == "VAULT_LOCKED"
        assert resp2["recommended_sync_mode"] == "HOLD_UNTIL_UNLOCKED"
        triage_locked = presence.evaluate_interruption_urgency(
            relationship_tier="FAMILY",
            speech_acts=["SCHEDULING_COORDINATION"],
            device_id=dev_id,
        )
        assert triage_locked["surface_action"] == "HOLD_UNTIL_UNLOCKED"
    finally:
        db.close()


def test_knowledge_vault_crud_vector_zeroization_and_research_rigor(tmp_path: Path) -> None:
    db = _make_unlocked_db(tmp_path, "kv_research")
    try:
        kv = PsycheKnowledgeVaultEngine(db=db)
        vid = kv.add_item(
            title="Deep Work Focus Protocol",
            category="GOAL_MANIFESTO",
            content="Protect evenings after 8 PM for thesis study and decline urgent ad-hoc calls.",
            language_modes=["en"],
        )
        item = kv.get_item(vid)
        assert item is not None
        assert item["title"] == "Deep Work Focus Protocol"

        updated = kv.update_item(
            vid,
            content="Protect evenings after 7 PM for deep study and calm family time.",
        )
        assert "7 PM" in updated["content"]

        hits = kv.search_vault(query_text="protect evenings deep study boundaries", top_k=3)
        assert len(hits) == 1
        assert hits[0]["vault_item_id"] == vid

        research = PsycheResearchIntelligenceEngine(db=db, knowledge_vault=kv)
        brief = research.retrieve_knowledge_and_evidence(
            query_text="urgent right now demand disrupting deep work study",
            speech_acts=["URGENCY_OR_BOUNDARY_PRESSURE", "SCHEDULING_COORDINATION"],
            retrieved_memories=[
                {
                    "memory_record": {
                        "memory_id": generate_uuidv7(),
                        "memory_domain": "GOAL",
                        "statement_text": "Prioritize thesis writing after 7 PM",
                        "quarantine": {"status": "NONE"},
                    },
                    "emotional_quarantine_warning": None,
                }
            ],
            timeline_state={"open_loops_count": 2, "boundary_pressure_score": 0.65},
        )
        assert len(brief.applicable_frameworks) >= 1
        fw = brief.applicable_frameworks[0]
        assert fw["citation"]
        assert fw["methodology"]
        assert fw["population_limitations"]
        assert fw["contradictory_findings"]
        assert len(brief.cross_referenced_evidence) >= 2

        # Delete item and verify vector row zeroized on disk/RAM
        emb_row = db.connection.execute(
            "SELECT embedding_row_index FROM knowledge_vault_items WHERE vault_item_id = ?", (vid,)
        ).fetchone()
        idx = int(emb_row["embedding_row_index"])
        assert kv.delete_item(vid) is True
        assert kv.get_item(vid) is None
        assert float(np.linalg.norm(db._vectors[idx])) == 0.0
    finally:
        db.close()


def test_cross_lingual_concept_embeddings_across_all_7_modes() -> None:
    def _cos(a: str, b: str) -> float:
        va = compute_local_multilingual_embedding(a).astype(np.float32)
        vb = compute_local_multilingual_embedding(b).astype(np.float32)
        return float(np.dot(va, vb))

    # Cross-script semantically aligned pairs ("where are you?" / "meet tomorrow")
    assert _cos("Where are you?", "Evideya nee?") > 0.25
    assert _cos("Where are you?", "എവിടെയാ നീ?") > 0.25
    assert _cos("Where are you?", "तुम कहाँ हो?") > 0.25
    assert _cos("Where are you?", "Nuvvu ekkada unnava?") > 0.25
    assert _cos("Where are you?", "నువ్వు ఎక్కడ ఉన్నావు?") > 0.25

    # Semantically aligned cross-lingual pair should outscore unrelated pair
    aligned = _cos("Let's meet tomorrow morning to talk", "Kal subah milte hain baat karne")
    unrelated = _cos("Let's meet tomorrow morning to talk", "Food dinner pizza tasty biryani")
    assert aligned > unrelated


def test_mind_ledger_comm_dna_spelling_and_slot_aware_orchestrator(tmp_path: Path) -> None:
    db = _make_unlocked_db(tmp_path, "e2e_phase3")
    try:
        orch = PsycheIntelligenceOrchestrator(db=db)
        now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        # 1. Record USER_MIND / GOAL ledger entry & Knowledge Vault goal manifesto
        orch.knowledge_vault.add_item(
            title="Autonomous Research Goal",
            category="GOAL_MANIFESTO",
            content="Stay calm in evening coordination and prioritize GATE/research study.",
            language_modes=["en"],
        )
        orch.memory_integrity.record_memory(
            memory_domain="USER_MIND",
            epistemic_class="USER_REPORT",
            statement_text="Complete robotics milestone before sleeping without reactive calls.",
            original_language_mode="en",
            confidence_score=0.98,
            source_type="USER_EXPLICIT_INPUT",
            extractor_component="user.manual",
        )

        # 2. Seed paired device + contact + train COMMUNICATION DNA transliteration spelling & marker preferences
        _, dev_id, ed_priv = _perform_real_cryptographic_pairing(db)
        contact_req = {
            "schema_version": "1.0.0",
            "sync_batch_id": generate_uuidv7(),
            "device_id": dev_id,
            "sent_at_utc": now_utc,
            "ed25519_signature": "",
            "contacts": [
                {
                    "android_contact_lookup_key": "c-arjun",
                    "display_name": "Arjun Menon",
                    "normalized_phone_hashes": [compute_sha256_hex("+919900112233")],
                    "aliases": [],
                    "starred_on_android": True,
                    "updated_at_utc": now_utc,
                }
            ],
        }
        contact_req["ed25519_signature"] = base64.b64encode(
            ed25519_sign(ed_priv, canonical_contact_sync_bytes(contact_req))
        ).decode("ascii")
        c_sync = orch.people_memory.sync_android_contacts(contact_req)
        person_id = c_sync["resolved_mappings"][0]["person_id"]
        learned = orch.comm_dna_pillar.learn_from_user_message(
            person_id=person_id,
            user_message_text="machane evdeya nee ippo, nale 8 maniku vilikam",
        )
        assert "machane" in learned["signature_markers"]
        assert learned["transliteration_spelling_map"].get("evideya") == "evdeya"
        assert learned["transliteration_spelling_map"].get("manikku") == "maniku"
        assert learned["transliteration_spelling_map"].get("vilikkam") == "vilikam"

        # 3. Verify contextual slot extraction
        slots = extract_contextual_slots("Eda tomorrow 9:30 PM call cheyyamo?")
        assert "9:30 PM" in slots["time_mentions"]
        assert slots["day_window"] == "TOMORROW"
        assert "Eda" in slots["honorifics"]

        # 4. Ingest event mentioning explicit time (9:30 PM tomorrow) & synthesize
        raw_msg = "Eda tomorrow 9:30 PM vilikkamo?"
        modes, spans = detect_language_modes_and_spans(raw_msg)
        ev_id = generate_uuidv7()
        ev = {
            "event_id": ev_id,
            "package_name": "com.whatsapp",
            "notification_category": "msg",
            "conversation_key": "conv-arjun",
            "is_group_conversation": False,
            "group_title": None,
            "direction": "INBOUND",
            "sender": {
                "raw_title": "Arjun Menon",
                "android_contact_lookup_key": "c-arjun",
                "normalized_phone_sha256": compute_sha256_hex("+919900112233"),
                "candidate_person_ids": [person_id],
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
        orch.people_memory.ingest_notification_batch(batch_req)
        packet = orch.synthesize_for_event(event_id=ev_id, reference_now_utc=now_utc)
        assert packet["safety_execution_locks"]["requires_user_review"] is True
        assert packet["safety_execution_locks"]["auto_send_permitted"] is False
        assert "Complete robotics milestone" in packet["pillar_assessments"]["mind"]["user_goal_alignment"]

        primary_draft = packet["goal_aware_recommendations"]["reply_candidates"][0]["draft_text"]
        assert "machane" in primary_draft.lower()
        assert "9:30" in primary_draft
        # Spelling preference ("vilikam" instead of "vilikkam", "maniku" instead of "manikku") applied
        assert "vilikam" in primary_draft.lower()
        assert "maniku" in primary_draft.lower()
    finally:
        db.close()


def test_llama_server_process_manager_and_hardware_matrix(tmp_path: Path) -> None:
    mgr = LlamaServerProcessManager(
        binary_path=tmp_path / "llama-server.exe",
        model_path=tmp_path / "Qwen2.5-7B-Instruct-Q4_K_M.gguf",
    )
    assert mgr.endpoint == "http://127.0.0.1:8089"
    cmd = mgr.build_launch_command(validate_files=False)
    assert "--host" in cmd and "127.0.0.1" in cmd
    assert "--port" in cmd and "8089" in cmd
    assert "--no-webui" in cmd
    assert mgr.is_model_weight_present() is False
    with pytest.raises(FileNotFoundError):
        mgr.build_launch_command(validate_files=True)

    matrix = evaluate_candidate_models_for_hardware()
    names = {m["model_name"]: m for m in matrix}
    assert names["Qwen2.5-7B-Instruct-Q4_K_M"]["fits_vram_cap"] is True
    assert names["Qwen2.5-7B-Instruct-Q4_K_M"]["recommended_role"] == "PRIMARY_TIER_2"
    assert names["Qwen2.5-7B-Instruct-Q4_K_M"]["requires_owner_approval_before_download"] is True
    assert names["Qwen2.5-3B-Instruct-Q4_K_M"]["fits_vram_cap"] is True
    assert names["Qwen2.5-3B-Instruct-Q4_K_M"]["recommended_role"] == "FAST_TIER_1"
    assert names["Gemma-2-9B-It-Q4_K_M"]["fits_vram_cap"] is False


def test_210_case_golden_multilingual_evaluation_suite() -> None:
    assert len(GOLDEN_MULTILINGUAL_CORPUS) == 210
    assert len({c.case_id for c in GOLDEN_MULTILINGUAL_CORPUS}) == 210
    assert len({c.raw_text for c in GOLDEN_MULTILINGUAL_CORPUS}) == 210

    t0 = time.perf_counter()
    report = evaluate_golden_corpus()
    elapsed_ms = (time.perf_counter() - t0) * 1000.0

    assert report["total_cases"] == 210
    assert report["ac01_verbatim_sha256_all_passed"] is True
    assert report["ac03_meets_95pct_threshold"] is True, f"Corpus failures: {report['failures']}"
    assert report["accuracy"] >= 0.95
    assert elapsed_ms < 2000.0  # Fast local deterministic throughput
