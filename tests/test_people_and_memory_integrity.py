"""Automated tests for PEOPLE AND MEMORY (Pillar 5) & Memory Integrity Engine (Safeguard B)."""

from __future__ import annotations

import pytest

from core.contracts import compute_sha256_hex, detect_language_modes_and_spans
from core.pillars.people_memory import PeopleAndMemoryEngine
from core.safeguards.memory_integrity import MemoryIntegrityEngine
from core.storage import PsycheDatabase
from core.storage.database import generate_uuidv7


@pytest.fixture
def engine_bundle() -> tuple[PsycheDatabase, MemoryIntegrityEngine, PeopleAndMemoryEngine]:
    db = PsycheDatabase(db_path=":memory:")
    mem_engine = MemoryIntegrityEngine(db=db)
    pm_engine = PeopleAndMemoryEngine(db=db, memory_integrity=mem_engine)
    return db, mem_engine, pm_engine


def test_cross_script_contact_sync_and_alias_resolution(
    engine_bundle: tuple[PsycheDatabase, MemoryIntegrityEngine, PeopleAndMemoryEngine]
) -> None:
    db, _, pm_engine = engine_bundle
    device_id = generate_uuidv7()
    pm_engine.register_paired_device(
        device_id=device_id,
        device_name="Lenovo LOQ Android Test Device",
        ed25519_public_key_b64="dGVzdC1wdWIta2V5LWJhc2U2NA==",
        tls_cert_sha256_pin="a" * 64,
    )

    sync_req = {
        "schema_version": "1.0.0",
        "sync_batch_id": generate_uuidv7(),
        "device_id": device_id,
        "sent_at_utc": "2026-11-15T01:45:00Z",
        "contacts": [
            {
                "android_contact_lookup_key": "lk_ammu_01",
                "display_name": "Ammu",
                "normalized_phone_hashes": [compute_sha256_hex("+919800000001")],
                "aliases": [
                    {"alias_text": "അമ്മു", "language_mode": "ml-Mlym", "match_confidence": 1.0},
                    {"alias_text": "Ammu Chechi", "language_mode": "ml-Latn", "match_confidence": 0.95},
                ],
                "starred_on_android": True,
                "updated_at_utc": "2026-11-15T01:44:00Z",
            },
            {
                "android_contact_lookup_key": "lk_raju_02",
                "display_name": "Raju Garu",
                "normalized_phone_hashes": [compute_sha256_hex("+919800000002")],
                "aliases": [
                    {"alias_text": "రాజు గారు", "language_mode": "te-Telu", "match_confidence": 1.0},
                ],
                "starred_on_android": False,
                "updated_at_utc": "2026-11-15T01:44:00Z",
            },
        ],
        "ed25519_signature": "c2lnbmF0dXJlLWJhc2U2NC12YWxpZA==",
    }
    resp = pm_engine.sync_android_contacts(sync_req)
    assert len(resp["resolved_mappings"]) == 2
    ammu_pid = resp["resolved_mappings"][0]["person_id"]
    raju_pid = resp["resolved_mappings"][1]["person_id"]

    # Resolve Malayalam script sender 'അമ്മു' without lookup key -> matches Ammu!
    resolved_1, _, amb_1 = pm_engine.resolve_sender_identity(raw_title="അമ്മു")
    assert resolved_1 == ammu_pid
    assert amb_1 is False

    # Resolve Manglish honorific sender 'Ammu Chechi' -> matches Ammu!
    resolved_2, _, amb_2 = pm_engine.resolve_sender_identity(raw_title="Ammu Chechi")
    assert resolved_2 == ammu_pid
    assert amb_2 is False

    # Resolve Telugu script sender 'రాజు గారు' -> matches Raju Garu!
    resolved_3, _, amb_3 = pm_engine.resolve_sender_identity(raw_title="రాజు గారు")
    assert resolved_3 == raju_pid
    assert amb_3 is False
    db.close()


def test_identity_ambiguity_quarantine_for_colliding_names(
    engine_bundle: tuple[PsycheDatabase, MemoryIntegrityEngine, PeopleAndMemoryEngine]
) -> None:
    db, _, pm_engine = engine_bundle
    pid_a = pm_engine.create_or_update_person(
        canonical_display_name="Arun",
        android_contact_lookup_key="lk_arun_college",
        normalized_phone_hashes=[compute_sha256_hex("+919111111111")],
    )
    pid_b = pm_engine.create_or_update_person(
        canonical_display_name="Arun",
        android_contact_lookup_key="lk_arun_work",
        normalized_phone_hashes=[compute_sha256_hex("+919222222222")],
    )
    assert pid_a != pid_b

    # Notification arrives with only raw_title="Arun" and no phone hash / lookup key
    resolved_pid, candidates, is_ambiguous = pm_engine.resolve_sender_identity(raw_title="Arun")
    assert resolved_pid is None
    assert is_ambiguous is True
    assert set(candidates) == {pid_a, pid_b}
    db.close()


def test_emotional_quarantine_blocks_permanent_trait_corruption(
    engine_bundle: tuple[PsycheDatabase, MemoryIntegrityEngine, PeopleAndMemoryEngine]
) -> None:
    db, mem_engine, pm_engine = engine_bundle
    person_id = pm_engine.create_or_update_person(
        canonical_display_name="Vikram",
        relationship_tier="CLOSE_FRIEND",
        trust_level=0.85,
    )

    # User vents in acute frustration (English + Manglish)
    vent_rec = mem_engine.record_memory(
        memory_domain="RELATIONAL",
        epistemic_class="USER_REPORT",
        statement_text="I am never talking to Vikram again, ini mindilla, he is completely useless!",
        original_language_mode="ml-Latn",
        confidence_score=0.90,
        source_type="USER_EXPLICIT_INPUT",
        extractor_component="pillar.human",
        person_id=person_id,
    )
    assert vent_rec["quarantine"]["status"] == "EMOTIONAL_TRANSIENT"
    assert vent_rec["quarantine"]["expires_at_utc"] is not None

    # Attempting to downgrade Vikram's permanent relationship_tier from a quarantined context must fail
    with pytest.raises(ValueError, match="Memory Integrity Safeguard"):
        pm_engine.create_or_update_person(
            canonical_display_name="Vikram",
            relationship_tier="UNKNOWN",
            trust_level=0.0,
            source_quarantine_status=vent_rec["quarantine"]["status"],
        )

    # Retrieval must include the explicit emotional quarantine warning
    results = pm_engine.retrieve_relevant_memories(query_text="Vikram talking", person_id=person_id)
    assert len(results) >= 1
    assert results[0]["emotional_quarantine_warning"] is not None
    db.close()


def test_contradiction_detection_co_retrieval_correction_and_deletion(
    engine_bundle: tuple[PsycheDatabase, MemoryIntegrityEngine, PeopleAndMemoryEngine]
) -> None:
    db, mem_engine, pm_engine = engine_bundle
    person_id = pm_engine.create_or_update_person(
        canonical_display_name="Karthik",
        relationship_tier="COLLEAGUE",
        trust_level=0.70,
    )

    m1 = mem_engine.record_memory(
        memory_domain="EPISODIC",
        epistemic_class="USER_REPORT",
        statement_text="Karthik will attend the project review meeting tomorrow morning.",
        original_language_mode="en",
        confidence_score=0.85,
        source_type="USER_EXPLICIT_INPUT",
        extractor_component="pillar.reality",
        person_id=person_id,
    )
    m2 = mem_engine.record_memory(
        memory_domain="EPISODIC",
        epistemic_class="OBSERVATION",
        statement_text="Karthik will not attend the project review meeting tomorrow morning.",
        original_language_mode="en",
        confidence_score=0.95,
        source_type="ANDROID_NOTIFICATION",
        extractor_component="pillar.reality",
        person_id=person_id,
    )

    # Verify contradiction was automatically detected and linked
    assert len(m2["contradictions"]) == 1
    assert m2["contradictions"][0]["conflicting_memory_id"] == m1["memory_id"]
    assert m2["contradictions"][0]["resolution_state"] == "OPEN"

    # Retrieve memories -> mandatory Contradiction Co-Retrieval Invariant must surface the conflict
    retrieved = pm_engine.retrieve_relevant_memories(
        query_text="Karthik project review meeting tomorrow", person_id=person_id
    )
    assert len(retrieved) >= 2
    assert len(retrieved[0]["co_retrieved_open_contradictions"]) == 1

    # User corrects m1 non-destructively
    corrected = mem_engine.correct_memory(
        m1["memory_id"],
        corrected_statement="Karthik confirmed he cannot attend the morning review due to travel.",
        correction_note="Updated after Karthik's message.",
        new_epistemic_class="VERIFIED_FACT",
        new_confidence_score=1.0,
    )
    assert corrected["lifecycle"]["revision_number"] == 2
    assert corrected["lifecycle"]["supersedes_memory_id"] == m1["memory_id"]

    superseded_m1 = mem_engine.get_memory_record(m1["memory_id"])
    assert superseded_m1["lifecycle"]["status"] == "SUPERSEDED"
    assert superseded_m1["lifecycle"]["superseded_by_memory_id"] == corrected["memory_id"]

    # Delete m2 and verify 0% leakage in active retrieval
    mem_engine.delete_memory(m2["memory_id"], reason="Duplicate entry removed by user")
    after_delete = pm_engine.retrieve_relevant_memories(
        query_text="Karthik project review meeting tomorrow", person_id=person_id
    )
    active_ids = {item["memory_record"]["memory_id"] for item in after_delete}
    assert m2["memory_id"] not in active_ids
    assert m1["memory_id"] not in active_ids
    assert corrected["memory_id"] in active_ids
    db.close()
