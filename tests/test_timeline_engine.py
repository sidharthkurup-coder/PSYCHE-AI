"""Automated tests for Safeguard C: Conversation Timeline Engine."""

from __future__ import annotations

from core.contracts import compute_sha256_hex, detect_language_modes_and_spans
from core.pillars.people_memory import PeopleAndMemoryEngine
from core.safeguards.timeline import ConversationTimelineEngine
from core.storage import PsycheDatabase
from core.storage.database import generate_uuidv7


def _make_event(
    *,
    event_id: str,
    conversation_key: str,
    direction: str,
    sender_title: str,
    lookup_key: str,
    text: str,
    posted_at_utc: str,
) -> dict:
    modes, spans = detect_language_modes_and_spans(text)
    return {
        "event_id": event_id,
        "package_name": "com.whatsapp",
        "notification_category": "msg",
        "conversation_key": conversation_key,
        "is_group_conversation": False,
        "group_title": None,
        "direction": direction,
        "sender": {
            "raw_title": sender_title,
            "android_contact_lookup_key": lookup_key,
            "normalized_phone_sha256": None,
            "candidate_person_ids": [],
            "identity_ambiguity": False,
        },
        "content": {
            "raw_text_immutable": text,
            "raw_text_sha256": compute_sha256_hex(text),
            "detected_language_modes": modes,
            "token_language_spans": spans,
        },
        "posted_at_utc": posted_at_utc,
        "security": {
            "untrusted_external_input": True,
            "otp_or_sensitive_filtered": True,
            "ed25519_event_signature": "dGVzdC1zaWctYmFzZTY0LW9r",
        },
    }


def test_timeline_chronology_open_loops_resolution_and_pattern_shift() -> None:
    db = PsycheDatabase(db_path=":memory:")
    pm = PeopleAndMemoryEngine(db=db)
    timeline = ConversationTimelineEngine(db=db)

    device_id = generate_uuidv7()
    pm.register_paired_device(
        device_id=device_id,
        device_name="Lenovo LOQ Android",
        ed25519_public_key_b64="dGVzdC1wdWIta2V5",
        tls_cert_sha256_pin="b" * 64,
    )
    person_id = pm.create_or_update_person(
        canonical_display_name="Ammu",
        relationship_tier="FAMILY",
        trust_level=0.95,
        android_contact_lookup_key="lk_ammu",
    )

    conv_key = "whatsapp_ammu_thread"
    events = [
        # Exchange 1: Fast 2-minute reply
        _make_event(
            event_id="01932c7a-0001-7000-8000-000000000001",
            conversation_key=conv_key,
            direction="INBOUND",
            sender_title="Ammu",
            lookup_key="lk_ammu",
            text="Eda bhakshanam kazhinjo?",
            posted_at_utc="2026-11-14T10:00:00Z",
        ),
        _make_event(
            event_id="01932c7a-0002-7000-8000-000000000002",
            conversation_key=conv_key,
            direction="OUTBOUND_OBSERVED",
            sender_title="Sidharth",
            lookup_key="lk_ammu",
            text="Kazhinju, njan evening vilikkam",
            posted_at_utc="2026-11-14T10:02:00Z",
        ),
        # Exchange 2: Fast 3-minute inbound reply
        _make_event(
            event_id="01932c7a-0003-7000-8000-000000000003",
            conversation_key=conv_key,
            direction="INBOUND",
            sender_title="Ammu",
            lookup_key="lk_ammu",
            text="Okay, eppo varumo?",
            posted_at_utc="2026-11-14T10:05:00Z",
        ),
        _make_event(
            event_id="01932c7a-0004-7000-8000-000000000004",
            conversation_key=conv_key,
            direction="OUTBOUND_OBSERVED",
            sender_title="Sidharth",
            lookup_key="lk_ammu",
            text="Nale rathri 8 manikku call cheyyamo?",
            posted_at_utc="2026-11-14T10:07:00Z",
        ),
        # Exchange 3: Fast 2-minute inbound reply + fast outbound reply
        _make_event(
            event_id="01932c7a-0005-7000-8000-000000000005",
            conversation_key=conv_key,
            direction="INBOUND",
            sender_title="Ammu",
            lookup_key="lk_ammu",
            text="8 manikku ok aano?",
            posted_at_utc="2026-11-14T10:09:00Z",
        ),
        _make_event(
            event_id="01932c7a-0006-7000-8000-000000000006",
            conversation_key=conv_key,
            direction="OUTBOUND_OBSERVED",
            sender_title="Sidharth",
            lookup_key="lk_ammu",
            text="Yes, confirm aayittu parayu",
            posted_at_utc="2026-11-14T10:11:00Z",
        ),
        # Exchange 4: Sudden 5-hour inbound delay (anomaly compared to ~2-3 min baseline) + new open question
        _make_event(
            event_id="01932c7a-0007-7000-8000-000000000007",
            conversation_key=conv_key,
            direction="INBOUND",
            sender_title="Ammu",
            lookup_key="lk_ammu",
            text="Sorry busy aayirunnu, nale രാവിലെ പറ്റുമോ?",
            posted_at_utc="2026-11-14T15:11:00Z",
        ),
    ]

    ingest_resp = pm.ingest_notification_batch(
        {
            "schema_version": "1.0.0",
            "batch_id": generate_uuidv7(),
            "device_id": device_id,
            "sent_at_utc": "2026-11-14T15:12:00Z",
            "events": events,
            "batch_ed25519_signature": "YmF0Y2gtc2lnLWJhc2U2NA==",
        }
    )
    assert len(ingest_resp["acked_event_ids"]) == 7

    state = timeline.process_conversation_events(
        person_id=person_id,
        conversation_key=conv_key,
        reference_now_utc="2026-11-14T16:15:00Z",
    )

    assert state["pattern_shift"]["anomaly_detected"] is True
    assert state["pattern_shift"]["anomaly_description"] is not None

    # Verify separation between OBSERVED_EVENT and INFERRED_EVENT
    natures = {e["event_nature"] for e in state["chronological_events"]}
    assert "OBSERVED_EVENT" in natures
    assert "INFERRED_EVENT" in natures

    # Earlier inbound questions were resolved by outbound replies, while the last inbound question remains OPEN
    resolved_questions = [
        l for l in state["open_loops"] if l["status"] == "RESOLVED"
    ]
    open_questions = [
        l
        for l in state["open_loops"]
        if l["status"] == "OPEN" and l["loop_kind"] == "UNANSWERED_QUESTION_INBOUND"
    ]
    open_commitments = [
        l
        for l in state["open_loops"]
        if l["status"] == "OPEN" and l["loop_kind"] == "UNRESOLVED_COMMITMENT"
    ]
    assert len(resolved_questions) >= 2
    assert len(open_questions) == 1
    assert "രാവിലെ പറ്റുമോ" in open_questions[0]["description"]
    assert len(open_commitments) >= 1
    assert "vilikkam" in open_commitments[0]["description"]
    db.close()
