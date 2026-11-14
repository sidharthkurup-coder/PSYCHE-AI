"""Automated test suite for PSYCHE AI v1 Companion API Contracts & 7-Mode Multilingual Tagger."""

from __future__ import annotations

import pytest

from core.contracts import (
    AUTHORIZED_LANGUAGE_MODES,
    ContractValidationError,
    ContractValidator,
    compute_sha256_hex,
    detect_language_modes_and_spans,
    is_sensitive_or_otp_notification,
    normalize_phonetic_search_key,
)


@pytest.fixture(scope="module")
def validator() -> ContractValidator:
    return ContractValidator()


def test_exact_seven_authorized_language_modes() -> None:
    assert AUTHORIZED_LANGUAGE_MODES == {
        "en",
        "hi-Latn",
        "hi-Deva",
        "ml-Latn",
        "ml-Mlym",
        "te-Latn",
        "te-Telu",
    }
    assert len(AUTHORIZED_LANGUAGE_MODES) == 7


@pytest.mark.parametrize(
    ("sample_text", "expected_modes"),
    [
        ("Please send the project report by tomorrow.", ["en"]),
        ("Bhai kal milte hain office me", ["hi-Latn", "en"]),
        ("भाई कल ऑफिस में मिलते हैं", ["hi-Deva"]),
        ("Nale rathri 8 manikku call cheyyamo?", ["ml-Latn", "en"]),
        ("നാളെ രാത്രി 8 മണിക്ക് വിളിക്കാം", ["ml-Mlym"]),
        ("Anna repu intiki vastava?", ["te-Latn"]),
        ("అన్నా రేపు ఇంటికి వస్తావా?", ["te-Telu"]),
        ("Machane tomorrow meeting kazhinju call cheyyam, theek hai?", ["ml-Latn", "en", "hi-Latn"]),
        ("Привет мир", ["out_of_scope"]),
    ],
)
def test_multilingual_7_mode_and_code_mix_detection(
    sample_text: str, expected_modes: list[str]
) -> None:
    original_copy = str(sample_text)
    modes, spans = detect_language_modes_and_spans(sample_text)
    # Verify raw message is never modified
    assert sample_text == original_copy
    for exp in expected_modes:
        assert exp in modes, f"Expected {exp} in {modes} for text: {sample_text}"
    assert len(spans) >= 1


def test_phonetic_transliteration_normalization() -> None:
    # Manglish spelling variations map to the same normalized key
    assert normalize_phonetic_search_key("evideya") == normalize_phonetic_search_key("evdeya")
    # Hinglish abbreviations map to canonical key
    assert normalize_phonetic_search_key("kya kr rha nhi") == normalize_phonetic_search_key(
        "kyaa kar raha nahi"
    )
    # Native script Malayalam 'അമ്മു' maps to phonetic 'ammu'
    assert normalize_phonetic_search_key("അമ്മു") == normalize_phonetic_search_key("Ammu")


def test_valid_notification_ingest_request(validator: ContractValidator) -> None:
    raw_msg = "Machane nale office-il varumo? Call cheyyamo?"
    modes, spans = detect_language_modes_and_spans(raw_msg)
    payload = {
        "schema_version": "1.0.0",
        "batch_id": "01932c7a-8b10-7000-8000-000000000001",
        "device_id": "01932c7a-8b10-7000-8000-0000000000aa",
        "sent_at_utc": "2026-11-15T01:35:00Z",
        "events": [
            {
                "event_id": "01932c7a-8b10-7000-8000-000000000002",
                "package_name": "com.whatsapp",
                "notification_category": "msg",
                "conversation_key": "chat_ammu_01",
                "is_group_conversation": False,
                "group_title": None,
                "direction": "INBOUND",
                "sender": {
                    "raw_title": "Ammu (അമ്മു)",
                    "android_contact_lookup_key": "lookup_ammu_1",
                    "normalized_phone_sha256": compute_sha256_hex("+919876543210"),
                    "candidate_person_ids": ["01932c7a-8b10-7000-8000-000000000099"],
                    "identity_ambiguity": False,
                },
                "content": {
                    "raw_text_immutable": raw_msg,
                    "raw_text_sha256": compute_sha256_hex(raw_msg),
                    "detected_language_modes": modes,
                    "token_language_spans": spans,
                },
                "posted_at_utc": "2026-11-15T01:34:55Z",
                "security": {
                    "untrusted_external_input": True,
                    "otp_or_sensitive_filtered": True,
                    "ed25519_event_signature": "dGVzdC1zaWduYXR1cmUtYmFzZTY0LWV4YW1wbGU=",
                },
            }
        ],
        "batch_ed25519_signature": "YmF0Y2gtc2lnbmF0dXJlLWJhc2U2NC1leGFtcGxl",
    }
    validator.validate("notification_ingest.schema.json", "NotificationIngestRequest", payload)


def test_notification_sha256_tampering_rejected(validator: ContractValidator) -> None:
    raw_msg = "Nale rathri 8 manikku call cheyyamo?"
    payload = {
        "event_id": "01932c7a-8b10-7000-8000-000000000003",
        "package_name": "com.whatsapp",
        "notification_category": "msg",
        "conversation_key": "chat_1",
        "is_group_conversation": False,
        "direction": "INBOUND",
        "sender": {"raw_title": "Rahul", "identity_ambiguity": False},
        "content": {
            "raw_text_immutable": raw_msg,
            "raw_text_sha256": "0" * 64,  # Tampered hash
            "detected_language_modes": ["ml-Latn", "en"],
        },
        "posted_at_utc": "2026-11-15T01:35:00Z",
        "security": {
            "untrusted_external_input": True,
            "otp_or_sensitive_filtered": True,
            "ed25519_event_signature": "dGVzdC1zaWduYXR1cmUtYmFzZTY0LWV4YW1wbGU=",
        },
    }
    with pytest.raises(ContractValidationError) as exc_info:
        validator.validate("notification_ingest.schema.json", "NotificationEventItem", payload)
    assert exc_info.value.error_code == "SHA256_MISMATCH"


def test_unapproved_language_rejected_by_contract(validator: ContractValidator) -> None:
    raw_msg = "Bonjour tout le monde"
    payload = {
        "event_id": "01932c7a-8b10-7000-8000-000000000004",
        "package_name": "com.whatsapp",
        "notification_category": "msg",
        "conversation_key": "chat_fr",
        "is_group_conversation": False,
        "direction": "INBOUND",
        "sender": {"raw_title": "Jean", "identity_ambiguity": False},
        "content": {
            "raw_text_immutable": raw_msg,
            "raw_text_sha256": compute_sha256_hex(raw_msg),
            "detected_language_modes": ["fr"],  # Unauthorized language tag
        },
        "posted_at_utc": "2026-11-15T01:35:00Z",
        "security": {
            "untrusted_external_input": True,
            "otp_or_sensitive_filtered": True,
            "ed25519_event_signature": "dGVzdC1zaWduYXR1cmUtYmFzZTY0LWV4YW1wbGU=",
        },
    }
    with pytest.raises(ContractValidationError):
        validator.validate("notification_ingest.schema.json", "NotificationEventItem", payload)


def test_otp_notification_blocked_by_validator(validator: ContractValidator) -> None:
    otp_text = "Your OTP for UPI transaction is 482910. Do not share with anyone."
    assert is_sensitive_or_otp_notification(otp_text, "com.google.android.apps.messaging") is True
    # Also test 6-digit UPI / Aadhaar / bank verification codes without the word "OTP"
    assert (
        is_sensitive_or_otp_notification(
            "Use 839201 for your UPI payment to merchant.", "com.whatsapp"
        )
        is True
    )
    assert (
        is_sensitive_or_otp_notification(
            "Aadhaar verification number is 592014.", "com.whatsapp"
        )
        is True
    )
    assert len(validator.loaded_schema_names) == 8
    payload = {
        "event_id": "01932c7a-8b10-7000-8000-000000000005",
        "package_name": "com.google.android.apps.messaging",
        "notification_category": "msg",
        "conversation_key": "bank_sms",
        "is_group_conversation": False,
        "direction": "INBOUND",
        "sender": {"raw_title": "VM-HDFCBK", "identity_ambiguity": False},
        "content": {
            "raw_text_immutable": otp_text,
            "raw_text_sha256": compute_sha256_hex(otp_text),
            "detected_language_modes": ["en"],
        },
        "posted_at_utc": "2026-11-15T01:35:00Z",
        "security": {
            "untrusted_external_input": True,
            "otp_or_sensitive_filtered": True,
            "ed25519_event_signature": "dGVzdC1zaWduYXR1cmUtYmFzZTY0LWV4YW1wbGU=",
        },
    }
    with pytest.raises(ContractValidationError, match="OTP or sensitive banking"):
        validator.validate("notification_ingest.schema.json", "NotificationEventItem", payload)


def test_intelligence_synthesis_contract_enforces_no_auto_send(validator: ContractValidator) -> None:
    valid_synthesis = {
        "schema_version": "1.0.0",
        "synthesis_id": "01932c7a-8b10-7000-8000-000000000100",
        "trigger_event_id": "01932c7a-8b10-7000-8000-000000000002",
        "person_id": "01932c7a-8b10-7000-8000-000000000099",
        "pillar_assessments": {
            "human": {
                "emotional_state_summary": "Warm, seeking scheduling confirmation.",
                "interpersonal_dynamic": "Close sibling rapport.",
                "confidence": 0.91,
            },
            "reality": {
                "literal_meaning": "Asking if you can call tomorrow night at 8 PM.",
                "pragmatic_subtext": "Wants to catch up; low urgency but high relational value.",
                "sarcasm_or_idiom_detected": False,
                "idiom_or_colloquial_notes": None,
            },
            "mind": {
                "user_goal_alignment": "Consistent with maintaining close family contact.",
                "cognitive_trigger_watch": None,
                "independent_reflection": "Confirm whether 8 PM conflicts with study block before committing.",
            },
            "communication_dna": {
                "recommended_language_modes": ["ml-Latn", "en"],
                "formality_target": 0.15,
                "style_constraints": ["casual_manglish", "no_trailing_period"],
            },
            "people_and_memory": {
                "relationship_tier": "FAMILY",
                "retrieved_memory_ids": [],
                "open_loop_ids": [],
                "active_contradiction_ids": [],
            },
            "influence_and_mentor": {
                "strategic_recommendation": "Confirm time clearly or propose a concrete alternative.",
                "boundary_guidance": "Protect deep-work hours if deadline is active.",
                "growth_insight": "Proactive time-boxing prevents last-minute cancellations.",
            },
        },
        "uncertainty_audit": {
            "verified_facts": ["Message received at 01:34:55Z asking for an 8 PM call tomorrow."],
            "primary_interpretation": "Routine family catch-up request.",
            "calibrated_confidence": 0.88,
            "verdict_status": "HIGH_CONFIDENCE",
            "alternative_explanations": [
                {
                    "hypothesis_id": "H1",
                    "explanation": "Routine check-in call.",
                    "plausibility_score": 0.75,
                    "supporting_evidence_ids": [],
                },
                {
                    "hypothesis_id": "H2",
                    "explanation": "Wants to discuss a specific family event.",
                    "plausibility_score": 0.25,
                    "supporting_evidence_ids": [],
                },
            ],
            "contradictory_evidence": [],
        },
        "reality_check_audit": {
            "challenged_user_assumptions": [],
            "challenged_ai_assumptions": ["Do not assume topic of call without evidence."],
            "feelings_vs_facts_distinction": "Fact: Call requested for 8 PM. Unknown: Specific agenda.",
            "independent_thinking_prompt": "Check your tomorrow evening schedule before replying.",
            "sycophancy_guard_passed": True,
        },
        "goal_aware_recommendations": {
            "inferred_user_objective": "Confirm availability warmly in Manglish.",
            "clarification_needed": False,
            "clarification_question": None,
            "reply_candidates": [
                {
                    "candidate_id": "R1",
                    "strategy_label": "Warm Confirmation (Manglish)",
                    "target_language_modes": ["ml-Latn"],
                    "draft_text": "Sure eda, nale rathri 8 manikku vilikkam",
                    "english_meaning_gloss": "Sure, I will call tomorrow night at 8 PM",
                    "comm_dna_match_score": 0.95,
                    "model_neutralizer_passed": True,
                }
            ],
        },
        "neutralizer_audit": {
            "ai_boilerplate_stripped": True,
            "identity_lock_verified": True,
        },
        "safety_execution_locks": {
            "requires_user_review": True,
            "auto_send_permitted": False,
            "processed_locally": True,
        },
        "created_at_utc": "2026-11-15T01:35:02Z",
    }
    validator.validate(
        "intelligence_synthesis.schema.json", "IntelligenceSynthesisPacket", valid_synthesis
    )

    # Attempting to set auto_send_permitted = True must fail validation
    invalid_copy = dict(valid_synthesis)
    invalid_copy["safety_execution_locks"] = {
        "requires_user_review": True,
        "auto_send_permitted": True,
        "processed_locally": True,
    }
    with pytest.raises(ContractValidationError):
        validator.validate(
            "intelligence_synthesis.schema.json", "IntelligenceSynthesisPacket", invalid_copy
        )
