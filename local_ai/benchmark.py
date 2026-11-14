"""Local AI Inference & 7-Mode Multilingual Benchmark Suite (Legion 5 Pro).

Benchmarks PSYCHE LOCAL CORE, PSYCHE ECONOMY, 7-mode multilingual pragmatics, and the complete
6-Pillar / 5-Safeguard synthesis pipeline across:
- English (`en`)
- Hindi in English letters (`hi-Latn`) and Devanagari (`hi-Deva`)
- Malayalam in English letters (`ml-Latn`) and Malayalam script (`ml-Mlym`)
- Telugu in English letters (`te-Latn`) and Telugu script (`te-Telu`)
- Natural code-mixed combinations of these authorized modes.
"""

from __future__ import annotations

import statistics
import time
from typing import Any

from core.contracts.validator import compute_sha256_hex, detect_language_modes_and_spans
from core.pipeline.orchestrator import PsycheIntelligenceOrchestrator
from core.storage.database import PsycheDatabase, generate_uuidv7

BENCHMARK_CORPUS: tuple[dict[str, Any], ...] = (
    {
        "case_id": "BM-01-EN-BOUNDARY",
        "label": "English urgent boundary pressure",
        "sender_title": "Manager David",
        "lookup_key": "lk_david",
        "relationship_tier": "COLLEAGUE",
        "text": "Need the final architecture deck right now tonight itself, don't make excuses.",
        "expected_modes": ["en"],
        "expect_sarcasm_or_idiom": False,
        "expect_boundary_pressure": True,
    },
    {
        "case_id": "BM-02-HI-LATN-IDIOM",
        "label": "Hinglish peer coordination with idiom",
        "sender_title": "Rohit Bhai",
        "lookup_key": "lk_rohit",
        "relationship_tier": "CLOSE_FRIEND",
        "text": "Bhai kal milte hain office me, kya scene hai?",
        "expected_modes": ["hi-Latn", "en"],
        "expect_sarcasm_or_idiom": True,
        "expect_boundary_pressure": False,
    },
    {
        "case_id": "BM-03-HI-DEVA-SARCASM",
        "label": "Hindi Devanagari sarcastic tardiness remark",
        "sender_title": "रोहित भाई",
        "lookup_key": "lk_rohit",
        "relationship_tier": "CLOSE_FRIEND",
        "text": "बहुत बढ़िया, अब बता रहे हो जब मीटिंग खत्म हो गई",
        "expected_modes": ["hi-Deva"],
        "expect_sarcasm_or_idiom": True,
        "expect_boundary_pressure": False,
    },
    {
        "case_id": "BM-04-ML-LATN-SCHEDULE",
        "label": "Manglish sibling scheduling question",
        "sender_title": "Ammu Chechi",
        "lookup_key": "lk_ammu",
        "relationship_tier": "FAMILY",
        "text": "Eda nale rathri 8 manikku call cheyyamo? Adipoli news undu",
        "expected_modes": ["ml-Latn", "en"],
        "expect_sarcasm_or_idiom": True,
        "expect_boundary_pressure": False,
    },
    {
        "case_id": "BM-05-ML-MLYM-SARCASM",
        "label": "Malayalam script sarcastic remark",
        "sender_title": "അമ്മു",
        "lookup_key": "lk_ammu",
        "relationship_tier": "FAMILY",
        "text": "വളരെ നന്നായി, ഇപ്പോഴാണോ പറയുന്നേ? നാളെ രാത്രി വിളിക്കാം",
        "expected_modes": ["ml-Mlym"],
        "expect_sarcasm_or_idiom": True,
        "expect_boundary_pressure": False,
    },
    {
        "case_id": "BM-06-TE-LATN-IDIOM",
        "label": "Telugish peer reassurance and scheduling",
        "sender_title": "Raju Garu",
        "lookup_key": "lk_raju",
        "relationship_tier": "CLOSE_FRIEND",
        "text": "Anna repu intiki vastava? Light teesko, chala bagundi",
        "expected_modes": ["te-Latn"],
        "expect_sarcasm_or_idiom": True,
        "expect_boundary_pressure": False,
    },
    {
        "case_id": "BM-07-TE-TELU-NATIVE",
        "label": "Telugu script question and idiom",
        "sender_title": "రాజు గారు",
        "lookup_key": "lk_raju",
        "relationship_tier": "CLOSE_FRIEND",
        "text": "అన్నా రేపు ఇంటికి వస్తావా? లైట్ తీసుకో, చాలా బాగుంది",
        "expected_modes": ["te-Telu"],
        "expect_sarcasm_or_idiom": True,
        "expect_boundary_pressure": False,
    },
    {
        "case_id": "BM-08-TRILINGUAL-CODEMIX",
        "label": "Natural Manglish + English + Hinglish code-mixed message",
        "sender_title": "Ammu Chechi",
        "lookup_key": "lk_ammu",
        "relationship_tier": "FAMILY",
        "text": "Machane tomorrow meeting kazhinju call cheyyam, kya scene hai?",
        "expected_modes": ["ml-Latn", "en", "hi-Latn"],
        "expect_sarcasm_or_idiom": True,
        "expect_boundary_pressure": False,
    },
)


class MultilingualBenchmarkRunner:
    """Executes deterministic hardware & accuracy benchmarks for PSYCHE LOCAL CORE and all 6 Pillars."""

    def __init__(self, db: PsycheDatabase | None = None) -> None:
        self._owns_db = db is None
        self.db = db or PsycheDatabase(db_path=":memory:")
        self.orchestrator = PsycheIntelligenceOrchestrator(db=self.db)

    def run_suite(self) -> dict[str, Any]:
        """Runs the 8-case 7-mode multilingual benchmark corpus and returns a detailed report."""
        device_id = generate_uuidv7()
        self.orchestrator.people_memory.register_paired_device(
            device_id=device_id,
            device_name="Legion-LOQ Benchmark Harness",
            ed25519_public_key_b64="YmVuY2htYXJrLXB1Yi1rZXk=",
            tls_cert_sha256_pin="c" * 64,
        )

        # Seed Knowledge Vault goal manifesto
        self.db.add_knowledge_vault_item(
            title="2026 Focus & Boundary Manifesto",
            category="GOAL_MANIFESTO",
            content="Protect evening deep-work hours after 9 PM while staying warm with family.",
            language_modes=["en"],
        )

        # Seed contacts
        seeded_keys: set[str] = set()
        for item in BENCHMARK_CORPUS:
            lk = item["lookup_key"]
            if lk not in seeded_keys:
                self.orchestrator.people_memory.create_or_update_person(
                    canonical_display_name=item["sender_title"],
                    relationship_tier=item["relationship_tier"],
                    trust_level=0.80,
                    android_contact_lookup_key=lk,
                )
                seeded_keys.add(lk)

        case_reports: list[dict[str, Any]] = []
        latencies_ms: list[float] = []
        mode_matches = 0
        pragmatic_matches = 0
        schema_valid_count = 0

        for idx, case in enumerate(BENCHMARK_CORPUS, start=1):
            ev_id = f"01932c7a-b000-7000-8000-{idx:012d}"
            text = case["text"]
            modes, spans = detect_language_modes_and_spans(text)
            ingest_payload = {
                "schema_version": "1.0.0",
                "batch_id": generate_uuidv7(),
                "device_id": device_id,
                "sent_at_utc": "2026-11-15T02:10:00Z",
                "events": [
                    {
                        "event_id": ev_id,
                        "package_name": "com.whatsapp",
                        "notification_category": "msg",
                        "conversation_key": f"bench_thread_{case['lookup_key']}",
                        "is_group_conversation": False,
                        "group_title": None,
                        "direction": "INBOUND",
                        "sender": {
                            "raw_title": case["sender_title"],
                            "android_contact_lookup_key": case["lookup_key"],
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
                        "posted_at_utc": f"2026-11-15T02:0{idx}:00Z",
                        "security": {
                            "untrusted_external_input": True,
                            "otp_or_sensitive_filtered": True,
                            "ed25519_event_signature": "YmVuY2htYXJrLXNpZ25hdHVyZS1vaw==",
                        },
                    }
                ],
                "batch_ed25519_signature": "YmVuY2htYXJrLWJhdGNoLXNpZ25hdHVyZQ==",
            }
            self.orchestrator.people_memory.ingest_notification_batch(ingest_payload)

            t0 = time.perf_counter()
            packet = self.orchestrator.synthesize_for_event(event_id=ev_id)
            elapsed_ms = round((time.perf_counter() - t0) * 1000.0, 3)
            latencies_ms.append(elapsed_ms)

            # Check language mode coverage
            expected_set = set(case["expected_modes"])
            detected_set = set(modes)
            mode_ok = expected_set.issubset(detected_set)
            if mode_ok:
                mode_matches += 1

            # Check sarcasm/idiom detection
            sarc_idiom_actual = packet["pillar_assessments"]["reality"]["sarcasm_or_idiom_detected"]
            prag_ok = bool(sarc_idiom_actual == case["expect_sarcasm_or_idiom"])
            if prag_ok:
                pragmatic_matches += 1

            # Check safety locks & schema validity
            locks = packet["safety_execution_locks"]
            if (
                locks["requires_user_review"] is True
                and locks["auto_send_permitted"] is False
                and locks["processed_locally"] is True
            ):
                schema_valid_count += 1

            case_reports.append(
                {
                    "case_id": case["case_id"],
                    "label": case["label"],
                    "detected_modes": modes,
                    "mode_accuracy_passed": mode_ok,
                    "pragmatic_subtext_passed": prag_ok,
                    "latency_ms": elapsed_ms,
                    "verdict_status": packet["uncertainty_audit"]["verdict_status"],
                    "primary_draft": packet["goal_aware_recommendations"]["reply_candidates"][0][
                        "draft_text"
                    ],
                }
            )

        economy_summary = self.orchestrator.economy.get_economy_summary()
        total_cases = len(BENCHMARK_CORPUS)
        report = {
            "total_cases": total_cases,
            "language_mode_accuracy_pct": round(100.0 * mode_matches / total_cases, 2),
            "pragmatic_subtext_accuracy_pct": round(100.0 * pragmatic_matches / total_cases, 2),
            "contract_schema_compliance_pct": round(100.0 * schema_valid_count / total_cases, 2),
            "mean_synthesis_latency_ms": round(statistics.mean(latencies_ms), 3),
            "median_synthesis_latency_ms": round(statistics.median(latencies_ms), 3),
            "max_synthesis_latency_ms": round(max(latencies_ms), 3),
            "economy_telemetry": economy_summary,
            "case_reports": case_reports,
        }
        if self._owns_db:
            self.db.close()
        return report


def run_multilingual_benchmark() -> dict[str, Any]:
    """Convenience entrypoint to execute the full 7-mode multilingual benchmark suite."""
    runner = MultilingualBenchmarkRunner()
    return runner.run_suite()
