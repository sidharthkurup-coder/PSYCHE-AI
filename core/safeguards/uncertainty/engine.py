"""Safeguard A: Contextual Uncertainty Engine (REQ-SAFE-01).

Enforces:
1. Strict separation between `verified_facts` (from VERIFIED_FACT / OBSERVATION records)
   and `primary_interpretation` (AI_HYPOTHESIS).
2. Generation of >= 2 plausible ranked `alternative_explanations` with `plausibility_score`
   and `supporting_evidence_ids` (UUIDv7 references).
3. Explicit surfacing of `contradictory_evidence` from open memory contradictions or timeline anomalies.
4. Calibrated uncertainty with mandatory `verdict_status = 'INCONCLUSIVE'` when calibrated
   confidence < 0.55 or when identity ambiguity / uncorroborated single-event shifts occur.
"""

from __future__ import annotations

from typing import Any

from core.multilingual.pragmatics import MultilingualPragmaticAnalysis


class ContextualUncertaintyEngine:
    """Separates verified facts from hypotheses and calibrates multi-hypothesis uncertainty."""

    def evaluate(
        self,
        *,
        trigger_event_id: str,
        sender_name: str,
        posted_at_utc: str,
        pragmatics: MultilingualPragmaticAnalysis,
        human_confidence: float,
        retrieved_memories: list[dict[str, Any]],
        timeline_state: dict[str, Any] | None = None,
        identity_ambiguity: bool = False,
        injection_detected: bool = False,
    ) -> dict[str, Any]:
        """Returns a contract-compliant `ContextualUncertaintyAudit` dictionary."""
        verified_facts: list[str] = [
            f"Message event {trigger_event_id} received from '{sender_name}' at {posted_at_utc} "
            f"in language modes {pragmatics.detected_language_modes}."
        ]

        evidence_ids: list[str] = [trigger_event_id]
        contradictory_evidence: list[str] = []

        for item in retrieved_memories:
            rec = item["memory_record"]
            mid = rec["memory_id"]
            if rec["epistemic_class"] in {"VERIFIED_FACT", "OBSERVATION"}:
                verified_facts.append(f"[{rec['epistemic_class']}] {rec['statement_text']}")
                if mid not in evidence_ids:
                    evidence_ids.append(mid)
            for conf in item.get("co_retrieved_open_contradictions", []):
                contradictory_evidence.append(
                    f"Conflicting memory ({conf['conflicting_memory_id']}): "
                    f"{conf['conflicting_statement']} [{conf['conflict_description']}]"
                )

        if timeline_state:
            ps = timeline_state.get("pattern_shift", {})
            if ps.get("median_inbound_reply_sec") is not None:
                verified_facts.append(
                    f"[OBSERVATION] Historical median inbound reply latency is "
                    f"{int(ps['median_inbound_reply_sec'])}s over {ps.get('window_days', 30)}d window."
                )
            if ps.get("anomaly_detected") and ps.get("anomaly_description"):
                contradictory_evidence.append(
                    f"Timeline pattern shift: {ps['anomaly_description']}"
                )

        # Generate >= 2 ranked alternative explanations
        if pragmatics.sarcasm_detected:
            primary_interp = (
                f"{sender_name} is expressing indirect frustration or dissatisfaction via sarcasm "
                "regarding timing or unmet expectations."
            )
            alternatives = [
                {
                    "hypothesis_id": "H1",
                    "explanation": (
                        "Indirect frustration about delayed communication or a missed expectation."
                    ),
                    "plausibility_score": 0.65,
                    "supporting_evidence_ids": evidence_ids[:2],
                },
                {
                    "hypothesis_id": "H2",
                    "explanation": (
                        "Dry, habitual playful banter without genuine interpersonal hostility."
                    ),
                    "plausibility_score": 0.35,
                    "supporting_evidence_ids": evidence_ids[:1],
                },
            ]
        elif pragmatics.boundary_pressure_detected:
            primary_interp = (
                f"{sender_name} is applying high time-urgency pressure seeking immediate action."
            )
            alternatives = [
                {
                    "hypothesis_id": "H1",
                    "explanation": (
                        "External deadline pressure is causing the sender to request immediate turnaround."
                    ),
                    "plausibility_score": 0.60,
                    "supporting_evidence_ids": evidence_ids[:2],
                },
                {
                    "hypothesis_id": "H2",
                    "explanation": (
                        "Habitual urgency phrasing where a calm next-day window is actually acceptable."
                    ),
                    "plausibility_score": 0.40,
                    "supporting_evidence_ids": evidence_ids[:1],
                },
            ]
        elif "SCHEDULING_COORDINATION" in pragmatics.speech_acts:
            primary_interp = (
                f"{sender_name} is coordinating a call/meeting time and seeking availability confirmation."
            )
            alternatives = [
                {
                    "hypothesis_id": "H1",
                    "explanation": "Routine catch-up or coordination call at the proposed time.",
                    "plausibility_score": 0.72,
                    "supporting_evidence_ids": evidence_ids[:2],
                },
                {
                    "hypothesis_id": "H2",
                    "explanation": (
                        "Wants to discuss a specific time-sensitive topic that has not yet been stated."
                    ),
                    "plausibility_score": 0.28,
                    "supporting_evidence_ids": evidence_ids[:1],
                },
            ]
        else:
            primary_interp = (
                f"Conversational message from {sender_name} aligned with ongoing thread context."
            )
            alternatives = [
                {
                    "hypothesis_id": "H1",
                    "explanation": "Straightforward conversational exchange matching literal phrasing.",
                    "plausibility_score": 0.70,
                    "supporting_evidence_ids": evidence_ids[:2],
                },
                {
                    "hypothesis_id": "H2",
                    "explanation": (
                        "Testing availability or rapport before raising a follow-up request."
                    ),
                    "plausibility_score": 0.30,
                    "supporting_evidence_ids": evidence_ids[:1],
                },
            ]

        # Calibrate confidence based on corroboration, contradictions, and ambiguity
        calibrated = float(human_confidence)
        if contradictory_evidence:
            calibrated -= 0.18
        if identity_ambiguity or injection_detected or pragmatics.has_out_of_scope_script:
            calibrated = min(calibrated, 0.42)
        if (
            timeline_state
            and timeline_state.get("pattern_shift", {}).get("anomaly_detected")
            and len(retrieved_memories) <= 1
        ):
            # Single-event anomaly without longitudinal corroboration must remain cautious/inconclusive
            calibrated = min(calibrated, 0.52)

        calibrated = round(max(0.10, min(0.95, calibrated)), 2)

        if calibrated < 0.55 or identity_ambiguity or injection_detected:
            verdict = "INCONCLUSIVE"
        elif calibrated < 0.70:
            verdict = "LOW_CONFIDENCE"
        elif calibrated < 0.84:
            verdict = "MODERATE_CONFIDENCE"
        else:
            verdict = "HIGH_CONFIDENCE"

        return {
            "verified_facts": verified_facts,
            "primary_interpretation": primary_interp,
            "calibrated_confidence": calibrated,
            "verdict_status": verdict,
            "alternative_explanations": alternatives,
            "contradictory_evidence": contradictory_evidence,
        }
