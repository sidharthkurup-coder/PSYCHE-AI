"""Pillar 1: HUMAN — Psychology & Interpersonal Intelligence (REQ-PIL-01).

Evaluates:
- Emotional state summary (valence, arousal, cognitive load, frustration vs. warmth).
- Interpersonal dynamic grounded in relationship tier, trust level, and longitudinal memory count.
- Calibrated psychological confidence that penalizes single-message over-interpretation.
"""

from __future__ import annotations

from typing import Any

from core.multilingual.pragmatics import MultilingualPragmaticAnalysis


class HumanPillarEngine:
    """Synthesizes psychological and relational dynamics without single-message pop-psych overreach."""

    def assess(
        self,
        *,
        pragmatics: MultilingualPragmaticAnalysis,
        sender_name: str,
        relationship_tier: str,
        trust_level: float,
        retrieved_memories: list[dict[str, Any]],
        timeline_state: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Returns the contract-compliant `human` pillar assessment plus diagnostic metadata."""
        if pragmatics.acute_venting_detected:
            emotional_state = (
                f"High-arousal emotional venting / frustration detected from {sender_name} "
                f"(valence={pragmatics.emotional_valence}, arousal={pragmatics.emotional_arousal}). "
                "Treat as transient emotional state rather than permanent character shift."
            )
        elif pragmatics.sarcasm_detected:
            emotional_state = (
                f"Guarded or frustrated affect expressed through irony/sarcasm "
                f"(valence={pragmatics.emotional_valence}, arousal={pragmatics.emotional_arousal})."
            )
        elif pragmatics.boundary_pressure_detected:
            emotional_state = (
                f"High-urgency, time-pressured affect seeking immediate compliance "
                f"(arousal={pragmatics.emotional_arousal})."
            )
        elif pragmatics.emotional_valence >= 0.5:
            emotional_state = (
                f"Warm, constructive affect with positive relational engagement "
                f"(valence={pragmatics.emotional_valence})."
            )
        elif "SCHEDULING_COORDINATION" in pragmatics.speech_acts:
            emotional_state = "Calm, task- or coordination-oriented state seeking scheduling alignment."
        else:
            emotional_state = "Neutral, conversational baseline affect."

        # Interpersonal dynamic grounded in relationship_tier and honorific/intimacy cues
        cue_summary = ""
        if pragmatics.intimacy_markers:
            cue_summary = f" Uses peer/intimate markers ({', '.join(pragmatics.intimacy_markers[:3])})."
        elif pragmatics.respect_honorifics:
            cue_summary = f" Uses respectful honorifics ({', '.join(pragmatics.respect_honorifics[:3])})."

        anomaly_note = ""
        if timeline_state and timeline_state.get("pattern_shift", {}).get("anomaly_detected"):
            anomaly_note = " Recent reply-latency shift observed relative to baseline cadence."

        interpersonal_dynamic = (
            f"Relationship tier: {relationship_tier} (trust={trust_level:.2f})."
            f"{cue_summary}{anomaly_note}"
        ).strip()

        # Confidence calibration: higher when corroborated by non-quarantined retrieved memories
        non_quarantined_memories = [
            m
            for m in retrieved_memories
            if m.get("memory_record", {}).get("quarantine", {}).get("status", "NONE") == "NONE"
        ]
        base_conf = 0.72
        if len(non_quarantined_memories) >= 2:
            base_conf += 0.12
        elif len(non_quarantined_memories) == 1:
            base_conf += 0.06
        if pragmatics.sarcasm_detected or pragmatics.acute_venting_detected:
            base_conf -= 0.08
        if relationship_tier == "UNKNOWN":
            base_conf = min(base_conf, 0.58)

        confidence = round(max(0.25, min(0.95, base_conf)), 2)

        return {
            "emotional_state_summary": emotional_state,
            "interpersonal_dynamic": interpersonal_dynamic,
            "confidence": confidence,
        }
