"""Pillar 4: COMMUNICATION DNA — Personal Writing Intelligence (REQ-PIL-04).

Models how the user naturally writes to each specific person across the 7 authorized language modes:
- Preferred language modes and code-mix ratios per contact (`en`, `hi-Latn`, `hi-Deva`, `ml-Latn`,
  `ml-Mlym`, `te-Latn`, `te-Telu`).
- Formality level, sentence length cadence, punctuation habits (e.g., dropping trailing periods
  in casual chats), and signature greeting markers (`machane`, `eda`, `bhai`, `anna`, `garu`).
- Continuous learning from user-outbound messages and user-edited reply drafts.
"""

from __future__ import annotations

import re
from typing import Any

from core.contracts.validator import (
    AUTHORIZED_LANGUAGE_MODES,
    detect_language_modes_and_spans,
)
from core.multilingual.pragmatics import MultilingualPragmaticAnalysis
from core.pillars.people_memory.engine import PeopleAndMemoryEngine


class CommunicationDnaPillarEngine:
    """Learns, retrieves, and enforces the user's authentic per-contact COMMUNICATION DNA."""

    def __init__(self, people_memory: PeopleAndMemoryEngine) -> None:
        self.people_memory = people_memory

    def learn_from_user_message(
        self,
        *,
        person_id: str | None,
        user_message_text: str,
    ) -> dict[str, Any]:
        """Updates the per-contact or global COMMUNICATION DNA profile from an authentic user message."""
        modes, spans = detect_language_modes_and_spans(user_message_text)
        auth_modes = [m for m in modes if m in AUTHORIZED_LANGUAGE_MODES] or ["en"]

        counts: dict[str, int] = {}
        for sp in spans:
            m = sp["language_mode"]
            if m in AUTHORIZED_LANGUAGE_MODES:
                counts[m] = counts.get(m, 0) + 1
        total = max(1, sum(counts.values()))
        ratio = {m: round(c / total, 3) for m, c in counts.items()} or {auth_modes[0]: 1.0}

        words = user_message_text.strip().split()
        avg_words = float(len(words)) if words else 6.0
        drops_period = not user_message_text.strip().endswith(".")
        lowercase_start = bool(user_message_text and user_message_text[0].islower())

        # Extract signature markers used by user
        marker_candidates = re.findall(
            r"\b(?:machane|eda|edi|aliya|chechi|chetta|bhai|yaar|bro|anna|akka|garu|ra|mama)\b",
            user_message_text,
            flags=re.IGNORECASE,
        )
        existing = self.people_memory.get_comm_dna_profile(person_id)
        prev_markers = existing["signature_markers"] if existing else []
        merged_markers = list(dict.fromkeys([m.lower() for m in marker_candidates] + prev_markers))[:6]

        formality = 0.20 if merged_markers or drops_period else 0.55
        if existing:
            formality = round(0.6 * existing["formality_level"] + 0.4 * formality, 2)

        cadence_profile = {
            "avg_words": round(avg_words, 1),
            "drops_trailing_period": drops_period,
            "lowercase_start": lowercase_start,
        }
        self.people_memory.upsert_comm_dna_profile(
            person_id=person_id,
            preferred_language_modes=auth_modes,
            code_mix_ratio=ratio,
            cadence_profile=cadence_profile,
            signature_markers=merged_markers,
            formality_level=formality,
        )
        return self.people_memory.get_comm_dna_profile(person_id) or {}

    def assess(
        self,
        *,
        person_id: str | None,
        relationship_tier: str,
        incoming_pragmatics: MultilingualPragmaticAnalysis,
    ) -> dict[str, Any]:
        """Returns the contract-compliant `communication_dna` pillar assessment."""
        stored = self.people_memory.get_comm_dna_profile(person_id)
        if stored is not None:
            rec_modes = [
                m for m in stored["preferred_language_modes"] if m in AUTHORIZED_LANGUAGE_MODES
            ] or incoming_pragmatics.detected_language_modes
            formality_target = float(stored["formality_level"])
            constraints: list[str] = ["preserve_authentic_user_voice", "no_ai_assistant_boilerplate"]
            if stored["cadence_profile"].get("drops_trailing_period"):
                constraints.append("no_trailing_period")
            if stored["signature_markers"]:
                constraints.append(f"natural_markers:{','.join(stored['signature_markers'][:3])}")
        else:
            rec_modes = list(incoming_pragmatics.detected_language_modes) or ["en"]
            if relationship_tier in {"INNER_CIRCLE", "FAMILY", "CLOSE_FRIEND"}:
                formality_target = min(0.25, incoming_pragmatics.formality_estimate)
                constraints = [
                    "casual_warm_cadence",
                    "no_trailing_period",
                    "preserve_incoming_script_and_code_mix",
                ]
            elif relationship_tier in {"COLLEAGUE", "PROFESSIONAL_EXTERNAL"}:
                formality_target = max(0.65, incoming_pragmatics.formality_estimate)
                constraints = [
                    "concise_professional_directness",
                    "clear_commitment_boundaries",
                ]
            else:
                formality_target = incoming_pragmatics.formality_estimate
                constraints = ["balanced_natural_tone", "preserve_incoming_language_mode"]

        return {
            "recommended_language_modes": rec_modes,
            "formality_target": round(max(0.0, min(1.0, formality_target)), 2),
            "style_constraints": constraints,
        }

    def score_candidate_authenticity(
        self,
        *,
        draft_text: str,
        target_language_modes: list[str],
        formality_target: float,
        style_constraints: list[str],
    ) -> float:
        """Computes a [0.0, 1.0] authenticity score measuring fit to the user's COMMUNICATION DNA."""
        detected_modes, _ = detect_language_modes_and_spans(draft_text)
        mode_overlap = len(set(detected_modes) & set(target_language_modes)) / max(
            1, len(set(target_language_modes))
        )
        score = 0.65 + 0.25 * mode_overlap
        if "no_trailing_period" in style_constraints and not draft_text.strip().endswith("."):
            score += 0.06
        if formality_target <= 0.35 and len(draft_text.split()) <= 18:
            score += 0.04
        return round(max(0.1, min(0.99, score)), 2)
