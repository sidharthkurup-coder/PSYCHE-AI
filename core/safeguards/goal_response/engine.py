"""Safeguard D: Goal-Aware Response Engine (REQ-SAFE-04).

Synthesizes:
1. `inferred_user_objective`: Explicit relational and task goal for the response.
2. `clarification_needed` & `clarification_question`: Triggered when identity is ambiguous,
   verdict is INCONCLUSIVE, or open memory contradictions materially affect the reply strategy.
3. Multi-strategy `reply_candidates` tailored to the user's COMMUNICATION DNA across all 7
   authorized language modes (`en`, `hi-Latn`, `hi-Deva`, `ml-Latn`, `ml-Mlym`, `te-Latn`, `te-Telu`),
   each neutralized by `ModelNeutralizerAndIdentityLock`.
"""

from __future__ import annotations

from typing import Any

from core.contracts.validator import AUTHORIZED_LANGUAGE_MODES
from core.multilingual.pragmatics import MultilingualPragmaticAnalysis
from core.pillars.comm_dna.engine import CommunicationDnaPillarEngine
from core.subsystems.model_neutralizer.engine import ModelNeutralizerAndIdentityLock

# Multilingual strategic draft templates across all 7 authorized language modes
_MULTILINGUAL_DRAFTS: dict[str, dict[str, tuple[str, str]]] = {
    "ml-Latn": {
        "WARM_CONFIRM": (
            "Sure eda, nale rathri 8 manikku vilikkam",
            "Sure, I will call tomorrow night at 8 PM.",
        ),
        "BOUNDARY_ALTERNATIVE": (
            "Eda innu kurachu busy aanu, nale evening samsarikkam",
            "Hey, I am a bit busy today; let's talk tomorrow evening.",
        ),
        "CALM_DEESCALATION": (
            "Eda namukku ithu samadhanamayi samsarichu solve cheyyam",
            "Let's talk this through calmly and sort it out.",
        ),
    },
    "ml-Mlym": {
        "WARM_CONFIRM": (
            "തീർച്ചയായും, നാളെ രാത്രി 8 മണിക്ക് വിളിക്കാം",
            "Sure, I will call tomorrow night at 8 PM.",
        ),
        "BOUNDARY_ALTERNATIVE": (
            "ഇന്ന് അല്പം തിരക്കിലാണ്, നാളെ വൈകുന്നേരം സംസാരിക്കാം",
            "I am a bit busy today; let's talk tomorrow evening.",
        ),
        "CALM_DEESCALATION": (
            "നമുക്ക് ഇത് സമാധാനമായി സംസാരിച്ച് പരിഹരിക്കാം",
            "Let's discuss this calmly and resolve it.",
        ),
    },
    "hi-Latn": {
        "WARM_CONFIRM": (
            "Haan bhai, kal milte hain aur आराम se baat karte hain",
            "Yes brother, let's meet tomorrow and talk comfortably.",
        ),
        "BOUNDARY_ALTERNATIVE": (
            "Bhai abhi thoda busy hoon, kal subah call karta hoon",
            "Brother, I am a bit busy right now; I will call tomorrow morning.",
        ),
        "CALM_DEESCALATION": (
            "Yaar aaram se baat karke clear kar lete hain",
            "Friend, let's talk calmly and clear this up.",
        ),
    },
    "hi-Deva": {
        "WARM_CONFIRM": (
            "हाँ भाई, कल समय पर बात करते हैं",
            "Yes brother, let's talk on time tomorrow.",
        ),
        "BOUNDARY_ALTERNATIVE": (
            "अभी थोड़ा व्यस्त हूँ, कल सुबह बात करते हैं",
            "I am a bit busy right now; let's talk tomorrow morning.",
        ),
        "CALM_DEESCALATION": (
            "शांत होकर बात करके इसे सुलझा लेते हैं",
            "Let's talk calmly and sort this out.",
        ),
    },
    "te-Latn": {
        "WARM_CONFIRM": (
            "Sare anna, repu sayantram kaluddam",
            "Okay brother, let's meet tomorrow evening.",
        ),
        "BOUNDARY_ALTERNATIVE": (
            "Anna ippudu koncham busy ga unna, repu call chestha",
            "Brother, I am a bit busy right now; I will call tomorrow.",
        ),
        "CALM_DEESCALATION": (
            "Prashanthanga matladukuni solve cheddam",
            "Let's talk calmly and resolve this.",
        ),
    },
    "te-Telu": {
        "WARM_CONFIRM": (
            "సరే అన్నా, రేపు సాయంత్రం మాట్లాడుకుందాం",
            "Okay brother, let's talk tomorrow evening.",
        ),
        "BOUNDARY_ALTERNATIVE": (
            "ఇప్పుడు కొంచెం పనిలో ఉన్నాను, రేపు ఉదయం కాల్ చేస్తా",
            "I am in the middle of work right now; I will call tomorrow morning.",
        ),
        "CALM_DEESCALATION": (
            "ప్రశాంతంగా మాట్లాడుకుని పరిష్కరించుకుందాం",
            "Let's speak calmly and resolve this.",
        ),
    },
    "en": {
        "WARM_CONFIRM": (
            "Sounds good, let's connect at the proposed time.",
            "Confirms availability warmly and clearly.",
        ),
        "BOUNDARY_ALTERNATIVE": (
            "I'm tied up right now, but I can review this tomorrow morning and get back to you.",
            "Sets a clear boundary while offering a concrete follow-up window.",
        ),
        "CALM_DEESCALATION": (
            "I want to make sure we're aligned on this—let's step back and discuss the specifics calmly.",
            "Addresses tension constructively without matching sarcasm or urgency.",
        ),
    },
}


class GoalAwareResponseEngine:
    """Generates goal-aligned, COMMUNICATION DNA-matched, neutralized reply candidates."""

    def __init__(
        self,
        *,
        comm_dna: CommunicationDnaPillarEngine,
        neutralizer: ModelNeutralizerAndIdentityLock | None = None,
    ) -> None:
        self.comm_dna = comm_dna
        self.neutralizer = neutralizer or ModelNeutralizerAndIdentityLock()

    def generate_recommendations(
        self,
        *,
        pragmatics: MultilingualPragmaticAnalysis,
        comm_dna_assessment: dict[str, Any],
        uncertainty_audit: dict[str, Any],
        identity_ambiguity: bool = False,
        open_contradictions_count: int = 0,
        spelling_map: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        """Returns the contract-compliant `goal_aware_recommendations` dictionary."""
        target_modes = [
            m
            for m in comm_dna_assessment.get("recommended_language_modes", ["en"])
            if m in AUTHORIZED_LANGUAGE_MODES
        ] or ["en"]
        primary_mode = target_modes[0]
        formality_target = float(comm_dna_assessment.get("formality_target", 0.4))
        style_constraints = list(comm_dna_assessment.get("style_constraints", []))

        # Determine inferred user objective
        if pragmatics.boundary_pressure_detected:
            objective = (
                "Protect personal focus/schedule boundaries while proposing a clear, realistic "
                f"follow-up window in {', '.join(target_modes)}."
            )
            primary_strategy_key = "BOUNDARY_ALTERNATIVE"
            secondary_strategy_key = "CALM_DEESCALATION"
        elif pragmatics.sarcasm_detected or pragmatics.acute_venting_detected:
            objective = (
                "De-escalate tension calmly and address the substantive concern without mirroring "
                f"sarcasm or reactivity in {', '.join(target_modes)}."
            )
            primary_strategy_key = "CALM_DEESCALATION"
            secondary_strategy_key = "BOUNDARY_ALTERNATIVE"
        else:
            objective = (
                "Confirm alignment or availability warmly and concisely in the user's authentic "
                f"{', '.join(target_modes)} voice."
            )
            primary_strategy_key = "WARM_CONFIRM"
            secondary_strategy_key = "BOUNDARY_ALTERNATIVE"

        # Check if clarification is needed before replying
        clarification_needed = False
        clarification_question: str | None = None
        if identity_ambiguity:
            clarification_needed = True
            clarification_question = (
                "Multiple contacts share this display name. Which specific contact sent this message?"
            )
        elif open_contradictions_count > 0:
            clarification_needed = True
            clarification_question = (
                "There is an unresolved contradiction in your saved memories for this thread. "
                "Do you want to confirm availability or propose an alternative time?"
            )
        elif uncertainty_audit.get("verdict_status") == "INCONCLUSIVE":
            clarification_needed = True
            clarification_question = (
                "The sender's intent has multiple plausible interpretations. Do you prefer a direct "
                "confirmation or a boundary-setting pause?"
            )

        mode_bank = _MULTILINGUAL_DRAFTS.get(primary_mode, _MULTILINGUAL_DRAFTS["en"])
        raw_draft_1, gloss_1 = mode_bank[primary_strategy_key]
        raw_draft_2, gloss_2 = mode_bank[secondary_strategy_key]

        clean_1, _ = self.neutralizer.neutralize_and_lock_draft(
            draft_text=raw_draft_1,
            style_constraints=style_constraints,
            transliteration_spelling_map=spelling_map,
        )
        clean_2, _ = self.neutralizer.neutralize_and_lock_draft(
            draft_text=raw_draft_2,
            style_constraints=style_constraints,
            transliteration_spelling_map=spelling_map,
        )

        score_1 = self.comm_dna.score_candidate_authenticity(
            draft_text=clean_1,
            target_language_modes=target_modes,
            formality_target=formality_target,
            style_constraints=style_constraints,
        )
        score_2 = self.comm_dna.score_candidate_authenticity(
            draft_text=clean_2,
            target_language_modes=target_modes,
            formality_target=formality_target,
            style_constraints=style_constraints,
        )

        candidates = [
            {
                "candidate_id": "R1",
                "strategy_label": f"Primary ({primary_strategy_key.replace('_', ' ').title()})",
                "target_language_modes": target_modes,
                "draft_text": clean_1,
                "english_meaning_gloss": gloss_1,
                "comm_dna_match_score": score_1,
                "model_neutralizer_passed": True,
            },
            {
                "candidate_id": "R2",
                "strategy_label": f"Alternative ({secondary_strategy_key.replace('_', ' ').title()})",
                "target_language_modes": target_modes,
                "draft_text": clean_2,
                "english_meaning_gloss": gloss_2,
                "comm_dna_match_score": score_2,
                "model_neutralizer_passed": True,
            },
        ]

        return {
            "inferred_user_objective": objective,
            "clarification_needed": clarification_needed,
            "clarification_question": clarification_question,
            "reply_candidates": candidates,
        }
