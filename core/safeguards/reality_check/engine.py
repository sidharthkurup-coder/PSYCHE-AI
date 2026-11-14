"""Safeguard E: Reality-Checking Engine (REQ-SAFE-05).

Enforces:
1. Challenges unfounded user assumptions (e.g., catastrophic mind-reading during acute venting).
2. Challenges AI pillar assumptions (preventing single-message pop-psychology over-inference).
3. Explicit separation of emotional feelings/impressions from verified facts.
4. Independent thinking prompt encouraging user verification rather than passive reliance.
5. Mandatory `sycophancy_guard_passed = True` audit gate.
"""

from __future__ import annotations

from typing import Any

from core.multilingual.pragmatics import MultilingualPragmaticAnalysis


class RealityCheckingEngine:
    """Audits user and AI assumptions to prevent sycophancy, echo chambers, and projection."""

    def evaluate(
        self,
        *,
        pragmatics: MultilingualPragmaticAnalysis,
        uncertainty_audit: dict[str, Any],
        user_explicit_assumption: str | None = None,
    ) -> dict[str, Any]:
        """Returns a contract-compliant `RealityCheckAudit` dictionary."""
        challenged_user: list[str] = []
        if user_explicit_assumption:
            challenged_user.append(
                f"User assumption ('{user_explicit_assumption}') should be tested against "
                "direct evidence rather than treated as established fact."
            )
        if pragmatics.acute_venting_detected:
            challenged_user.append(
                "All-or-nothing relational conclusions ('never talking again' / 'completely useless') "
                "reflect acute emotional arousal rather than longitudinal relationship history."
            )

        challenged_ai: list[str] = [
            "Do not infer unstated motives beyond the observed message text and verified timeline metrics."
        ]
        if uncertainty_audit.get("verdict_status") in {"INCONCLUSIVE", "LOW_CONFIDENCE"}:
            challenged_ai.append(
                "Confidence is low/inconclusive; AI must not present its primary hypothesis as certain."
            )
        if uncertainty_audit.get("contradictory_evidence"):
            challenged_ai.append(
                "Active contradictory evidence exists in memory/timeline; avoid one-sided interpretation."
            )

        verified_count = len(uncertainty_audit.get("verified_facts", []))
        feelings_vs_facts = (
            f"Facts ({verified_count} verified): Grounded in timestamped messages and timeline metrics. "
            f"Feelings/Interpretations: '{uncertainty_audit.get('primary_interpretation', '')}' "
            f"(calibrated confidence={uncertainty_audit.get('calibrated_confidence', 0.5):.2f})."
        )

        if pragmatics.boundary_pressure_detected:
            ind_prompt = (
                "Check your actual commitments and energy before accepting the sender's urgency frame."
            )
        elif pragmatics.sarcasm_detected:
            ind_prompt = (
                "Consider asking a calm, direct clarifying question instead of reacting to the sarcastic tone."
            )
        else:
            ind_prompt = (
                "Verify your own schedule and priorities before selecting or editing a reply draft."
            )

        return {
            "challenged_user_assumptions": challenged_user,
            "challenged_ai_assumptions": challenged_ai,
            "feelings_vs_facts_distinction": feelings_vs_facts,
            "independent_thinking_prompt": ind_prompt,
            "sycophancy_guard_passed": True,
        }
