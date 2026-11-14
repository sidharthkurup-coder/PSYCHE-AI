"""Pillar 6: INFLUENCE AND MENTOR — Ethical Strategy, Boundaries & Growth (REQ-PIL-06).

Synthesizes:
- `strategic_recommendation`: Concrete interpersonal strategy tailored to relationship tier and subtext.
- `boundary_guidance`: Explicit protection of user time, emotional energy, and autonomy.
- `growth_insight`: Long-term personal development reflection grounded in PSYCHE RESEARCH INTELLIGENCE.
"""

from __future__ import annotations

from typing import Any

from core.multilingual.pragmatics import MultilingualPragmaticAnalysis
from core.subsystems.research_intel.engine import ResearchEvidenceBrief


class InfluenceAndMentorPillarEngine:
    """Provides ethical communication strategy, boundary guidance, and mentoring insight."""

    def assess(
        self,
        *,
        pragmatics: MultilingualPragmaticAnalysis,
        relationship_tier: str,
        research_brief: ResearchEvidenceBrief,
        open_loops_count: int = 0,
    ) -> dict[str, Any]:
        """Returns the contract-compliant `influence_and_mentor` pillar assessment."""
        fw_principle = (
            research_brief.applicable_frameworks[0]["principle"]
            if research_brief.applicable_frameworks
            else "Clear, non-defensive communication builds durable relational trust."
        )

        if pragmatics.boundary_pressure_detected:
            strategic_rec = (
                "Acknowledge receipt calmly without accepting artificial urgency; propose a specific, "
                "realistic time slot when you can review or respond."
            )
            boundary_guidance = (
                "Hold firm against immediate-compliance pressure ('right now' / 'ippo thanne'). "
                "Protect your scheduled focus blocks."
            )
            growth_insight = f"Mentoring principle: {fw_principle}"
        elif pragmatics.sarcasm_detected or pragmatics.acute_venting_detected:
            strategic_rec = (
                "Respond to the underlying substantive issue rather than the sarcastic or heated wrapper; "
                "keep tone steady, brief, and non-escalatory."
            )
            boundary_guidance = (
                "Do not absorb displaced frustration or engage in tit-for-tat irony; pause before replying "
                "if you feel provoked."
            )
            growth_insight = f"Mentoring principle: {fw_principle}"
        elif "SCHEDULING_COORDINATION" in pragmatics.speech_acts:
            loop_note = (
                f" Address the {open_loops_count} open loop(s) in this thread."
                if open_loops_count > 0
                else ""
            )
            strategic_rec = (
                f"Confirm the proposed time clearly or offer one concrete counter-option to close "
                f"the scheduling loop.{loop_note}"
            )
            boundary_guidance = (
                "Ensure the agreed call/meeting window leaves buffer around your deep-work and rest hours."
            )
            growth_insight = f"Mentoring principle: {fw_principle}"
        else:
            strategic_rec = (
                f"Maintain warm, concise engagement appropriate for {relationship_tier} rapport."
            )
            boundary_guidance = "Keep commitments explicit and bounded."
            growth_insight = f"Mentoring principle: {fw_principle}"

        return {
            "strategic_recommendation": strategic_rec,
            "boundary_guidance": boundary_guidance,
            "growth_insight": growth_insight,
        }
