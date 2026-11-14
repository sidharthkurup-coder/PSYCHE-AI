"""Pillar 3: MIND — Personal Intelligence, Self-Understanding & Goal Alignment (REQ-PIL-03).

Evaluates:
- Alignment between incoming interaction demands and the user's explicit goals/boundaries in
  PSYCHE KNOWLEDGE VAULT and USER_MIND / GOAL memories.
- Cognitive trigger watch (urgency compliance trap, people-pleasing over-commitment,
  reactive emotional escalation).
- Independent reflection prompt to encourage deliberate user agency.
"""

from __future__ import annotations

from typing import Any

from core.multilingual.pragmatics import MultilingualPragmaticAnalysis
from core.subsystems.research_intel.engine import ResearchEvidenceBrief


class MindPillarEngine:
    """Monitors the user's personal goals, cognitive triggers, and independent reflection."""

    def assess(
        self,
        *,
        pragmatics: MultilingualPragmaticAnalysis,
        relationship_tier: str,
        research_brief: ResearchEvidenceBrief,
        user_boundary_notes: dict[str, Any] | list[str] | None = None,
    ) -> dict[str, Any]:
        """Returns the contract-compliant `mind` pillar assessment."""
        goals_summary = (
            research_brief.goal_manifesto_excerpts[0]
            if research_brief.goal_manifesto_excerpts
            else "Maintain intentional boundaries, deep-work focus, and authentic relationships."
        )

        if pragmatics.boundary_pressure_detected:
            user_goal_alignment = (
                f"Potential conflict with user goal ({goals_summary}): incoming message exerts "
                "high urgency/pressure that could disrupt planned priorities."
            )
            cognitive_trigger_watch = (
                "Urgency-Compliance & People-Pleasing Trigger: Watch for automatic 'yes' under "
                "time pressure without checking your actual capacity."
            )
            independent_reflection = (
                "Does this request genuinely require immediate action tonight, or can you set a "
                "clear, calm time window tomorrow?"
            )
        elif pragmatics.acute_venting_detected or pragmatics.sarcasm_detected:
            user_goal_alignment = (
                f"Requires emotional regulation to stay aligned with user goal ({goals_summary})."
            )
            cognitive_trigger_watch = (
                "Defensive-Reactivity Trigger: Avoid matching sarcasm or making permanent "
                "relational judgments during high emotional arousal."
            )
            independent_reflection = (
                "What concrete outcome do you want from this conversation 48 hours from now?"
            )
        elif "SCHEDULING_COORDINATION" in pragmatics.speech_acts:
            user_goal_alignment = (
                f"Consistent with maintaining {relationship_tier} rapport while honoring "
                f"personal schedule ({goals_summary})."
            )
            cognitive_trigger_watch = None
            independent_reflection = (
                "Verify your calendar and deep-work blocks before locking in the exact time."
            )
        else:
            user_goal_alignment = (
                f"Aligned with constructive communication and user priorities ({goals_summary})."
            )
            cognitive_trigger_watch = (
                f"Active contact boundary note: {user_boundary_notes}"
                if user_boundary_notes
                else None
            )
            independent_reflection = (
                "Respond with clarity and brevity that reflects your genuine intent."
            )

        return {
            "user_goal_alignment": user_goal_alignment,
            "cognitive_trigger_watch": cognitive_trigger_watch,
            "independent_reflection": independent_reflection,
        }
