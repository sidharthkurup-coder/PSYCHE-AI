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
        user_mind_memories: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        """Returns the contract-compliant `mind` pillar assessment."""
        mind_ledger_summaries: list[str] = []
        for raw_m in user_mind_memories or []:
            if not isinstance(raw_m, dict):
                continue
            rec = raw_m.get("memory_record", raw_m)
            if not isinstance(rec, dict):
                continue
            q_obj = rec.get("quarantine") if isinstance(rec.get("quarantine"), dict) else {}
            l_obj = rec.get("lifecycle") if isinstance(rec.get("lifecycle"), dict) else {}
            if rec.get("quarantined") or q_obj.get("status", "NONE") != "NONE":
                continue
            if l_obj.get("status", "ACTIVE") != "ACTIVE":
                continue
            text_val = str(rec.get("statement_text") or rec.get("canonical_summary") or "").strip()
            if text_val:
                mind_ledger_summaries.append(text_val)

        goal_parts: list[str] = []
        if research_brief.goal_manifesto_excerpts:
            goal_parts.append(research_brief.goal_manifesto_excerpts[0])
        if mind_ledger_summaries:
            goal_parts.append(f"MIND Ledger: {mind_ledger_summaries[0]}")

        goals_summary = (
            " | ".join(goal_parts)
            if goal_parts
            else "Maintain intentional boundaries, deep-work focus, and authentic relationships."
        )
        ledger_reflection_clause = (
            f" Align with your recorded priority: '{mind_ledger_summaries[0]}'."
            if mind_ledger_summaries
            else ""
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
                f"clear, calm time window tomorrow?{ledger_reflection_clause}"
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
                f"{ledger_reflection_clause}"
            )
        elif "SCHEDULING_COORDINATION" in pragmatics.speech_acts:
            user_goal_alignment = (
                f"Consistent with maintaining {relationship_tier} rapport while honoring "
                f"personal schedule ({goals_summary})."
            )
            cognitive_trigger_watch = None
            independent_reflection = (
                "Verify your calendar and deep-work blocks before locking in the exact time."
                f"{ledger_reflection_clause}"
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
                f"{ledger_reflection_clause}"
            )

        return {
            "user_goal_alignment": user_goal_alignment,
            "cognitive_trigger_watch": cognitive_trigger_watch,
            "independent_reflection": independent_reflection,
        }
