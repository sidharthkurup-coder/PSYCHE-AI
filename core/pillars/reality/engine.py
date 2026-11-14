"""Pillar 2: REALITY — Message & Interaction Intelligence (REQ-PIL-02).

Separates literal surface meaning from pragmatic subtext across all 7 language modes,
integrating Conversation Timeline Engine open loops and latency/cadence shifts.
"""

from __future__ import annotations

from typing import Any

from core.multilingual.pragmatics import MultilingualPragmaticAnalysis


class RealityPillarEngine:
    """Evaluates literal meaning, pragmatic subtext, idioms/sarcasm, and timeline context."""

    def assess(
        self,
        *,
        pragmatics: MultilingualPragmaticAnalysis,
        timeline_state: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Returns the contract-compliant `reality` pillar assessment."""
        subtext_parts = [pragmatics.pragmatic_subtext]

        if timeline_state:
            ps = timeline_state.get("pattern_shift", {})
            if ps.get("anomaly_detected") and ps.get("anomaly_description"):
                subtext_parts.append(f"Timeline context: {ps['anomaly_description']}")

            open_loops = [
                l for l in timeline_state.get("open_loops", []) if l.get("status") == "OPEN"
            ]
            if open_loops:
                subtext_parts.append(
                    f"Active open loops in thread: {len(open_loops)} ({open_loops[0]['loop_kind']})."
                )

        return {
            "literal_meaning": pragmatics.literal_meaning,
            "pragmatic_subtext": " ".join(subtext_parts),
            "sarcasm_or_idiom_detected": bool(
                pragmatics.sarcasm_detected or pragmatics.idiom_detected
            ),
            "idiom_or_colloquial_notes": pragmatics.idiom_or_colloquial_notes,
        }
