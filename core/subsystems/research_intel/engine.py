"""PSYCHE RESEARCH INTELLIGENCE — Local Evidence & Knowledge Vault Synthesis (REQ-SUB-02).

Combines:
1. Encrypted PSYCHE KNOWLEDGE VAULT retrieval (user's personal manifestos, notes, boundaries,
   and reference documents stored in `knowledge_vault_items`).
2. Local evidence-based behavioral and communication frameworks with strict source attribution
   (distinguishing empirical findings from heuristic strategies).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from core.storage.database import PsycheDatabase

_BUILTIN_BEHAVIORAL_FRAMEWORKS: tuple[dict[str, str], ...] = (
    {
        "framework_id": "REF-COMM-01",
        "topic": "URGENCY_AND_BOUNDARY_PRESSURE",
        "evidence_tier": "EMPIRICAL_COMMUNICATION_RESEARCH",
        "principle": (
            "Time-pressured demands ('right now', 'ippo thanne', 'abhi ke abhi') trigger reactive "
            "compliance. Pausing to separate urgency from importance preserves autonomy and trust."
        ),
    },
    {
        "framework_id": "REF-COMM-02",
        "topic": "SARCASM_AND_INDIRECT_SUBTEXT",
        "evidence_tier": "PRAGMATIC_LINGUISTICS",
        "principle": (
            "Indirect or sarcastic remarks often mask unmet expectations. Addressing the underlying "
            "concrete concern calmly outperforms mirroring sarcasm or defending literally."
        ),
    },
    {
        "framework_id": "REF-COMM-03",
        "topic": "EMOTIONAL_FLOODING_COOLDOWN",
        "evidence_tier": "AFFECTIVE_PSYCHOLOGY",
        "principle": (
            "High physiological arousal impairs perspective-taking. Delaying permanent relational "
            "decisions during acute venting prevents irreversible damage to high-trust bonds."
        ),
    },
    {
        "framework_id": "REF-COMM-04",
        "topic": "RELATIONAL_COORDINATION_CLARITY",
        "evidence_tier": "INTERPERSONAL_EFFECTIVENESS",
        "principle": (
            "Explicitly confirming times or proposing a concrete counter-window reduces open-loop "
            "cognitive load for both parties."
        ),
    },
)


@dataclass(frozen=True)
class ResearchEvidenceBrief:
    """Grounded research & Knowledge Vault brief for intelligence synthesis."""

    matched_vault_items: list[dict[str, Any]]
    applicable_frameworks: list[dict[str, str]]
    goal_manifesto_excerpts: list[str]
    synthesis_summary: str


class PsycheResearchIntelligenceEngine:
    """Synthesizes decrypted PSYCHE KNOWLEDGE VAULT items and behavioral reference principles."""

    def __init__(self, db: PsycheDatabase) -> None:
        self.db = db

    def retrieve_knowledge_and_evidence(
        self,
        *,
        query_text: str,
        speech_acts: list[str],
        top_k: int = 3,
    ) -> ResearchEvidenceBrief:
        """Retrieves relevant encrypted Knowledge Vault items and behavioral evidence frameworks."""
        conn = self.db.connection
        rows = conn.execute(
            "SELECT vault_item_id, category, embedding_row_index FROM knowledge_vault_items"
        ).fetchall()

        matched_vault: list[dict[str, Any]] = []
        goal_excerpts: list[str] = []

        if rows:
            emb_indices = [
                int(r["embedding_row_index"])
                for r in rows
                if r["embedding_row_index"] is not None
            ]
            sim_scores = self.db.cosine_similarity_scores(query_text, emb_indices)

            scored_items: list[tuple[float, dict[str, Any]]] = []
            for r in rows:
                vid = r["vault_item_id"]
                item = self.db.get_knowledge_vault_item(vid)
                if item is None:
                    continue
                idx = r["embedding_row_index"]
                score = sim_scores.get(int(idx), 0.5) if idx is not None else 0.5
                if item["category"] == "GOAL_MANIFESTO":
                    score += 0.15
                    goal_excerpts.append(f"{item['title']}: {item['content']}")
                scored_items.append((score, item))

            scored_items.sort(key=lambda x: x[0], reverse=True)
            matched_vault = [it for _, it in scored_items[:top_k]]

        # Select applicable behavioral frameworks based on speech acts
        frameworks: list[dict[str, str]] = []
        for fw in _BUILTIN_BEHAVIORAL_FRAMEWORKS:
            if "URGENCY_OR_BOUNDARY_PRESSURE" in speech_acts and fw["topic"] == "URGENCY_AND_BOUNDARY_PRESSURE":
                frameworks.append(fw)
            elif "SARCASTIC_OR_PASSIVE_AGGRESSIVE_REMARK" in speech_acts and fw["topic"] == "SARCASM_AND_INDIRECT_SUBTEXT":
                frameworks.append(fw)
            elif "ACUTE_EMOTIONAL_VENTING" in speech_acts and fw["topic"] == "EMOTIONAL_FLOODING_COOLDOWN":
                frameworks.append(fw)
            elif "SCHEDULING_COORDINATION" in speech_acts and fw["topic"] == "RELATIONAL_COORDINATION_CLARITY":
                frameworks.append(fw)

        if not frameworks:
            frameworks.append(_BUILTIN_BEHAVIORAL_FRAMEWORKS[-1])

        summary_parts: list[str] = []
        if goal_excerpts:
            summary_parts.append(f"Vault Goals ({len(goal_excerpts)}): {goal_excerpts[0]}")
        if frameworks:
            summary_parts.append(
                f"Evidence Principle [{frameworks[0]['framework_id']}]: {frameworks[0]['principle']}"
            )

        return ResearchEvidenceBrief(
            matched_vault_items=matched_vault,
            applicable_frameworks=frameworks,
            goal_manifesto_excerpts=goal_excerpts,
            synthesis_summary=" | ".join(summary_parts),
        )
