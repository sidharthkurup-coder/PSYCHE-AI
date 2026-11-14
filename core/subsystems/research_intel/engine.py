"""PSYCHE RESEARCH INTELLIGENCE — Local Evidence & Knowledge Vault Synthesis (REQ-SUB-02).

Combines:
1. Encrypted PSYCHE KNOWLEDGE VAULT retrieval (user's personal manifestos, notes, boundaries,
   and reference documents stored in `knowledge_vault_items`).
2. Local evidence-based behavioral and communication frameworks with strict source attribution
   (distinguishing empirical findings from heuristic strategies).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from core.storage.database import PsycheDatabase
from core.subsystems.knowledge_vault import PsycheKnowledgeVaultEngine

_BUILTIN_BEHAVIORAL_FRAMEWORKS: tuple[dict[str, str], ...] = (
    {
        "framework_id": "REF-COMM-01",
        "topic": "URGENCY_AND_BOUNDARY_PRESSURE",
        "evidence_tier": "EMPIRICAL_SOCIAL_PSYCHOLOGY",
        "citation": (
            "Cialdini, R. B. (2021). Influence: The Psychology of Persuasion (Rev. ed.). "
            "Scarcity and artificial time-pressure compliance heuristics."
        ),
        "methodology": (
            "Controlled behavioral experiments and field compliance trials measuring decision "
            "accuracy and autonomic haste under perceived time scarcity."
        ),
        "population_limitations": (
            "Primary empirical cohorts are mostly Western university/adult samples; high-context "
            "South Asian family registers frequently use urgent phrasing out of care rather than coercion."
        ),
        "contradictory_findings": (
            "Genuine external deadlines (transit cutoffs, medical emergencies, exam schedules) "
            "warrant concise logistical alignment rather than boundary skepticism."
        ),
        "principle": (
            "Time-pressured demands ('right now', 'ippo thanne', 'abhi ke abhi') trigger reactive "
            "compliance. Pausing to separate urgency from importance preserves autonomy and trust."
        ),
    },
    {
        "framework_id": "REF-COMM-02",
        "topic": "SARCASM_AND_INDIRECT_SUBTEXT",
        "evidence_tier": "PRAGMATIC_LINGUISTICS",
        "citation": (
            "Brown, P., & Levinson, S. C. (1987). Politeness: Some Universals in Language Usage; "
            "Grice, H. P. (1975). Logic and Conversation."
        ),
        "methodology": (
            "Cross-linguistic pragmatic discourse analysis of conversational implicature, "
            "face-threatening acts, and off-record indirectness strategies."
        ),
        "population_limitations": (
            "Pragmatic indirectness markers shift substantially across English, Hindi, Malayalam, "
            "and Telugu honorific systems and kinship familiarity."
        ),
        "contradictory_findings": (
            "High-solidarity peer banter often employs surface sarcasm or hyperbolic teasing without "
            "hostile subtext."
        ),
        "principle": (
            "Indirect or sarcastic remarks often mask unmet expectations. Addressing the underlying "
            "concrete concern calmly outperforms mirroring sarcasm or defending literally."
        ),
    },
    {
        "framework_id": "REF-COMM-03",
        "topic": "EMOTIONAL_FLOODING_COOLDOWN",
        "evidence_tier": "AFFECTIVE_PSYCHOLOGY",
        "citation": (
            "Gottman, J. M. (1994). What Predicts Divorce? Physiological flooding and "
            "demand-withdraw regulation; Gross, J. J. (2015). Handbook of Emotion Regulation."
        ),
        "methodology": (
            "Longitudinal dyadic interaction coding paired with cardiovascular arousal indices "
            "and experimental cognitive reappraisal vs. suppression trials."
        ),
        "population_limitations": (
            "Empirical baseline derives primarily from clinical and lab dyads; when acute venting "
            "stems from external stress rather than relational conflict, brief warm validation helps."
        ),
        "contradictory_findings": (
            "Silent withdrawal without signaling a clear return time can amplify distress and perceived "
            "rejection more than a short, calm acknowledgment."
        ),
        "principle": (
            "High physiological arousal impairs perspective-taking. Delaying permanent relational "
            "decisions during acute venting prevents irreversible damage to high-trust bonds."
        ),
    },
    {
        "framework_id": "REF-COMM-04",
        "topic": "RELATIONAL_COORDINATION_CLARITY",
        "evidence_tier": "INTERPERSONAL_EFFECTIVENESS",
        "citation": (
            "Clark, H. H. (1996). Using Language (joint commitment grounding); "
            "Linehan, M. M. (2014). DBT Skills Training Manual (2nd ed.)."
        ),
        "methodology": (
            "Psycholinguistic task-dialogue studies on common-ground accumulation and clinical trials "
            "of structured interpersonal effectiveness assertions."
        ),
        "population_limitations": (
            "Highly explicit assertiveness scripts require warm lexical softening in informal Hindi, "
            "Malayalam, and Telugu sibling or peer conversations."
        ),
        "contradictory_findings": (
            "Advancing straight to scheduling before acknowledging an emotional bid can feel dismissive "
            "to close relational contacts."
        ),
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
    cross_referenced_evidence: list[dict[str, Any]] = field(default_factory=list)


class PsycheResearchIntelligenceEngine:
    """Synthesizes decrypted PSYCHE KNOWLEDGE VAULT items and behavioral reference principles."""

    def __init__(
        self,
        db: PsycheDatabase,
        knowledge_vault: PsycheKnowledgeVaultEngine | None = None,
    ) -> None:
        self.db = db
        self.knowledge_vault = knowledge_vault or PsycheKnowledgeVaultEngine(db)

    def retrieve_knowledge_and_evidence(
        self,
        *,
        query_text: str,
        speech_acts: list[str],
        top_k: int = 3,
        retrieved_memories: list[dict[str, Any]] | None = None,
        timeline_state: dict[str, Any] | None = None,
    ) -> ResearchEvidenceBrief:
        """Retrieves Knowledge Vault items, scientific frameworks, and multi-hop evidence links."""
        top_k = max(1, int(top_k))
        vault_hits = self.knowledge_vault.search_vault(
            query_text=query_text,
            top_k=max(top_k, 5),
        )
        goal_items = self.knowledge_vault.list_items(category="GOAL_MANIFESTO")
        goal_excerpts: list[str] = [
            f"{item['title']}: {item['content']}" for item in goal_items
        ]

        # Prioritize goal manifestos cleanly while preserving semantic rank order
        ranked_pool: list[tuple[float, dict[str, Any]]] = []
        seen_ids: set[str] = set()
        for it in vault_hits:
            vid = it["vault_item_id"]
            seen_ids.add(vid)
            score = float(it.get("similarity_score", 0.5))
            if it["category"] == "GOAL_MANIFESTO":
                score += 0.15
            ranked_pool.append((score, it))
        for g_item in goal_items:
            vid = g_item["vault_item_id"]
            if vid not in seen_ids:
                seen_ids.add(vid)
                ranked_pool.append((0.65, g_item))

        ranked_pool.sort(key=lambda pair: pair[0], reverse=True)
        matched_vault = [item for _, item in ranked_pool[:top_k]]

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

        # Multi-hop cross-referencing across memories, timeline state, vault items, and frameworks
        cross_referenced: list[dict[str, Any]] = []
        if retrieved_memories:
            quarantined_count = 0
            first_active_rec: dict[str, Any] | None = None
            for entry in retrieved_memories:
                if not isinstance(entry, dict):
                    continue
                rec = entry.get("memory_record", entry)
                if not isinstance(rec, dict):
                    continue
                q_obj = rec.get("quarantine") if isinstance(rec.get("quarantine"), dict) else {}
                is_quarantined = bool(
                    rec.get("quarantined")
                    or entry.get("emotional_quarantine_warning")
                    or (q_obj.get("status", "NONE") != "NONE")
                )
                if is_quarantined:
                    quarantined_count += 1
                elif first_active_rec is None:
                    first_active_rec = rec

            if quarantined_count > 0:
                cross_referenced.append(
                    {
                        "hop_type": "MEMORY_QUARANTINE_TO_FRAMEWORK",
                        "framework_id": "REF-COMM-03",
                        "detail": (
                            f"{quarantined_count} retrieved memory item(s) remain emotionally quarantined; "
                            "avoid generalizing volatile acute remarks into fixed traits."
                        ),
                    }
                )
            mem_for_hop = first_active_rec
            if mem_for_hop is None and isinstance(retrieved_memories[0], dict):
                mem_for_hop = retrieved_memories[0].get("memory_record", retrieved_memories[0])
            if matched_vault and isinstance(mem_for_hop, dict):
                mem_kind = (
                    mem_for_hop.get("memory_domain")
                    or mem_for_hop.get("epistemic_class")
                    or mem_for_hop.get("memory_kind")
                    or "MEMORY"
                )
                cross_referenced.append(
                    {
                        "hop_type": "MEMORY_TO_VAULT_ALIGNMENT",
                        "memory_id": mem_for_hop.get("memory_id", ""),
                        "vault_item_id": matched_vault[0]["vault_item_id"],
                        "detail": (
                            f"Cross-checked memory ({mem_kind}) against "
                            f"vault item '{matched_vault[0]['title']}'."
                        ),
                    }
                )

        if timeline_state:
            open_loops_val = timeline_state.get("open_loops_count")
            if open_loops_val is None and isinstance(timeline_state.get("open_loops"), list):
                open_loops_val = len(timeline_state["open_loops"])
            if open_loops_val and int(open_loops_val) > 0:
                cross_referenced.append(
                    {
                        "hop_type": "TIMELINE_OPEN_LOOP_TO_FRAMEWORK",
                        "framework_id": "REF-COMM-04",
                        "detail": (
                            f"{int(open_loops_val)} open conversational loop(s) detected; "
                            "explicit time/window grounding recommended."
                        ),
                    }
                )
            pressure_score = float(timeline_state.get("boundary_pressure_score", 0.0) or 0.0)
            if pressure_score >= 0.4:
                cross_referenced.append(
                    {
                        "hop_type": "TIMELINE_PRESSURE_TO_FRAMEWORK",
                        "framework_id": "REF-COMM-01",
                        "detail": (
                            f"Elevated timeline boundary pressure ({pressure_score:.2f}); "
                            "verify user-owned goals before conceding focus blocks."
                        ),
                    }
                )

        summary_parts: list[str] = []
        if goal_excerpts:
            summary_parts.append(f"Vault Goals ({len(goal_excerpts)}): {goal_excerpts[0]}")
        if frameworks:
            summary_parts.append(
                f"Evidence Principle [{frameworks[0]['framework_id']} | {frameworks[0]['citation']}]: "
                f"{frameworks[0]['principle']}"
            )
        if cross_referenced:
            summary_parts.append(
                f"Cross-Referenced Signals ({len(cross_referenced)}): {cross_referenced[0]['detail']}"
            )

        return ResearchEvidenceBrief(
            matched_vault_items=matched_vault,
            applicable_frameworks=frameworks,
            goal_manifesto_excerpts=goal_excerpts,
            synthesis_summary=" | ".join(summary_parts),
            cross_referenced_evidence=cross_referenced,
        )
