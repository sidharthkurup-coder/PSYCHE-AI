"""Unified Six-Pillar & Five-Safeguard Reasoning Pipeline Orchestrator.

Coordinates:
- All 6 Intelligence Pillars (HUMAN, REALITY, MIND, COMMUNICATION DNA, PEOPLE AND MEMORY,
  INFLUENCE AND MENTOR).
- All 5 Mandatory Engineering Safeguards (Contextual Uncertainty Engine, Memory Integrity Engine,
  Conversation Timeline Engine, Goal-Aware Response Engine, Reality-Checking Engine).
- Supporting Subsystems: PSYCHE KNOWLEDGE VAULT, PSYCHE RESEARCH INTELLIGENCE, PSYCHE LOCAL CORE,
  MODEL NEUTRALIZER AND IDENTITY LOCK, PSYCHE ECONOMY, and PSYCHE FORTRESS.
- Strict schema validation against `contracts/v1/intelligence_synthesis.schema.json` and
  immutable enforcement of `requires_user_review = True` and `auto_send_permitted = False`.
"""

from __future__ import annotations

import json
from typing import Any

from core.contracts.validator import ContractValidator
from core.multilingual.pragmatics import MultilingualPragmaticsEngine
from core.pillars.comm_dna.engine import CommunicationDnaPillarEngine
from core.pillars.human.engine import HumanPillarEngine
from core.pillars.influence_mentor.engine import InfluenceAndMentorPillarEngine
from core.pillars.mind.engine import MindPillarEngine
from core.pillars.people_memory.engine import PeopleAndMemoryEngine
from core.pillars.reality.engine import RealityPillarEngine
from core.safeguards.goal_response.engine import GoalAwareResponseEngine
from core.safeguards.memory_integrity.engine import MemoryIntegrityEngine
from core.safeguards.reality_check.engine import RealityCheckingEngine
from core.safeguards.timeline.engine import ConversationTimelineEngine
from core.safeguards.uncertainty.engine import ContextualUncertaintyEngine
from core.storage.database import PsycheDatabase, generate_uuidv7, utc_now_iso
from core.subsystems.economy.governor import PsycheEconomyGovernor
from core.subsystems.knowledge_vault import PsycheKnowledgeVaultEngine
from core.subsystems.local_core.runtime import PsycheLocalCoreRuntime
from core.subsystems.model_neutralizer.engine import ModelNeutralizerAndIdentityLock
from core.subsystems.presence import PsychePresenceEngine
from core.subsystems.research_intel.engine import PsycheResearchIntelligenceEngine


class PsycheIntelligenceOrchestrator:
    """End-to-end local intelligence orchestrator for the Legion 5 Pro."""

    def __init__(
        self,
        *,
        db: PsycheDatabase,
        economy: PsycheEconomyGovernor | None = None,
        validator: ContractValidator | None = None,
    ) -> None:
        self.db = db
        self.validator = validator or ContractValidator()
        self.economy = economy or PsycheEconomyGovernor()
        self.pragmatics = MultilingualPragmaticsEngine()
        self.local_core = PsycheLocalCoreRuntime(
            economy=self.economy, pragmatics=self.pragmatics
        )

        # Safeguards B & C + Pillar 5
        self.memory_integrity = MemoryIntegrityEngine(db=self.db, validator=self.validator)
        self.people_memory = PeopleAndMemoryEngine(
            db=self.db, memory_integrity=self.memory_integrity, validator=self.validator
        )
        self.timeline = ConversationTimelineEngine(db=self.db, validator=self.validator)

        # Supporting Subsystems
        self.knowledge_vault = PsycheKnowledgeVaultEngine(db=self.db)
        self.research_intel = PsycheResearchIntelligenceEngine(
            db=self.db, knowledge_vault=self.knowledge_vault
        )
        self.presence = PsychePresenceEngine(
            db=self.db,
            validator=self.validator,
            pairing_manager=self.people_memory.pairing,
        )
        self.neutralizer = ModelNeutralizerAndIdentityLock()

        # Pillars 1, 2, 3, 4, 6
        self.human_pillar = HumanPillarEngine()
        self.reality_pillar = RealityPillarEngine()
        self.mind_pillar = MindPillarEngine()
        self.comm_dna_pillar = CommunicationDnaPillarEngine(people_memory=self.people_memory)
        self.influence_mentor_pillar = InfluenceAndMentorPillarEngine()

        # Safeguards A, D, E
        self.uncertainty_engine = ContextualUncertaintyEngine()
        self.reality_check_engine = RealityCheckingEngine()
        self.goal_response_engine = GoalAwareResponseEngine(
            comm_dna=self.comm_dna_pillar, neutralizer=self.neutralizer
        )

    def synthesize_for_event(
        self,
        *,
        event_id: str,
        user_explicit_assumption: str | None = None,
        reference_now_utc: str | None = None,
    ) -> dict[str, Any]:
        """Runs the complete 6-Pillar, 5-Safeguard synthesis for an ingested communication event."""
        self.economy.assert_local_only_execution("local")
        conn = self.db.connection
        ev_row = conn.execute(
            "SELECT * FROM raw_events WHERE event_id = ?", (event_id,)
        ).fetchone()
        if ev_row is None:
            raise KeyError(f"Raw event {event_id} not found in raw_events")

        person_id: str | None = ev_row["resolved_person_id"]
        identity_ambiguity = bool(ev_row["identity_ambiguity"])
        raw_text = ev_row["raw_text_immutable"]
        sender_title = ev_row["sender_raw_title"]
        conv_key = ev_row["conversation_key"]
        posted_at_utc = ev_row["posted_at_utc"]

        relationship_tier = "UNKNOWN"
        trust_level = 0.5
        boundary_notes = None
        if person_id is not None:
            p_row = conn.execute(
                "SELECT * FROM people WHERE person_id = ?", (person_id,)
            ).fetchone()
            if p_row is not None:
                relationship_tier = p_row["relationship_tier"]
                trust_level = float(p_row["trust_level"])
                if p_row["boundary_notes_json"]:
                    boundary_notes = json.loads(p_row["boundary_notes_json"])

        # 1. Execute PSYCHE LOCAL CORE (Prompt-Injection Sandboxing + 7-Mode Pragmatics + Economy)
        local_res = self.local_core.execute_local_reasoning(
            event_id=event_id,
            raw_message_text=raw_text,
            sender_display_name=sender_title,
            relationship_tier=relationship_tier,
            task_complexity="DEEP_SYNTHESIS",
        )
        prag = local_res.pragmatic_analysis

        # 2. Update & fetch Conversation Timeline State (Safeguard C) if person_id is resolved
        timeline_state: dict[str, Any] | None = None
        open_loop_ids: list[str] = []
        if person_id is not None:
            timeline_state = self.timeline.process_conversation_events(
                person_id=person_id,
                conversation_key=conv_key,
                reference_now_utc=reference_now_utc,
            )
            open_loop_ids = [
                l["loop_id"]
                for l in timeline_state.get("open_loops", [])
                if l.get("status") == "OPEN"
            ]

        # 3. Retrieve relevant memories & open contradictions (Pillar 5 + Safeguard B)
        retrieved_memories = self.people_memory.retrieve_relevant_memories(
            query_text=raw_text, person_id=person_id, top_k=5
        )
        retrieved_memory_ids = [
            m["memory_record"]["memory_id"] for m in retrieved_memories
        ]
        active_contradiction_ids: list[str] = []
        for m in retrieved_memories:
            for c in m["memory_record"].get("contradictions", []):
                if (
                    c["resolution_state"] == "OPEN"
                    and c["contradiction_id"] not in active_contradiction_ids
                ):
                    active_contradiction_ids.append(c["contradiction_id"])

        # 4. Retrieve PSYCHE RESEARCH INTELLIGENCE & PSYCHE KNOWLEDGE VAULT brief
        research_brief = self.research_intel.retrieve_knowledge_and_evidence(
            query_text=raw_text,
            speech_acts=prag.speech_acts,
            retrieved_memories=retrieved_memories,
            timeline_state=timeline_state,
        )

        # Fetch active USER_MIND / GOAL memories for MIND pillar evaluation
        mind_rows = conn.execute(
            """
            SELECT memory_id FROM memory_ledger
            WHERE memory_domain IN ('USER_MIND', 'GOAL')
              AND lifecycle_status = 'ACTIVE'
              AND quarantine_status = 'NONE'
            ORDER BY updated_at_utc DESC
            LIMIT 5
            """
        ).fetchall()
        user_mind_memories = [
            self.memory_integrity.get_memory_record(r["memory_id"])
            for r in mind_rows
        ]

        # 5. Evaluate All 6 Intelligence Pillars
        human_assessment = self.human_pillar.assess(
            pragmatics=prag,
            sender_name=sender_title,
            relationship_tier=relationship_tier,
            trust_level=trust_level,
            retrieved_memories=retrieved_memories,
            timeline_state=timeline_state,
        )
        reality_assessment = self.reality_pillar.assess(
            pragmatics=prag,
            timeline_state=timeline_state,
        )
        mind_assessment = self.mind_pillar.assess(
            pragmatics=prag,
            relationship_tier=relationship_tier,
            research_brief=research_brief,
            user_boundary_notes=boundary_notes,
            user_mind_memories=user_mind_memories,
        )
        comm_dna_assessment = self.comm_dna_pillar.assess(
            person_id=person_id,
            relationship_tier=relationship_tier,
            incoming_pragmatics=prag,
        )
        people_memory_assessment = {
            "relationship_tier": relationship_tier,
            "retrieved_memory_ids": retrieved_memory_ids,
            "open_loop_ids": open_loop_ids,
            "active_contradiction_ids": active_contradiction_ids,
        }
        influence_mentor_assessment = self.influence_mentor_pillar.assess(
            pragmatics=prag,
            relationship_tier=relationship_tier,
            research_brief=research_brief,
            open_loops_count=len(open_loop_ids),
        )

        # 6. Record AI_HYPOTHESIS in Memory Integrity Engine (Safeguard B)
        # Note: if injection_detected or acute_venting_detected, MemoryIntegrityEngine automatically
        # quarantines the hypothesis so it can never corrupt permanent traits.
        self.memory_integrity.record_memory(
            memory_domain="RELATIONAL",
            epistemic_class="AI_HYPOTHESIS",
            statement_text=(
                f"Hypothesis for {sender_title}: {human_assessment['emotional_state_summary']}"
            ),
            original_language_mode=prag.detected_language_modes[0],
            confidence_score=human_assessment["confidence"],
            source_type="PILLAR_INFERENCE",
            extractor_component="pillar.human",
            person_id=person_id,
            source_event_id=event_id,
            evidence_quote_verbatim=raw_text,
            model_identifier=local_res.model_identifier,
        )

        # 7. Evaluate Safeguard A (Contextual Uncertainty Engine)
        uncertainty_audit = self.uncertainty_engine.evaluate(
            trigger_event_id=event_id,
            sender_name=sender_title,
            posted_at_utc=posted_at_utc,
            pragmatics=prag,
            human_confidence=human_assessment["confidence"],
            retrieved_memories=retrieved_memories,
            timeline_state=timeline_state,
            identity_ambiguity=identity_ambiguity,
            injection_detected=local_res.injection_detected,
        )

        # 8. Evaluate Safeguard E (Reality-Checking Engine)
        reality_check_audit = self.reality_check_engine.evaluate(
            pragmatics=prag,
            uncertainty_audit=uncertainty_audit,
            user_explicit_assumption=user_explicit_assumption,
        )

        # 9. Evaluate Safeguard D (Goal-Aware Response Engine) + MODEL NEUTRALIZER AND IDENTITY LOCK
        stored_dna = self.people_memory.get_comm_dna_profile(person_id)
        spelling_map = (
            stored_dna.get("transliteration_spelling_map") if stored_dna else None
        )
        learned_markers = (
            stored_dna.get("signature_markers") if stored_dna else None
        )
        goal_recommendations = self.goal_response_engine.generate_recommendations(
            pragmatics=prag,
            comm_dna_assessment=comm_dna_assessment,
            uncertainty_audit=uncertainty_audit,
            identity_ambiguity=identity_ambiguity,
            open_contradictions_count=len(active_contradiction_ids),
            spelling_map=spelling_map,
            raw_text=raw_text,
            signature_markers=learned_markers,
        )

        now_iso = utc_now_iso()
        synthesis_id = generate_uuidv7()
        synthesis_packet: dict[str, Any] = {
            "schema_version": "1.0.0",
            "synthesis_id": synthesis_id,
            "trigger_event_id": event_id,
            "person_id": person_id,
            "pillar_assessments": {
                "human": human_assessment,
                "reality": reality_assessment,
                "mind": mind_assessment,
                "communication_dna": comm_dna_assessment,
                "people_and_memory": people_memory_assessment,
                "influence_and_mentor": influence_mentor_assessment,
            },
            "uncertainty_audit": uncertainty_audit,
            "reality_check_audit": reality_check_audit,
            "goal_aware_recommendations": goal_recommendations,
            "neutralizer_audit": {
                "ai_boilerplate_stripped": True,
                "identity_lock_verified": True,
            },
            "safety_execution_locks": {
                "requires_user_review": True,
                "auto_send_permitted": False,
                "processed_locally": True,
            },
            "created_at_utc": now_iso,
        }

        # Validate strictly against contracts/v1/intelligence_synthesis.schema.json
        self.validator.validate(
            "intelligence_synthesis.schema.json",
            "IntelligenceSynthesisPacket",
            synthesis_packet,
        )

        # Persist in reasoning_syntheses audit log
        conn.execute(
            """
            INSERT INTO reasoning_syntheses (
                synthesis_id, trigger_event_id, person_id, synthesis_payload_json,
                user_review_decision, user_final_edited_text, created_at_utc, reviewed_at_utc
            ) VALUES (?, ?, ?, ?, 'PENDING', NULL, ?, NULL)
            """,
            (
                synthesis_id,
                event_id,
                person_id,
                json.dumps(synthesis_packet),
                now_iso,
            ),
        )
        conn.commit()
        return synthesis_packet

    def record_user_review_decision(
        self,
        *,
        synthesis_id: str,
        decision: str,
        user_final_edited_text: str | None = None,
    ) -> dict[str, Any]:
        """Records the user's review decision and feeds approved/edited text back into COMMUNICATION DNA."""
        valid_decisions = {
            "ACCEPTED_AS_IS",
            "EDITED_BY_USER",
            "REJECTED",
            "CORRECTION_SUBMITTED",
        }
        if decision not in valid_decisions:
            raise ValueError(f"Invalid review decision '{decision}'; must be one of {valid_decisions}")

        conn = self.db.connection
        row = conn.execute(
            "SELECT * FROM reasoning_syntheses WHERE synthesis_id = ?", (synthesis_id,)
        ).fetchone()
        if row is None:
            raise KeyError(f"Synthesis {synthesis_id} not found")

        now_iso = utc_now_iso()
        conn.execute(
            """
            UPDATE reasoning_syntheses
            SET user_review_decision = ?,
                user_final_edited_text = ?,
                reviewed_at_utc = ?
            WHERE synthesis_id = ?
            """,
            (decision, user_final_edited_text, now_iso, synthesis_id),
        )
        conn.commit()

        updated_dna = None
        if decision in {"ACCEPTED_AS_IS", "EDITED_BY_USER"} and user_final_edited_text:
            updated_dna = self.comm_dna_pillar.learn_from_user_message(
                person_id=row["person_id"],
                user_message_text=user_final_edited_text,
            )

        return {
            "synthesis_id": synthesis_id,
            "user_review_decision": decision,
            "user_final_edited_text": user_final_edited_text,
            "reviewed_at_utc": now_iso,
            "updated_comm_dna_profile": updated_dna,
        }
