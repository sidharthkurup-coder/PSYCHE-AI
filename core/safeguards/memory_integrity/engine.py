"""Safeguard B: Memory Integrity Engine (REQ-SAFE-02).

Enforces:
1. Four-tier epistemic classification: VERIFIED_FACT, USER_REPORT, OBSERVATION, AI_HYPOTHESIS.
2. Immutable provenance and UTC timestamps for every memory record.
3. Automated contradiction detection and linking across memories.
4. Non-destructive corrections, versioned superseding chains, recovery, and hard/soft deletion.
5. Emotional Quarantine (EMOTIONAL_TRANSIENT) preventing acute emotional venting from becoming
   permanent relationship or personal assumptions.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import re
from typing import Any

from core.contracts.validator import (
    ALL_VALID_LANGUAGE_TAGS,
    ContractValidator,
    normalize_phonetic_search_key,
)
from core.storage.database import PsycheDatabase, generate_uuidv7, utc_now_iso
from core.subsystems.fortress.crypto_vault import detect_prompt_injection_attempt

VALID_EPISTEMIC_CLASSES: frozenset[str] = frozenset(
    {"VERIFIED_FACT", "USER_REPORT", "OBSERVATION", "AI_HYPOTHESIS"}
)

VALID_MEMORY_DOMAINS: frozenset[str] = frozenset(
    {"EPISODIC", "SEMANTIC", "RELATIONAL", "USER_MIND", "COMM_STRATEGY", "GOAL"}
)

# Multilingual acute emotional venting / absolutist reaction markers across en, hi, ml, te
_EMOTIONAL_VENTING_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(
        r"\b(?:never\s+talking\s+to\s+\w+\s+again|completely\s+useless|i\s+hate\s+(?:him|her|them)|"
        r"dead\s+to\s+me|worst\s+person\s+ever|done\s+with\s+(?:him|her|them)\s+forever)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(?:ini\s+mindilla|onnum\s+parayanda|eppozhum\s+ithu\s+thanne|kabhi\s+baat\s+nahi\s+karunga|"
        r"bekar\s+insaan|eppatiki\s+matladanu|naaku\s+vaddu)\b",
        re.IGNORECASE,
    ),
)

_NEGATION_TOKENS: frozenset[str] = frozenset(
    {
        "not", "never", "no", "cannot", "cant", "wont", "dont", "didnt",
        "nahi", "nhi", "naa", "mat",
        "illa", "alla", "ariyilla", "pattilla", "varilla",
        "ledu", "kaadu", "kadu", "radhu", "vaddu",
        "नहीं", "मत", "ഇല്ല", "അല്ല", "വരില്ല", "లేదు", "కాదు",
    }
)


def detect_emotional_transient_reaction(text: str) -> tuple[bool, str | None]:
    """Detects acute emotional venting or absolutist heat-of-the-moment statements."""
    for pat in _EMOTIONAL_VENTING_PATTERNS:
        m = pat.search(text)
        if m:
            return True, f"Acute emotional reaction phrase detected: '{m.group(0)}'"
    # Check high exclamation + ALL-CAPS shouting ratio
    alpha_chars = [c for c in text if c.isalpha()]
    if len(alpha_chars) >= 15:
        upper_ratio = sum(1 for c in alpha_chars if c.isupper()) / len(alpha_chars)
        if upper_ratio > 0.75 and text.count("!") >= 2:
            return True, "High-arousal shouting/exclamation pattern detected"
    return False, None


def _extract_content_keywords_and_polarity(statement: str) -> tuple[set[str], bool]:
    """Extracts normalized content keywords and whether negation tokens are present."""
    raw_words = set(re.findall(r"\w+", statement.lower()))
    phonetic_words = set(re.findall(r"\w+", normalize_phonetic_search_key(statement)))
    all_words = raw_words | phonetic_words
    has_negation = bool(all_words & _NEGATION_TOKENS) or any(
        w.endswith(("illa", "alla", "ledu", "kadu")) and len(w) > 4 for w in all_words
    )
    stop_words = {
        "the", "is", "are", "was", "were", "to", "in", "on", "at", "for", "and", "or",
        "he", "she", "they", "user", "contact", "said", "that", "hai", "hain",
    } | _NEGATION_TOKENS
    keywords = {w for w in phonetic_words if len(w) >= 3 and w not in stop_words}
    return keywords, has_negation


class MemoryIntegrityEngine:
    """Manages provenance-backed memory creation, contradiction detection, quarantine, and corrections."""

    def __init__(
        self,
        db: PsycheDatabase,
        validator: ContractValidator | None = None,
        emotional_cooldown_hours: int = 72,
    ) -> None:
        self.db = db
        self.validator = validator or ContractValidator()
        self.emotional_cooldown_hours = emotional_cooldown_hours

    def record_memory(
        self,
        *,
        memory_domain: str,
        epistemic_class: str,
        statement_text: str,
        original_language_mode: str,
        confidence_score: float,
        source_type: str,
        extractor_component: str,
        person_id: str | None = None,
        source_event_id: str | None = None,
        evidence_quote_verbatim: str | None = None,
        model_identifier: str | None = None,
        force_quarantine_status: str | None = None,
        force_quarantine_reason: str | None = None,
    ) -> dict[str, Any]:
        """Records a new memory with full provenance, emotional/injection quarantine, and contradiction checks."""
        if epistemic_class not in VALID_EPISTEMIC_CLASSES:
            raise ValueError(f"Invalid epistemic_class: {epistemic_class}")
        if memory_domain not in VALID_MEMORY_DOMAINS:
            raise ValueError(f"Invalid memory_domain: {memory_domain}")
        if original_language_mode not in ALL_VALID_LANGUAGE_TAGS:
            raise ValueError(f"Unauthorized language mode: {original_language_mode}")
        if not (0.0 <= confidence_score <= 1.0):
            raise ValueError("confidence_score must be in [0.0, 1.0]")

        now_dt = datetime.now(timezone.utc)
        now_iso = now_dt.strftime("%Y-%m-%dT%H:%M:%SZ")

        # Determine quarantine status (Injection -> Ambiguous -> Emotional -> None)
        quarantine_status = force_quarantine_status or "NONE"
        quarantine_reason = force_quarantine_reason
        quarantine_expires_utc: str | None = None

        probe_text = f"{statement_text} {evidence_quote_verbatim or ''}"
        is_inj, inj_reason = detect_prompt_injection_attempt(probe_text)
        if is_inj:
            quarantine_status = "SUSPECTED_INJECTION"
            quarantine_reason = inj_reason
        elif quarantine_status == "NONE":
            is_emo, emo_reason = detect_emotional_transient_reaction(probe_text)
            if is_emo and epistemic_class in {"USER_REPORT", "AI_HYPOTHESIS"}:
                quarantine_status = "EMOTIONAL_TRANSIENT"
                quarantine_reason = emo_reason
                exp_dt = now_dt + timedelta(hours=self.emotional_cooldown_hours)
                quarantine_expires_utc = exp_dt.strftime("%Y-%m-%dT%H:%M:%SZ")

        memory_id = generate_uuidv7()
        provenance_id = generate_uuidv7()

        # Only index non-injection memories into the semantic vector store
        emb_idx: int | None = None
        if quarantine_status != "SUSPECTED_INJECTION":
            emb_idx = self.db.append_embedding(statement_text)

        conn = self.db.connection
        conn.execute(
            """
            INSERT INTO memory_ledger (
                memory_id, person_id, memory_domain, epistemic_class,
                statement_text, original_language_mode, confidence_score,
                quarantine_status, quarantine_reason, quarantine_expires_utc,
                lifecycle_status, revision_number, supersedes_memory_id,
                superseded_by_memory_id, correction_note, embedding_row_index,
                created_at_utc, updated_at_utc
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'ACTIVE', 1, NULL, NULL, NULL, ?, ?, ?)
            """,
            (
                memory_id,
                person_id,
                memory_domain,
                epistemic_class,
                statement_text,
                original_language_mode,
                confidence_score,
                quarantine_status,
                quarantine_reason,
                quarantine_expires_utc,
                emb_idx,
                now_iso,
                now_iso,
            ),
        )

        conn.execute(
            """
            INSERT INTO memory_provenance (
                provenance_id, memory_id, source_type, source_event_id,
                evidence_quote_verbatim, extractor_component, model_identifier, captured_at_utc
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                provenance_id,
                memory_id,
                source_type,
                source_event_id,
                evidence_quote_verbatim,
                extractor_component,
                model_identifier,
                now_iso,
            ),
        )

        # Detect contradictions against existing ACTIVE memories for the same person
        if quarantine_status != "SUSPECTED_INJECTION":
            self._detect_and_record_contradictions(
                new_memory_id=memory_id,
                person_id=person_id,
                memory_domain=memory_domain,
                statement_text=statement_text,
                detected_at_utc=now_iso,
            )

        conn.commit()
        return self.get_memory_record(memory_id)

    def _detect_and_record_contradictions(
        self,
        *,
        new_memory_id: str,
        person_id: str | None,
        memory_domain: str,
        statement_text: str,
        detected_at_utc: str,
    ) -> list[str]:
        """Detects semantic topic overlap with opposing polarity or conflicting claims."""
        conn = self.db.connection
        if person_id is not None:
            existing_rows = conn.execute(
                """
                SELECT memory_id, statement_text, epistemic_class
                FROM memory_ledger
                WHERE person_id = ? AND memory_domain = ?
                  AND lifecycle_status = 'ACTIVE' AND memory_id != ?
                  AND quarantine_status != 'SUSPECTED_INJECTION'
                """,
                (person_id, memory_domain, new_memory_id),
            ).fetchall()
        else:
            existing_rows = conn.execute(
                """
                SELECT memory_id, statement_text, epistemic_class
                FROM memory_ledger
                WHERE person_id IS NULL AND memory_domain = ?
                  AND lifecycle_status = 'ACTIVE' AND memory_id != ?
                  AND quarantine_status != 'SUSPECTED_INJECTION'
                """,
                (memory_domain, new_memory_id),
            ).fetchall()

        new_kw, new_neg = _extract_content_keywords_and_polarity(statement_text)
        if not new_kw:
            return []

        created_contradiction_ids: list[str] = []
        for row in existing_rows:
            old_kw, old_neg = _extract_content_keywords_and_polarity(row["statement_text"])
            if not old_kw:
                continue
            overlap = new_kw & old_kw
            union = new_kw | old_kw
            jaccard = len(overlap) / len(union) if union else 0.0
            # If high subject/action overlap (>= 2 shared keywords or >= 0.35 Jaccard) and opposite negation polarity
            if (len(overlap) >= 2 or jaccard >= 0.35) and (new_neg != old_neg):
                cid = generate_uuidv7()
                desc = (
                    f"Polarity contradiction on shared topic ({', '.join(sorted(overlap))}): "
                    f"'{row['statement_text']}' vs. '{statement_text}'"
                )
                conn.execute(
                    """
                    INSERT INTO memory_contradictions (
                        contradiction_id, memory_id_primary, memory_id_conflicting,
                        conflict_description, severity, resolution_state, detected_at_utc, resolved_at_utc
                    ) VALUES (?, ?, ?, ?, 'HIGH', 'OPEN', ?, NULL)
                    """,
                    (cid, new_memory_id, row["memory_id"], desc, detected_at_utc),
                )
                created_contradiction_ids.append(cid)
        return created_contradiction_ids

    def correct_memory(
        self,
        target_memory_id: str,
        *,
        corrected_statement: str,
        correction_note: str,
        new_epistemic_class: str | None = None,
        new_confidence_score: float | None = None,
    ) -> dict[str, Any]:
        """Non-destructively supersedes an existing memory with a new versioned revision."""
        conn = self.db.connection
        old_row = conn.execute(
            "SELECT * FROM memory_ledger WHERE memory_id = ?", (target_memory_id,)
        ).fetchone()
        if old_row is None:
            raise KeyError(f"Memory {target_memory_id} not found")
        if old_row["lifecycle_status"] != "ACTIVE":
            raise ValueError(
                f"Cannot supersede memory {target_memory_id} with status {old_row['lifecycle_status']}"
            )

        now_iso = utc_now_iso()
        new_memory_id = generate_uuidv7()
        new_rev = int(old_row["revision_number"]) + 1
        ep_class = new_epistemic_class or old_row["epistemic_class"]
        conf = (
            new_confidence_score
            if new_confidence_score is not None
            else float(old_row["confidence_score"])
        )
        emb_idx = self.db.append_embedding(corrected_statement)

        # Insert new revision
        conn.execute(
            """
            INSERT INTO memory_ledger (
                memory_id, person_id, memory_domain, epistemic_class,
                statement_text, original_language_mode, confidence_score,
                quarantine_status, quarantine_reason, quarantine_expires_utc,
                lifecycle_status, revision_number, supersedes_memory_id,
                superseded_by_memory_id, correction_note, embedding_row_index,
                created_at_utc, updated_at_utc
            ) VALUES (?, ?, ?, ?, ?, ?, ?, 'NONE', NULL, NULL, 'ACTIVE', ?, ?, NULL, ?, ?, ?, ?)
            """,
            (
                new_memory_id,
                old_row["person_id"],
                old_row["memory_domain"],
                ep_class,
                corrected_statement,
                old_row["original_language_mode"],
                conf,
                new_rev,
                target_memory_id,
                correction_note,
                emb_idx,
                now_iso,
                now_iso,
            ),
        )

        # Mark old revision as SUPERSEDED
        conn.execute(
            """
            UPDATE memory_ledger
            SET lifecycle_status = 'SUPERSEDED',
                superseded_by_memory_id = ?,
                updated_at_utc = ?
            WHERE memory_id = ?
            """,
            (new_memory_id, now_iso, target_memory_id),
        )

        # Attach USER_CORRECTION provenance
        conn.execute(
            """
            INSERT INTO memory_provenance (
                provenance_id, memory_id, source_type, source_event_id,
                evidence_quote_verbatim, extractor_component, model_identifier, captured_at_utc
            ) VALUES (?, ?, 'USER_CORRECTION', NULL, ?, 'safeguard.memory_integrity', NULL, ?)
            """,
            (generate_uuidv7(), new_memory_id, correction_note, now_iso),
        )

        # Resolve open contradictions tied to the old superseded memory
        conn.execute(
            """
            UPDATE memory_contradictions
            SET resolution_state = 'RESOLVED_BY_USER', resolved_at_utc = ?
            WHERE (memory_id_primary = ? OR memory_id_conflicting = ?)
              AND resolution_state = 'OPEN'
            """,
            (now_iso, target_memory_id, target_memory_id),
        )

        conn.commit()
        return self.get_memory_record(new_memory_id)

    def delete_memory(self, memory_id: str, *, reason: str = "User requested deletion") -> None:
        """Marks memory DELETED, zeroes its vector row, and redacts provenance & contradiction quotes."""
        conn = self.db.connection
        row = conn.execute(
            "SELECT embedding_row_index FROM memory_ledger WHERE memory_id = ?", (memory_id,)
        ).fetchone()
        if row is None:
            raise KeyError(f"Memory {memory_id} not found")

        emb_idx = row["embedding_row_index"]
        if emb_idx is not None and 0 <= int(emb_idx) < self.db._vectors.shape[0]:
            self.db._vectors[int(emb_idx)] = 0.0
            self.db.save_vectors()

        now_iso = utc_now_iso()
        conn.execute(
            """
            UPDATE memory_ledger
            SET lifecycle_status = 'DELETED',
                statement_text = '[DELETED_BY_USER]',
                correction_note = ?,
                updated_at_utc = ?
            WHERE memory_id = ?
            """,
            (reason, now_iso, memory_id),
        )
        conn.execute(
            """
            UPDATE memory_provenance
            SET evidence_quote_verbatim = '[DELETED_BY_USER]'
            WHERE memory_id = ?
            """,
            (memory_id,),
        )
        conn.execute(
            """
            UPDATE memory_contradictions
            SET resolution_state = 'RESOLVED_BY_USER',
                conflict_description = '[REDACTED_DUE_TO_MEMORY_DELETION]',
                resolved_at_utc = ?
            WHERE memory_id_primary = ? OR memory_id_conflicting = ?
            """,
            (now_iso, memory_id, memory_id),
        )
        conn.commit()
        return self.get_memory_record(memory_id)

    def release_emotional_quarantine(
        self, memory_id: str, *, confirmed_by_user: bool = True, note: str = "Confirmed after cooldown"
    ) -> dict[str, Any]:
        """Releases or retracts an EMOTIONAL_TRANSIENT memory after user review post-cooldown."""
        conn = self.db.connection
        row = conn.execute(
            "SELECT * FROM memory_ledger WHERE memory_id = ?", (memory_id,)
        ).fetchone()
        if row is None:
            raise KeyError(f"Memory {memory_id} not found")
        now_iso = utc_now_iso()
        if confirmed_by_user:
            conn.execute(
                """
                UPDATE memory_ledger
                SET quarantine_status = 'NONE',
                    quarantine_reason = NULL,
                    quarantine_expires_utc = NULL,
                    correction_note = ?,
                    updated_at_utc = ?
                WHERE memory_id = ?
                """,
                (note, now_iso, memory_id),
            )
        else:
            conn.execute(
                """
                UPDATE memory_ledger
                SET lifecycle_status = 'RETRACTED_BY_USER',
                    correction_note = ?,
                    updated_at_utc = ?
                WHERE memory_id = ?
                """,
                (note, now_iso, memory_id),
            )
        conn.commit()
        return self.get_memory_record(memory_id)

    def get_memory_record(self, memory_id: str) -> dict[str, Any]:
        """Returns a MemoryRecord dictionary validated against contracts/v1/memory_record.schema.json."""
        conn = self.db.connection
        row = conn.execute(
            "SELECT * FROM memory_ledger WHERE memory_id = ?", (memory_id,)
        ).fetchone()
        if row is None:
            raise KeyError(f"Memory {memory_id} not found")

        prov_rows = conn.execute(
            "SELECT * FROM memory_provenance WHERE memory_id = ? ORDER BY captured_at_utc ASC",
            (memory_id,),
        ).fetchall()

        contra_rows = conn.execute(
            """
            SELECT * FROM memory_contradictions
            WHERE memory_id_primary = ? OR memory_id_conflicting = ?
            ORDER BY detected_at_utc ASC
            """,
            (memory_id, memory_id),
        ).fetchall()

        provenance_list = [
            {
                "provenance_id": p["provenance_id"],
                "source_type": p["source_type"],
                "source_event_id": p["source_event_id"],
                "evidence_quote_verbatim": p["evidence_quote_verbatim"],
                "extractor_component": p["extractor_component"],
                "model_identifier": p["model_identifier"],
                "captured_at_utc": p["captured_at_utc"],
            }
            for p in prov_rows
        ]

        contradictions_list = [
            {
                "contradiction_id": c["contradiction_id"],
                "conflicting_memory_id": (
                    c["memory_id_conflicting"]
                    if c["memory_id_primary"] == memory_id
                    else c["memory_id_primary"]
                ),
                "conflict_description": c["conflict_description"],
                "severity": c["severity"],
                "resolution_state": c["resolution_state"],
                "detected_at_utc": c["detected_at_utc"],
            }
            for c in contra_rows
        ]

        record = {
            "schema_version": "1.0.0",
            "memory_id": row["memory_id"],
            "person_id": row["person_id"],
            "memory_domain": row["memory_domain"],
            "epistemic_class": row["epistemic_class"],
            "statement_text": row["statement_text"],
            "original_language_mode": row["original_language_mode"],
            "confidence_score": float(row["confidence_score"]),
            "quarantine": {
                "status": row["quarantine_status"],
                "reason": row["quarantine_reason"],
                "expires_at_utc": row["quarantine_expires_utc"],
            },
            "lifecycle": {
                "status": row["lifecycle_status"],
                "revision_number": int(row["revision_number"]),
                "supersedes_memory_id": row["supersedes_memory_id"],
                "superseded_by_memory_id": row["superseded_by_memory_id"],
                "correction_note": row["correction_note"],
            },
            "provenance": provenance_list,
            "contradictions": contradictions_list,
            "created_at_utc": row["created_at_utc"],
            "updated_at_utc": row["updated_at_utc"],
        }
        self.validator.validate("memory_record.schema.json", "MemoryRecord", record)
        return record
