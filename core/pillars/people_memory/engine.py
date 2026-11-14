"""Pillar 5: PEOPLE AND MEMORY — Entity Graph, Cross-Script Alias Resolution & Hybrid Retrieval.

Implements:
- Android ContactSyncRequest processing with cross-script alias resolution (en, hi-Latn/Deva,
  ml-Latn/Mlym, te-Latn/Telu) and identity-ambiguity detection (REQ-PIL-05, REQ-AND-02).
- Android NotificationIngestRequest batch ingestion with verbatim raw_text_immutable preservation,
  FTS5 indexing, and automatic Memory Integrity Engine provenance recording.
- Four-signal hybrid memory retrieval (Vector Cosine + FTS5 BM25 + Person Graph + Temporal Decay
  weighted by Epistemic Class Priors) with mandatory Contradiction & Quarantine Co-Retrieval
  (REQ-SAFE-06, DATA_MODEL.md Section 4).
- Emotional Quarantine guardrail: quarantined memories can NEVER alter permanent person trust_level
  or relationship_tier (REQ-SAFE-02).
"""

from __future__ import annotations

from datetime import datetime, timezone
import json
import math
import re
from typing import Any

from core.contracts.validator import (
    ContractValidationError,
    ContractValidator,
    normalize_phonetic_search_key,
)
from core.safeguards.memory_integrity.engine import MemoryIntegrityEngine
from core.storage.database import PsycheDatabase, generate_uuidv7, utc_now_iso
from core.subsystems.fortress.pairing import (
    FortressPairingManager,
    canonical_batch_bytes,
    canonical_contact_sync_bytes,
    canonical_event_bytes,
)

EPISTEMIC_PRIORS: dict[str, float] = {
    "VERIFIED_FACT": 1.00,
    "OBSERVATION": 0.90,
    "USER_REPORT": 0.80,
    "AI_HYPOTHESIS": 0.60,
}

# Honorifics stripped when computing canonical phonetic person alias keys
_HONORIFIC_SUFFIXES: tuple[str, ...] = (
    "chechi", "chetta", "chettan", "garu", "gaaru", "bhai", "didi", "anna", "akka", "sir", "mam",
)


def _canonical_person_phonetic_key(name: str) -> str:
    """Computes a canonical phonetic key for a contact name, stripping parenthetical script annotations."""
    # If name is like "Ammu (അമ്മു)", take the primary display segment and also normalize
    primary = re.sub(r"\(.*?\)", "", name).strip() or name
    phonetic = normalize_phonetic_search_key(primary)
    tokens = [t for t in phonetic.split() if t not in _HONORIFIC_SUFFIXES]
    return " ".join(tokens) if tokens else phonetic


class PeopleAndMemoryEngine:
    """Manages the PEOPLE entity graph, notification ingestion, and hybrid memory retrieval."""

    def __init__(
        self,
        db: PsycheDatabase,
        memory_integrity: MemoryIntegrityEngine | None = None,
        validator: ContractValidator | None = None,
        pairing_manager: FortressPairingManager | None = None,
    ) -> None:
        self.db = db
        self.validator = validator or ContractValidator()
        self.memory_integrity = memory_integrity or MemoryIntegrityEngine(
            db=self.db, validator=self.validator
        )
        self.pairing = pairing_manager or FortressPairingManager(
            db=self.db, validator=self.validator
        )

    def register_paired_device(
        self,
        *,
        device_id: str,
        device_name: str,
        ed25519_public_key_b64: str,
        tls_cert_sha256_pin: str,
    ) -> None:
        """Registers or updates a trusted Android companion device in paired_devices."""
        conn = self.db.connection
        now_iso = utc_now_iso()
        conn.execute(
            """
            INSERT INTO paired_devices (
                device_id, device_name, ed25519_public_key_b64,
                tls_cert_sha256_pin, paired_at_utc, last_seen_at_utc, trust_status
            ) VALUES (?, ?, ?, ?, ?, ?, 'ACTIVE')
            ON CONFLICT(device_id) DO UPDATE SET
                device_name = excluded.device_name,
                ed25519_public_key_b64 = excluded.ed25519_public_key_b64,
                tls_cert_sha256_pin = excluded.tls_cert_sha256_pin,
                last_seen_at_utc = excluded.last_seen_at_utc,
                trust_status = 'ACTIVE'
            """,
            (device_id, device_name, ed25519_public_key_b64, tls_cert_sha256_pin, now_iso, now_iso),
        )
        conn.commit()

    def create_or_update_person(
        self,
        *,
        canonical_display_name: str,
        relationship_tier: str = "UNKNOWN",
        trust_level: float = 0.5,
        android_contact_lookup_key: str | None = None,
        aliases: list[dict[str, Any]] | None = None,
        normalized_phone_hashes: list[str] | None = None,
        boundary_notes: dict[str, Any] | list[str] | None = None,
        source_quarantine_status: str = "NONE",
    ) -> str:
        """Creates or updates a canonical person entity and their cross-script aliases.

        Enforces Safeguard B: if source_quarantine_status == 'EMOTIONAL_TRANSIENT' or
        'SUSPECTED_INJECTION', blocks any modification to relationship_tier or trust_level.
        """
        if source_quarantine_status in {"EMOTIONAL_TRANSIENT", "SUSPECTED_INJECTION"}:
            raise ValueError(
                f"Memory Integrity Safeguard: cannot mutate permanent PEOPLE traits from "
                f"quarantined context ({source_quarantine_status})"
            )

        conn = self.db.connection
        now_iso = utc_now_iso()
        boundary_json = json.dumps(boundary_notes) if boundary_notes is not None else None

        existing_id: str | None = None
        if android_contact_lookup_key:
            row = conn.execute(
                "SELECT person_id FROM people WHERE android_contact_lookup_key = ?",
                (android_contact_lookup_key,),
            ).fetchone()
            if row:
                existing_id = row["person_id"]

        if existing_id is None and normalized_phone_hashes:
            for ph in normalized_phone_hashes:
                row = conn.execute(
                    "SELECT person_id FROM person_aliases WHERE normalized_phone_sha256 = ? LIMIT 1",
                    (ph,),
                ).fetchone()
                if row:
                    existing_id = row["person_id"]
                    break

        if existing_id is None:
            person_id = generate_uuidv7()
            conn.execute(
                """
                INSERT INTO people (
                    person_id, canonical_display_name, android_contact_lookup_key,
                    relationship_tier, trust_level, boundary_notes_json, created_at_utc, updated_at_utc
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    person_id,
                    canonical_display_name,
                    android_contact_lookup_key,
                    relationship_tier,
                    trust_level,
                    boundary_json,
                    now_iso,
                    now_iso,
                ),
            )
        else:
            person_id = existing_id
            conn.execute(
                """
                UPDATE people
                SET canonical_display_name = ?,
                    relationship_tier = CASE WHEN ? != 'UNKNOWN' THEN ? ELSE relationship_tier END,
                    trust_level = ?,
                    boundary_notes_json = COALESCE(?, boundary_notes_json),
                    updated_at_utc = ?
                WHERE person_id = ?
                """,
                (
                    canonical_display_name,
                    relationship_tier,
                    relationship_tier,
                    trust_level,
                    boundary_json,
                    now_iso,
                    person_id,
                ),
            )

        # Register canonical display name as an alias plus any explicit cross-script aliases
        all_aliases = list(aliases or [])
        all_aliases.append(
            {
                "alias_text": canonical_display_name,
                "language_mode": "en",
                "match_confidence": 1.0,
            }
        )
        phone_hash_primary = (normalized_phone_hashes or [None])[0]

        for al in all_aliases:
            alias_text = al["alias_text"]
            lang_mode = al.get("language_mode", "en")
            conf = float(al.get("match_confidence", 0.95))
            phonetic_key = _canonical_person_phonetic_key(alias_text)
            dup = conn.execute(
                """
                SELECT alias_id FROM person_aliases
                WHERE person_id = ? AND alias_text = ? AND language_mode = ?
                """,
                (person_id, alias_text, lang_mode),
            ).fetchone()
            if not dup:
                conn.execute(
                    """
                    INSERT INTO person_aliases (
                        alias_id, person_id, alias_text, language_mode,
                        phonetic_key, platform_package, normalized_phone_sha256,
                        match_confidence, verified_by_user
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1)
                    """,
                    (
                        generate_uuidv7(),
                        person_id,
                        alias_text,
                        lang_mode,
                        phonetic_key,
                        al.get("platform_package"),
                        phone_hash_primary,
                        conf,
                    ),
                )

        conn.commit()
        return person_id

    def resolve_sender_identity(
        self,
        *,
        raw_title: str,
        android_contact_lookup_key: str | None = None,
        normalized_phone_sha256: str | None = None,
    ) -> tuple[str | None, list[str], bool]:
        """Resolves a notification sender to (resolved_person_id, candidate_person_ids, is_ambiguous).

        Stage 1: Deterministic match via android_contact_lookup_key or normalized_phone_sha256.
        Stage 2: Cross-script & transliterated phonetic alias resolution.
        Stage 3: Ambiguity quarantine if >= 2 distinct people match the alias without a unique handle.
        """
        conn = self.db.connection
        if android_contact_lookup_key:
            row = conn.execute(
                "SELECT person_id FROM people WHERE android_contact_lookup_key = ?",
                (android_contact_lookup_key,),
            ).fetchone()
            if row:
                return row["person_id"], [row["person_id"]], False

        if normalized_phone_sha256:
            rows = conn.execute(
                "SELECT DISTINCT person_id FROM person_aliases WHERE normalized_phone_sha256 = ?",
                (normalized_phone_sha256,),
            ).fetchall()
            if len(rows) == 1:
                pid = rows[0]["person_id"]
                return pid, [pid], False

        phonetic_target = _canonical_person_phonetic_key(raw_title)
        rows = conn.execute(
            """
            SELECT DISTINCT person_id FROM person_aliases
            WHERE LOWER(alias_text) = LOWER(?) OR phonetic_key = ?
            """,
            (raw_title.strip(), phonetic_target),
        ).fetchall()
        candidates = [r["person_id"] for r in rows]
        if len(candidates) == 1:
            return candidates[0], candidates, False
        if len(candidates) > 1:
            # Ambiguous identity: do not guess silently!
            return None, candidates, True
        return None, [], False

    def sync_android_contacts(
        self,
        request_payload: dict[str, Any],
        *,
        require_crypto_signature: bool = False,
    ) -> dict[str, Any]:
        """Processes a ContactSyncRequest, verifies Ed25519 signature if keyed, and returns ContactSyncResponse."""
        self.validator.validate("contact_sync.schema.json", "ContactSyncRequest", request_payload)
        self.pairing.verify_device_signature(
            device_id=request_payload["device_id"],
            canonical_payload=canonical_contact_sync_bytes(request_payload),
            signature_b64=request_payload["ed25519_signature"],
            require_crypto=require_crypto_signature,
        )

        resolved_mappings: list[dict[str, Any]] = []
        ambiguous_lookup_keys: list[str] = []

        # Track phonetic names seen across distinct lookup keys to flag collisions
        phonetic_to_lookup_keys: dict[str, set[str]] = {}
        for c in request_payload["contacts"]:
            pkey = _canonical_person_phonetic_key(c["display_name"])
            phonetic_to_lookup_keys.setdefault(pkey, set()).add(c["android_contact_lookup_key"])

        for c in request_payload["contacts"]:
            lookup_key = c["android_contact_lookup_key"]
            display_name = c["display_name"]
            tier = "CLOSE_FRIEND" if c.get("starred_on_android") else "ACQUAINTANCE"
            person_id = self.create_or_update_person(
                canonical_display_name=display_name,
                relationship_tier=tier,
                trust_level=0.75 if c.get("starred_on_android") else 0.5,
                android_contact_lookup_key=lookup_key,
                aliases=c.get("aliases", []),
                normalized_phone_hashes=c.get("normalized_phone_hashes", []),
            )
            person_row = self.db.connection.execute(
                "SELECT relationship_tier FROM people WHERE person_id = ?", (person_id,)
            ).fetchone()
            resolved_mappings.append(
                {
                    "android_contact_lookup_key": lookup_key,
                    "person_id": person_id,
                    "relationship_tier": person_row["relationship_tier"],
                }
            )
            pkey = _canonical_person_phonetic_key(display_name)
            if len(phonetic_to_lookup_keys.get(pkey, set())) > 1:
                ambiguous_lookup_keys.append(lookup_key)

        response = {
            "schema_version": "1.0.0",
            "sync_batch_id": request_payload["sync_batch_id"],
            "processed_at_utc": utc_now_iso(),
            "resolved_mappings": resolved_mappings,
            "ambiguous_lookup_keys": ambiguous_lookup_keys,
        }
        self.validator.validate("contact_sync.schema.json", "ContactSyncResponse", response)
        return response

    def ingest_notification_batch(
        self,
        request_payload: dict[str, Any],
        *,
        require_crypto_signature: bool = False,
        enforce_clock_skew: bool = False,
        reference_now_utc: str | None = None,
    ) -> dict[str, Any]:
        """Processes a NotificationIngestRequest batch with Ed25519 verification & replay defense."""
        self.validator.validate(
            "notification_ingest.schema.json", "NotificationIngestRequest", request_payload
        )
        conn = self.db.connection
        device_id = request_payload["device_id"]

        # Verify device is paired, active, and batch Ed25519 signature + replay window pass
        self.pairing.verify_device_signature(
            device_id=device_id,
            canonical_payload=canonical_batch_bytes(request_payload),
            signature_b64=request_payload["batch_ed25519_signature"],
            require_crypto=require_crypto_signature,
        )
        self.pairing.check_replay_and_clock_skew(
            batch_id=request_payload["batch_id"],
            device_id=device_id,
            sent_at_utc=request_payload["sent_at_utc"],
            reference_now_utc=reference_now_utc,
            enforce_clock_skew=enforce_clock_skew,
        )

        acked_ids: list[str] = []
        duplicate_ids: list[str] = []
        rejected_events: list[dict[str, Any]] = []
        now_iso = utc_now_iso()

        for ev in request_payload["events"]:
            ev_id = ev["event_id"]
            try:
                self.validator.validate(
                    "notification_ingest.schema.json", "NotificationEventItem", ev
                )
            except ContractValidationError as exc:
                rejected_events.append(
                    {
                        "event_id": ev_id,
                        "error_code": exc.error_code,
                        "reason": str(exc),
                    }
                )
                continue

            try:
                self.pairing.verify_device_signature(
                    device_id=device_id,
                    canonical_payload=canonical_event_bytes(ev),
                    signature_b64=ev["security"]["ed25519_event_signature"],
                    require_crypto=require_crypto_signature,
                )
            except PermissionError as exc:
                rejected_events.append(
                    {
                        "event_id": ev_id,
                        "error_code": "INVALID_ED25519_SIGNATURE",
                        "reason": str(exc),
                    }
                )
                continue

            # Check duplicate by event_id or unique (package_name, conversation_key, raw_text_sha256, posted_at_utc)
            existing = conn.execute(
                """
                SELECT event_id FROM raw_events
                WHERE event_id = ?
                   OR (package_name = ? AND conversation_key = ? AND raw_text_sha256 = ? AND posted_at_utc = ?)
                """,
                (
                    ev_id,
                    ev["package_name"],
                    ev["conversation_key"],
                    ev["content"]["raw_text_sha256"],
                    ev["posted_at_utc"],
                ),
            ).fetchone()
            if existing is not None:
                duplicate_ids.append(ev_id)
                continue

            sender_info = ev["sender"]
            resolved_pid, candidates, is_ambiguous = self.resolve_sender_identity(
                raw_title=sender_info["raw_title"],
                android_contact_lookup_key=sender_info.get("android_contact_lookup_key"),
                normalized_phone_sha256=sender_info.get("normalized_phone_sha256"),
            )
            if sender_info.get("identity_ambiguity"):
                is_ambiguous = True

            raw_text = ev["content"]["raw_text_immutable"]
            phonetic_norm = normalize_phonetic_search_key(raw_text)
            lang_modes = ev["content"]["detected_language_modes"]

            conn.execute(
                """
                INSERT INTO raw_events (
                    event_id, device_id, package_name, notification_category,
                    conversation_key, is_group_conversation, group_title, direction,
                    sender_raw_title, resolved_person_id, identity_ambiguity,
                    raw_text_immutable, raw_text_sha256, detected_language_modes_json,
                    token_language_spans_json, phonetic_search_normalized,
                    posted_at_utc, ingested_at_utc, untrusted_external_input, ed25519_signature_b64
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?)
                """,
                (
                    ev_id,
                    device_id,
                    ev["package_name"],
                    ev["notification_category"],
                    ev["conversation_key"],
                    1 if ev["is_group_conversation"] else 0,
                    ev.get("group_title"),
                    ev["direction"],
                    sender_info["raw_title"],
                    resolved_pid,
                    1 if is_ambiguous else 0,
                    raw_text,
                    ev["content"]["raw_text_sha256"],
                    json.dumps(lang_modes),
                    json.dumps(ev["content"].get("token_language_spans", [])),
                    phonetic_norm,
                    ev["posted_at_utc"],
                    now_iso,
                    ev["security"]["ed25519_event_signature"],
                ),
            )

            conn.execute(
                """
                INSERT INTO raw_events_fts (
                    event_id, sender_raw_title, raw_text_immutable, phonetic_search_normalized
                ) VALUES (?, ?, ?, ?)
                """,
                (ev_id, sender_info["raw_title"], raw_text, phonetic_norm),
            )

            # Record episodic observation in Memory Integrity Engine
            q_status = "IDENTITY_AMBIGUOUS" if is_ambiguous else "NONE"
            q_reason = (
                f"Multiple candidate contacts matched '{sender_info['raw_title']}': {candidates}"
                if is_ambiguous
                else None
            )
            self.memory_integrity.record_memory(
                memory_domain="EPISODIC",
                epistemic_class="VERIFIED_FACT",
                statement_text=f"{sender_info['raw_title']} sent message: {raw_text}",
                original_language_mode=lang_modes[0],
                confidence_score=1.0 if not is_ambiguous else 0.5,
                source_type="ANDROID_NOTIFICATION",
                extractor_component="pillar.people_memory.ingest",
                person_id=resolved_pid,
                source_event_id=ev_id,
                evidence_quote_verbatim=raw_text,
                force_quarantine_status=q_status,
                force_quarantine_reason=q_reason,
            )

            acked_ids.append(ev_id)

        conn.commit()
        response = {
            "schema_version": "1.0.0",
            "batch_id": request_payload["batch_id"],
            "processed_at_utc": utc_now_iso(),
            "acked_event_ids": acked_ids,
            "duplicate_event_ids": duplicate_ids,
            "rejected_events": rejected_events,
        }
        self.validator.validate(
            "notification_ingest.schema.json", "NotificationIngestResponse", response
        )
        return response

    def retrieve_relevant_memories(
        self,
        *,
        query_text: str,
        person_id: str | None = None,
        top_k: int = 5,
    ) -> list[dict[str, Any]]:
        """Four-signal hybrid memory retrieval with mandatory contradiction & quarantine co-retrieval.

        Combines:
        1. Semantic vector similarity (NumPy float16 cosine)
        2. Lexical + phonetic overlap (FTS5 / normalized tokens)
        3. Person entity graph proximity
        4. Temporal recency decay weighted by Epistemic Class Priors
        """
        conn = self.db.connection
        active_rows = conn.execute(
            """
            SELECT * FROM memory_ledger
            WHERE lifecycle_status = 'ACTIVE'
              AND quarantine_status != 'SUSPECTED_INJECTION'
            """
        ).fetchall()
        if not active_rows:
            return []

        emb_indices = [
            int(r["embedding_row_index"])
            for r in active_rows
            if r["embedding_row_index"] is not None
        ]
        vec_scores = self.db.cosine_similarity_scores(query_text, emb_indices)

        query_phonetic_tokens = set(re.findall(r"\w+", normalize_phonetic_search_key(query_text)))
        now_ts = datetime.now(timezone.utc).timestamp()

        scored_results: list[tuple[float, dict[str, Any]]] = []
        for row in active_rows:
            mid = row["memory_id"]
            emb_idx = row["embedding_row_index"]
            s_vec = vec_scores.get(int(emb_idx), 0.5) if emb_idx is not None else 0.5

            # Lexical + phonetic overlap score
            stmt_tokens = set(
                re.findall(r"\w+", normalize_phonetic_search_key(row["statement_text"]))
            )
            if query_phonetic_tokens and stmt_tokens:
                s_lex = len(query_phonetic_tokens & stmt_tokens) / len(query_phonetic_tokens)
            else:
                s_lex = 0.0

            # Graph proximity score
            if person_id is not None and row["person_id"] == person_id:
                s_graph = 1.0
            elif person_id is not None and row["person_id"] is None:
                s_graph = 0.4
            else:
                s_graph = 0.1

            # Temporal decay
            try:
                created_dt = datetime.strptime(
                    row["created_at_utc"], "%Y-%m-%dT%H:%M:%SZ"
                ).replace(tzinfo=timezone.utc)
                age_days = max(0.0, (now_ts - created_dt.timestamp()) / 86400.0)
            except ValueError:
                age_days = 0.0
            s_time = math.exp(-0.05 * age_days)

            ep_weight = EPISTEMIC_PRIORS.get(row["epistemic_class"], 0.6)
            total_score = (
                0.35 * s_vec + 0.30 * s_lex + 0.20 * s_graph + 0.15 * s_time
            ) * ep_weight

            full_record = self.memory_integrity.get_memory_record(mid)
            # Mandatory Contradiction Co-Retrieval Invariant: attach active conflicting statements verbatim
            co_retrieved_conflicts: list[dict[str, Any]] = []
            for c in full_record["contradictions"]:
                if c["resolution_state"] == "OPEN":
                    conf_row = conn.execute(
                        """
                        SELECT memory_id, statement_text, epistemic_class
                        FROM memory_ledger
                        WHERE memory_id = ? AND lifecycle_status != 'DELETED'
                        """,
                        (c["conflicting_memory_id"],),
                    ).fetchone()
                    if conf_row:
                        co_retrieved_conflicts.append(
                            {
                                "conflicting_memory_id": conf_row["memory_id"],
                                "conflicting_statement": conf_row["statement_text"],
                                "conflicting_epistemic_class": conf_row["epistemic_class"],
                                "conflict_description": c["conflict_description"],
                            }
                        )

            q_warning: str | None = None
            if full_record["quarantine"]["status"] == "EMOTIONAL_TRANSIENT":
                exp_iso = full_record["quarantine"].get("expires_at_utc")
                is_expired = False
                if exp_iso:
                    try:
                        exp_dt = datetime.strptime(exp_iso, "%Y-%m-%dT%H:%M:%SZ").replace(
                            tzinfo=timezone.utc
                        )
                        is_expired = now_ts >= exp_dt.timestamp()
                    except ValueError:
                        is_expired = False
                if is_expired:
                    q_warning = (
                        "[QUARANTINED_EMOTIONAL_REACTION_COOLDOWN_ELAPSED — "
                        "AWAITING_USER_CONFIRMATION; DO NOT TREAT AS PERMANENT TRAIT]"
                    )
                else:
                    q_warning = (
                        "[QUARANTINED_EMOTIONAL_REACTION — DO NOT TREAT AS PERMANENT TRAIT]"
                    )

            enriched = {
                "retrieval_score": round(total_score, 4),
                "memory_record": full_record,
                "co_retrieved_open_contradictions": co_retrieved_conflicts,
                "emotional_quarantine_warning": q_warning,
            }
            scored_results.append((total_score, enriched))

        scored_results.sort(key=lambda item: item[0], reverse=True)
        return [item[1] for item in scored_results[:top_k]]

    def upsert_comm_dna_profile(
        self,
        *,
        person_id: str | None,
        preferred_language_modes: list[str],
        code_mix_ratio: dict[str, float],
        cadence_profile: dict[str, Any] | None = None,
        signature_markers: list[str] | None = None,
        formality_level: float = 0.5,
        directness_score: float = 0.7,
        transliteration_spelling_map: dict[str, str] | None = None,
    ) -> str:
        """Creates or updates a per-contact or global (person_id=None) COMMUNICATION DNA profile."""
        conn = self.db.connection
        now_iso = utc_now_iso()
        cadence = cadence_profile or {}
        avg_words = float(cadence.get("avg_words", 8.0))
        if person_id is None:
            row = conn.execute(
                "SELECT profile_id FROM comm_dna_profiles WHERE person_id IS NULL LIMIT 1"
            ).fetchone()
        else:
            row = conn.execute(
                "SELECT profile_id FROM comm_dna_profiles WHERE person_id = ? LIMIT 1",
                (person_id,),
            ).fetchone()

        if row is not None:
            profile_id = row["profile_id"]
            conn.execute(
                """
                UPDATE comm_dna_profiles
                SET primary_language_modes_json = ?,
                    code_mix_ratio_json = ?,
                    typical_greeting_tokens_json = ?,
                    formality_score = ?,
                    directness_score = ?,
                    avg_sentence_length_words = ?,
                    casing_and_punctuation_style_json = ?,
                    transliteration_spelling_map_json = ?,
                    updated_at_utc = ?
                WHERE profile_id = ?
                """,
                (
                    json.dumps(preferred_language_modes),
                    json.dumps(code_mix_ratio),
                    json.dumps(signature_markers or []),
                    float(formality_level),
                    float(directness_score),
                    avg_words,
                    json.dumps(cadence),
                    json.dumps(transliteration_spelling_map or {}),
                    now_iso,
                    profile_id,
                ),
            )
        else:
            profile_id = generate_uuidv7()
            conn.execute(
                """
                INSERT INTO comm_dna_profiles (
                    profile_id, person_id, primary_language_modes_json,
                    code_mix_ratio_json, typical_greeting_tokens_json,
                    formality_score, directness_score, avg_sentence_length_words,
                    casing_and_punctuation_style_json, transliteration_spelling_map_json,
                    updated_at_utc
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    profile_id,
                    person_id,
                    json.dumps(preferred_language_modes),
                    json.dumps(code_mix_ratio),
                    json.dumps(signature_markers or []),
                    float(formality_level),
                    float(directness_score),
                    avg_words,
                    json.dumps(cadence),
                    json.dumps(transliteration_spelling_map or {}),
                    now_iso,
                ),
            )
        conn.commit()
        return profile_id

    def get_comm_dna_profile(self, person_id: str | None = None) -> dict[str, Any] | None:
        """Fetches the per-contact COMMUNICATION DNA profile, falling back to global if needed."""
        conn = self.db.connection
        row = None
        if person_id is not None:
            row = conn.execute(
                "SELECT * FROM comm_dna_profiles WHERE person_id = ? LIMIT 1",
                (person_id,),
            ).fetchone()
        if row is None:
            row = conn.execute(
                "SELECT * FROM comm_dna_profiles WHERE person_id IS NULL LIMIT 1"
            ).fetchone()
        if row is None:
            return None
        return {
            "profile_id": row["profile_id"],
            "person_id": row["person_id"],
            "preferred_language_modes": json.loads(row["primary_language_modes_json"]),
            "code_mix_ratio": json.loads(row["code_mix_ratio_json"]),
            "cadence_profile": json.loads(row["casing_and_punctuation_style_json"] or "{}"),
            "signature_markers": json.loads(row["typical_greeting_tokens_json"] or "[]"),
            "formality_level": float(row["formality_score"]),
            "directness_score": float(row["directness_score"]),
            "avg_sentence_length_words": float(row["avg_sentence_length_words"] or 8.0),
            "transliteration_spelling_map": json.loads(
                row["transliteration_spelling_map_json"] or "{}"
            ),
            "updated_at_utc": row["updated_at_utc"],
        }
