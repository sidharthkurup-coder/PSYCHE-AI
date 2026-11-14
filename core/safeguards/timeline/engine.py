"""Safeguard C: Conversation Timeline Engine (REQ-SAFE-03).

Implements:
1. Chronological interaction reconstruction with strict separation between OBSERVED_EVENT
   and INFERRED_EVENT.
2. Multilingual detection and resolution of unanswered questions and unresolved commitments
   (open_loops) across English, Hindi (hi-Latn/hi-Deva), Malayalam (ml-Latn/ml-Mlym), and
   Telugu (te-Latn/te-Telu).
3. Rolling communication pattern metrics (median reply latency, initiation ratio) and
   cadence/latency shift anomaly detection.
4. Schema-validated export conforming to contracts/v1/timeline_state.schema.json.
"""

from __future__ import annotations

from datetime import datetime, timezone
import re
import statistics
from typing import Any

from core.contracts.validator import ContractValidator, normalize_phonetic_search_key
from core.storage.database import PsycheDatabase, generate_uuidv7, utc_now_iso

_MULTILINGUAL_QUESTION_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\?"),
    re.compile(
        r"\b(?:can\s+you|will\s+you|could\s+you|when\s+are|where\s+are|did\s+you|"
        r"evide|evideya|evdeya|eppo|eppozha|varumo|cheyyamo|undo|aano|kazhinjo|"
        r"ekkada|eppudu|vastava|unnava|tinnava|cheppava|"
        r"kahan|kab|kaise|kya\s+tum|kya\s+aap)\b",
        re.IGNORECASE,
    ),
    re.compile(r"(?:എവിടെ|എപ്പോൾ|വരുമോ|ചെയ്യാമോ|उधर|कब|कहाँ|क्या|ఎక్కడ|ఎప్పుడు|వస్తావా)"),
)

_MULTILINGUAL_COMMITMENT_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(
        r"\b(?:i\s+will|i'll\s+\w+|will\s+send|will\s+call|"
        r"vilikkam|varaam|varam|cheyyam|ayakkam|"
        r"chestha|vastha|pampistha|kaluddam|"
        r"karunga|bhejunga|milte\s+hain|karta\s+hoon)\b",
        re.IGNORECASE,
    ),
    re.compile(r"(?:വിളിക്കാം|വരാം|ചെയ്യാം|भेजूंगा|मिलते हैं|చేస్తా|వస్తా)"),
)


def _parse_utc(ts: str) -> datetime:
    if ts.endswith("Z"):
        ts = ts[:-1] + "+00:00"
    return datetime.fromisoformat(ts).astimezone(timezone.utc)


def is_multilingual_question(text: str) -> bool:
    """Returns True if message text contains an explicit or morphological question across the 7 modes."""
    norm = normalize_phonetic_search_key(text)
    return any(p.search(text) or p.search(norm) for p in _MULTILINGUAL_QUESTION_PATTERNS)


def is_multilingual_commitment(text: str) -> bool:
    """Returns True if message text contains a promise/commitment across the 7 modes."""
    return any(p.search(text) for p in _MULTILINGUAL_COMMITMENT_PATTERNS)


class ConversationTimelineEngine:
    """Maintains chronological timelines, open loops, pattern shifts, and observed vs. inferred events."""

    def __init__(self, db: PsycheDatabase, validator: ContractValidator | None = None) -> None:
        self.db = db
        self.validator = validator or ContractValidator()

    def process_conversation_events(
        self,
        *,
        person_id: str,
        conversation_key: str,
        reference_now_utc: str | None = None,
        window_days: int = 30,
    ) -> dict[str, Any]:
        """Rebuilds and updates chronological timeline events, open loops, and pattern metrics."""
        conn = self.db.connection
        raw_rows = conn.execute(
            """
            SELECT * FROM raw_events
            WHERE (resolved_person_id = ? OR conversation_key = ?)
            ORDER BY posted_at_utc ASC, event_id ASC
            """,
            (person_id, conversation_key),
        ).fetchall()

        # Snapshot existing open loops keyed by (source_event_id, loop_kind) to preserve
        # stable loop_ids and user overrides (e.g., DISMISSED_BY_USER, EXPIRED, manual RESOLVED)
        existing_loop_rows = conn.execute(
            """
            SELECT * FROM conversation_open_loops
            WHERE person_id = ? AND conversation_key = ?
            """,
            (person_id, conversation_key),
        ).fetchall()
        preserved_loops: dict[tuple[str | None, str], dict[str, Any]] = {}
        for lr in existing_loop_rows:
            preserved_loops[(lr["source_event_id"], lr["loop_kind"])] = dict(lr)

        # Clear previous derived timeline state for idempotent chronological reconstruction
        conn.execute(
            "DELETE FROM conversation_timeline_events WHERE person_id = ? AND conversation_key = ?",
            (person_id, conversation_key),
        )
        conn.execute(
            "DELETE FROM conversation_open_loops WHERE person_id = ? AND conversation_key = ?",
            (person_id, conversation_key),
        )

        inbound_reply_latencies: list[float] = []
        outbound_reply_latencies: list[float] = []
        user_initiated_count = 0
        contact_initiated_count = 0

        prev_event_dt: datetime | None = None
        prev_direction: str | None = None

        open_inbound_q_ids: list[str] = []
        open_outbound_q_ids: list[str] = []

        for row in raw_rows:
            ev_id = row["event_id"]
            direction = row["direction"]
            raw_text = row["raw_text_immutable"]
            posted_utc = row["posted_at_utc"]
            cur_dt = _parse_utc(posted_utc)

            # Track initiation (first message or after > 6h gap) and reply latencies
            if prev_event_dt is None or (cur_dt - prev_event_dt).total_seconds() > 6 * 3600:
                if direction == "INBOUND":
                    contact_initiated_count += 1
                else:
                    user_initiated_count += 1
            elif prev_direction is not None and prev_direction != direction:
                delta_sec = max(0.0, (cur_dt - prev_event_dt).total_seconds())
                if direction == "INBOUND":
                    inbound_reply_latencies.append(delta_sec)
                else:
                    outbound_reply_latencies.append(delta_sec)

            # 1. Record OBSERVED_EVENT for the raw communication
            obs_type = "MESSAGE_RECEIVED" if direction == "INBOUND" else "MESSAGE_SENT"
            conn.execute(
                """
                INSERT INTO conversation_timeline_events (
                    timeline_event_id, person_id, conversation_key, source_event_id,
                    event_nature, event_type, summary_text, confidence, occurred_at_utc
                ) VALUES (?, ?, ?, ?, 'OBSERVED_EVENT', ?, ?, 1.0, ?)
                """,
                (
                    generate_uuidv7(),
                    person_id,
                    conversation_key,
                    ev_id,
                    obs_type,
                    f"[{obs_type}] {row['sender_raw_title']}: {raw_text}",
                    posted_utc,
                ),
            )

            # 2. If opposite direction reply arrives, resolve pending open questions
            if direction in {"OUTBOUND_OBSERVED", "USER_DRAFT"} and open_inbound_q_ids:
                for lid in open_inbound_q_ids:
                    conn.execute(
                        """
                        UPDATE conversation_open_loops
                        SET status = 'RESOLVED', resolved_by_event_id = ?, resolved_at_utc = ?
                        WHERE loop_id = ? AND status = 'OPEN'
                        """,
                        (ev_id, posted_utc, lid),
                    )
                open_inbound_q_ids.clear()
            elif direction == "INBOUND" and open_outbound_q_ids:
                for lid in open_outbound_q_ids:
                    conn.execute(
                        """
                        UPDATE conversation_open_loops
                        SET status = 'RESOLVED', resolved_by_event_id = ?, resolved_at_utc = ?
                        WHERE loop_id = ? AND status = 'OPEN'
                        """,
                        (ev_id, posted_utc, lid),
                    )
                open_outbound_q_ids.clear()

            # 3. Check for new questions -> open loops
            if is_multilingual_question(raw_text):
                loop_kind = (
                    "UNANSWERED_QUESTION_INBOUND"
                    if direction == "INBOUND"
                    else "UNANSWERED_QUESTION_OUTBOUND"
                )
                prev_loop = preserved_loops.get((ev_id, loop_kind))
                loop_id = prev_loop["loop_id"] if prev_loop else generate_uuidv7()
                init_status = (
                    prev_loop["status"]
                    if prev_loop and prev_loop["status"] in {"DISMISSED_BY_USER", "EXPIRED"}
                    else "OPEN"
                )
                conn.execute(
                    """
                    INSERT INTO conversation_open_loops (
                        loop_id, person_id, conversation_key, source_event_id,
                        loop_kind, description, opened_at_utc, due_or_expected_at_utc,
                        status, resolved_by_event_id, resolved_at_utc
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        loop_id,
                        person_id,
                        conversation_key,
                        ev_id,
                        loop_kind,
                        f"Question from {row['sender_raw_title']}: {raw_text}",
                        posted_utc,
                        prev_loop["due_or_expected_at_utc"] if prev_loop else None,
                        init_status,
                        prev_loop["resolved_by_event_id"] if init_status != "OPEN" else None,
                        prev_loop["resolved_at_utc"] if init_status != "OPEN" else None,
                    ),
                )
                if init_status == "OPEN":
                    if direction == "INBOUND":
                        open_inbound_q_ids.append(loop_id)
                    else:
                        open_outbound_q_ids.append(loop_id)

            # 4. Check for commitments -> UNRESOLVED_COMMITMENT open loop
            if is_multilingual_commitment(raw_text):
                prev_commit = preserved_loops.get((ev_id, "UNRESOLVED_COMMITMENT"))
                c_loop_id = prev_commit["loop_id"] if prev_commit else generate_uuidv7()
                c_status = (
                    prev_commit["status"]
                    if prev_commit
                    and prev_commit["status"] in {"DISMISSED_BY_USER", "EXPIRED", "RESOLVED"}
                    else "OPEN"
                )
                conn.execute(
                    """
                    INSERT INTO conversation_open_loops (
                        loop_id, person_id, conversation_key, source_event_id,
                        loop_kind, description, opened_at_utc, due_or_expected_at_utc,
                        status, resolved_by_event_id, resolved_at_utc
                    ) VALUES (?, ?, ?, ?, 'UNRESOLVED_COMMITMENT', ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        c_loop_id,
                        person_id,
                        conversation_key,
                        ev_id,
                        f"Commitment stated by {row['sender_raw_title']}: {raw_text}",
                        posted_utc,
                        prev_commit["due_or_expected_at_utc"] if prev_commit else None,
                        c_status,
                        prev_commit["resolved_by_event_id"] if prev_commit else None,
                        prev_commit["resolved_at_utc"] if prev_commit else None,
                    ),
                )

            prev_event_dt = cur_dt
            prev_direction = direction

        # 5. Compute rolling pattern metrics and detect latency/cadence shifts
        med_in = (
            float(statistics.median(inbound_reply_latencies))
            if inbound_reply_latencies
            else None
        )
        med_out = (
            float(statistics.median(outbound_reply_latencies))
            if outbound_reply_latencies
            else None
        )
        total_init = user_initiated_count + contact_initiated_count
        init_ratio = (user_initiated_count / total_init) if total_init > 0 else None

        anomaly_detected = False
        anomaly_desc: str | None = None
        now_iso = reference_now_utc or utc_now_iso()
        now_dt = _parse_utc(now_iso)

        if len(inbound_reply_latencies) >= 3:
            baseline = float(statistics.median(inbound_reply_latencies[:-1]))
            latest_latency = inbound_reply_latencies[-1]
            if baseline > 0 and latest_latency > max(baseline * 3.0, baseline + 3600.0):
                anomaly_detected = True
                anomaly_desc = (
                    f"Latest inbound reply latency ({int(latest_latency)}s) is >3x higher "
                    f"than baseline median ({int(baseline)}s)."
                )

        # If there is an unanswered question waiting for a long time, record an INFERRED_EVENT
        if raw_rows and (open_inbound_q_ids or open_outbound_q_ids):
            last_dt = _parse_utc(raw_rows[-1]["posted_at_utc"])
            elapsed_sec = max(0.0, (now_dt - last_dt).total_seconds())
            if elapsed_sec >= 1800:
                waiting_party = (
                    "Contact is awaiting user reply"
                    if open_inbound_q_ids
                    else "User is awaiting contact reply"
                )
                conn.execute(
                    """
                    INSERT INTO conversation_timeline_events (
                        timeline_event_id, person_id, conversation_key, source_event_id,
                        event_nature, event_type, summary_text, confidence, occurred_at_utc
                    ) VALUES (?, ?, ?, ?, 'INFERRED_EVENT', 'PENDING_RESPONSE_WINDOW', ?, 0.75, ?)
                    """,
                    (
                        generate_uuidv7(),
                        person_id,
                        conversation_key,
                        raw_rows[-1]["event_id"],
                        f"[INFERRED] {waiting_party} ({int(elapsed_sec // 60)} min elapsed since open question).",
                        now_iso,
                    ),
                )

        conn.execute(
            "DELETE FROM communication_pattern_metrics WHERE person_id = ? AND window_days = ?",
            (person_id, window_days),
        )
        conn.execute(
            """
            INSERT INTO communication_pattern_metrics (
                metric_id, person_id, window_days, median_inbound_reply_sec,
                median_outbound_reply_sec, initiation_ratio_user,
                anomaly_detected, anomaly_description, computed_at_utc
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                generate_uuidv7(),
                person_id,
                window_days,
                med_in,
                med_out,
                init_ratio,
                1 if anomaly_detected else 0,
                anomaly_desc,
                now_iso,
            ),
        )

        conn.commit()
        return self.get_timeline_state(
            person_id=person_id, conversation_key=conversation_key, window_days=window_days
        )

    def get_timeline_state(
        self, *, person_id: str, conversation_key: str, window_days: int = 30
    ) -> dict[str, Any]:
        """Exports the current ConversationTimelineState validated against timeline_state.schema.json."""
        conn = self.db.connection
        ev_rows = conn.execute(
            """
            SELECT * FROM conversation_timeline_events
            WHERE person_id = ? AND conversation_key = ?
            ORDER BY occurred_at_utc ASC
            """,
            (person_id, conversation_key),
        ).fetchall()

        loop_rows = conn.execute(
            """
            SELECT * FROM conversation_open_loops
            WHERE person_id = ? AND conversation_key = ?
            ORDER BY opened_at_utc ASC
            """,
            (person_id, conversation_key),
        ).fetchall()

        metric_row = conn.execute(
            """
            SELECT * FROM communication_pattern_metrics
            WHERE person_id = ? AND window_days = ?
            ORDER BY computed_at_utc DESC LIMIT 1
            """,
            (person_id, window_days),
        ).fetchone()

        state = {
            "schema_version": "1.0.0",
            "person_id": person_id,
            "conversation_key": conversation_key,
            "chronological_events": [
                {
                    "timeline_event_id": r["timeline_event_id"],
                    "source_event_id": r["source_event_id"],
                    "event_nature": r["event_nature"],
                    "event_type": r["event_type"],
                    "summary_text": r["summary_text"],
                    "confidence": float(r["confidence"]),
                    "occurred_at_utc": r["occurred_at_utc"],
                }
                for r in ev_rows
            ],
            "open_loops": [
                {
                    "loop_id": l["loop_id"],
                    "source_event_id": l["source_event_id"],
                    "loop_kind": l["loop_kind"],
                    "description": l["description"],
                    "opened_at_utc": l["opened_at_utc"],
                    "due_or_expected_at_utc": l["due_or_expected_at_utc"],
                    "status": l["status"],
                }
                for l in loop_rows
            ],
            "pattern_shift": {
                "anomaly_detected": bool(metric_row["anomaly_detected"]) if metric_row else False,
                "window_days": window_days,
                "median_inbound_reply_sec": (
                    float(metric_row["median_inbound_reply_sec"])
                    if metric_row and metric_row["median_inbound_reply_sec"] is not None
                    else None
                ),
                "median_outbound_reply_sec": (
                    float(metric_row["median_outbound_reply_sec"])
                    if metric_row and metric_row["median_outbound_reply_sec"] is not None
                    else None
                ),
                "initiation_ratio_user": (
                    float(metric_row["initiation_ratio_user"])
                    if metric_row and metric_row["initiation_ratio_user"] is not None
                    else None
                ),
                "anomaly_description": (
                    metric_row["anomaly_description"] if metric_row else None
                ),
            },
            "updated_at_utc": utc_now_iso(),
        }
        self.validator.validate("timeline_state.schema.json", "ConversationTimelineState", state)
        return state

    def dismiss_open_loop(self, loop_id: str) -> None:
        """Marks an open loop as DISMISSED_BY_USER, preserved across timeline re-runs."""
        conn = self.db.connection
        now_iso = utc_now_iso()
        conn.execute(
            """
            UPDATE conversation_open_loops
            SET status = 'DISMISSED_BY_USER', resolved_at_utc = ?
            WHERE loop_id = ?
            """,
            (now_iso, loop_id),
        )
        conn.commit()
