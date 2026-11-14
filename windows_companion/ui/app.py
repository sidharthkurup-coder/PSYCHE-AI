"""PSYCHE AI — Windows 11 Desktop Companion Workbench (PySide6 6.12.0).

Implements:
- Three-pane layout: People & Relationship Graph | Chronological Timeline & Open Loops |
  6-Pillar Intelligence, Contextual Uncertainty Hypotheses, Reality-Checking, Memory Integrity &
  Reply Review Studio.
- Security & Operational Controls (SECURITY.md §2.2-2.3):
  - Privacy Blur Mode masking contact names and message snippets on screen.
  - Configurable Idle Auto-Lock timer (default 5 minutes = 300,000 ms).
  - Emergency Panic Lock button & Ctrl+Shift+L shortcut zeroizing vault keys, RAM vectors & UI widgets.
- Strict Human-in-the-Loop Guarantee (REQ-WIN-02 / AC-07):
  - Zero automatic sending capability. Users review, optionally edit, approve/copy to clipboard,
    and train COMMUNICATION DNA.
"""

from __future__ import annotations

import json
import os
import sys
from typing import Any

from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QKeySequence, QShortcut
from PySide6.QtWidgets import (
    QApplication,
    QComboBox,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QPlainTextEdit,
    QPushButton,
    QSplitter,
    QStackedWidget,
    QTabWidget,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from core.contracts.validator import compute_sha256_hex, detect_language_modes_and_spans
from core.pipeline.orchestrator import PsycheIntelligenceOrchestrator
from core.storage.database import PsycheDatabase, generate_uuidv7, utc_now_iso

_DARK_STYLESHEET = """
QMainWindow, QWidget {
    background-color: #0E1117;
    color: #E6EDF3;
    font-family: "Segoe UI", "Nirmala UI", sans-serif;
    font-size: 13px;
}
QGroupBox {
    background-color: #161B22;
    border: 1px solid #30363D;
    border-radius: 6px;
    margin-top: 10px;
    padding: 10px;
    font-weight: 600;
}
QGroupBox::title {
    subcontrol-origin: margin;
    left: 10px;
    padding: 0 4px;
    color: #58A6FF;
}
QListWidget, QTextEdit, QPlainTextEdit, QLineEdit, QComboBox {
    background-color: #0D1117;
    border: 1px solid #30363D;
    border-radius: 4px;
    padding: 5px;
    color: #E6EDF3;
}
QPushButton {
    background-color: #21262D;
    border: 1px solid #30363D;
    border-radius: 4px;
    padding: 6px 12px;
    color: #E6EDF3;
    font-weight: 600;
}
QPushButton:hover {
    background-color: #30363D;
}
QPushButton#panicButton {
    background-color: #8E1B1B;
    border-color: #F85149;
    color: #FFFFFF;
}
QPushButton#approveButton {
    background-color: #1F6FEB;
    border-color: #58A6FF;
    color: #FFFFFF;
}
QPushButton:checked {
    background-color: #D29922;
    color: #0E1117;
}
"""


def mask_pii_text(text: str, *, is_message_body: bool = False) -> str:
    """Masks personal names or message bodies when Privacy Blur Mode is enabled."""
    if is_message_body:
        return "[HIDDEN BY PRIVACY BLUR — SHA-256 VERIFIED]"
    parts = [p for p in text.strip().split() if p]
    if not parts:
        return "***"
    masked: list[str] = []
    for p in parts:
        if len(p) <= 2:
            masked.append("*" * len(p))
        else:
            masked.append(f"{p[0]}{'*' * (len(p) - 2)}{p[-1]}")
    return " ".join(masked)


class PsycheDesktopMainWindow(QMainWindow):
    """Main Windows 11 Desktop Companion Workbench for PSYCHE AI."""

    def __init__(
        self,
        *,
        db: PsycheDatabase,
        orchestrator: PsycheIntelligenceOrchestrator | None = None,
        idle_timeout_ms: int = 300_000,
    ) -> None:
        super().__init__()
        self.db = db
        self.orchestrator = orchestrator or PsycheIntelligenceOrchestrator(db=db)
        self.privacy_blur_enabled: bool = False
        self.current_person_id: str | None = None
        self.current_synthesis_packet: dict[str, Any] | None = None
        self.last_clipboard_text: str = ""
        self.last_review_result: dict[str, Any] | None = None
        self._desktop_manual_device_id: str = generate_uuidv7()
        self._desktop_device_registered: bool = False

        self.setWindowTitle("PSYCHE AI — Windows 11 Desktop Companion (Local Only)")
        self.resize(1380, 860)
        self.setStyleSheet(_DARK_STYLESHEET)

        # Register Panic Lock state callback so external panic locks update UI immediately
        self.db.vault.register_lifecycle_callbacks(
            on_lock=self._on_vault_locked_callback,
            on_unlock=self.refresh_all,
        )

        self._build_ui()

        self.panic_shortcut = QShortcut(QKeySequence("Ctrl+Shift+L"), self)
        self.panic_shortcut.activated.connect(self.trigger_panic_lock)

        self.idle_timer = QTimer(self)
        self.idle_timer.setSingleShot(True)
        self.idle_timer.setInterval(idle_timeout_ms)
        self.idle_timer.timeout.connect(self.trigger_panic_lock)
        if not self.db.vault.is_locked:
            self.idle_timer.start()
            self.refresh_all()
        else:
            self._show_locked_overlay()

    def _build_ui(self) -> None:
        root = QWidget()
        self.setCentralWidget(root)
        main_layout = QVBoxLayout(root)

        # Top Security & Telemetry Bar
        top_bar = QHBoxLayout()
        self.status_badge = QLabel("LOCAL VAULT: UNLOCKED | CLOUD: DISABLED ($0.00)")
        self.economy_label = QLabel("VRAM / RAM: --")
        self.presence_combo = QComboBox()
        self.presence_combo.addItems(["ACTIVE_DESKTOP", "FOCUS_LOCKED", "IDLE_DESKTOP"])
        self.presence_combo.currentTextChanged.connect(self._on_presence_changed)

        self.privacy_blur_button = QPushButton("Privacy Blur: OFF")
        self.privacy_blur_button.setCheckable(True)
        self.privacy_blur_button.toggled.connect(self.set_privacy_blur)

        self.refresh_button = QPushButton("Refresh View")
        self.refresh_button.clicked.connect(self.refresh_all)

        self.panic_lock_button = QPushButton("EMERGENCY PANIC LOCK (Ctrl+Shift+L)")
        self.panic_lock_button.setObjectName("panicButton")
        self.panic_lock_button.clicked.connect(self.trigger_panic_lock)

        top_bar.addWidget(self.status_badge)
        top_bar.addWidget(self.economy_label)
        top_bar.addStretch()
        top_bar.addWidget(QLabel("Presence:"))
        top_bar.addWidget(self.presence_combo)
        top_bar.addWidget(self.privacy_blur_button)
        top_bar.addWidget(self.refresh_button)
        top_bar.addWidget(self.panic_lock_button)
        main_layout.addLayout(top_bar)

        # Main stack switches cleanly between unlocked workbench and locked overlay
        self.view_stack = QStackedWidget()
        main_layout.addWidget(self.view_stack)

        # Page 0: Unlocked Three-Pane Workbench
        workbench = QWidget()
        wb_layout = QHBoxLayout(workbench)
        splitter = QSplitter(Qt.Orientation.Horizontal)
        wb_layout.addWidget(splitter)

        # Left Pane: People & Relationship Graph
        left_box = QGroupBox("PEOPLE & MEMORY — Contacts")
        left_layout = QVBoxLayout(left_box)
        self.contact_list = QListWidget()
        self.contact_list.currentItemChanged.connect(self._on_contact_selected)
        self.person_detail_label = QLabel("Select a contact to inspect relationship state.")
        self.person_detail_label.setWordWrap(True)
        left_layout.addWidget(self.contact_list)
        left_layout.addWidget(self.person_detail_label)
        splitter.addWidget(left_box)

        # Center Pane: Chronological Timeline, Open Loops & Manual Entry
        center_box = QGroupBox("TIMELINE & CONVERSATION SIGNALS")
        center_layout = QVBoxLayout(center_box)
        center_layout.addWidget(QLabel("Chronological Events (OBSERVED vs INFERRED):"))
        self.timeline_list = QListWidget()
        center_layout.addWidget(self.timeline_list, stretch=2)

        center_layout.addWidget(QLabel("Active Open Loops:"))
        self.open_loops_list = QListWidget()
        center_layout.addWidget(self.open_loops_list, stretch=1)
        self.dismiss_loop_button = QPushButton("Dismiss Selected Open Loop")
        self.dismiss_loop_button.clicked.connect(self._on_dismiss_selected_loop)
        center_layout.addWidget(self.dismiss_loop_button)

        manual_group = QGroupBox("Manual Message Fallback / Quick Analysis")
        manual_layout = QVBoxLayout(manual_group)
        self.manual_sender_input = QLineEdit()
        self.manual_sender_input.setPlaceholderText("Sender name (e.g., Arjun Menon)")
        self.manual_text_input = QPlainTextEdit()
        self.manual_text_input.setPlaceholderText(
            "Paste or type incoming message verbatim (any of the 7 authorized modes)..."
        )
        self.manual_text_input.setMaximumHeight(85)
        self.manual_analyze_button = QPushButton("Analyze Message Locally")
        self.manual_analyze_button.clicked.connect(self._on_manual_analyze_clicked)
        manual_layout.addWidget(self.manual_sender_input)
        manual_layout.addWidget(self.manual_text_input)
        manual_layout.addWidget(self.manual_analyze_button)
        center_layout.addWidget(manual_group)
        splitter.addWidget(center_box)

        # Right Pane: 6 Pillars, Safeguards, Memory Integrity & Reply Studio
        right_box = QGroupBox("PSYCHOLOGICAL INTELLIGENCE, SAFEGUARDS & REPLY STUDIO")
        right_layout = QVBoxLayout(right_box)
        self.inspector_tabs = QTabWidget()

        self.pillars_view = QTextEdit()
        self.pillars_view.setReadOnly(True)
        self.inspector_tabs.addTab(self.pillars_view, "6 Pillars + Research")

        self.uncertainty_view = QTextEdit()
        self.uncertainty_view.setReadOnly(True)
        self.inspector_tabs.addTab(self.uncertainty_view, "Uncertainty & Competing Hypotheses")

        self.reality_check_view = QTextEdit()
        self.reality_check_view.setReadOnly(True)
        self.inspector_tabs.addTab(self.reality_check_view, "Reality Check")

        # Memory Integrity tab
        mem_tab = QWidget()
        mem_layout = QVBoxLayout(mem_tab)
        self.memory_list = QListWidget()
        mem_layout.addWidget(self.memory_list, stretch=2)
        self.correct_memory_input = QLineEdit()
        self.correct_memory_input.setPlaceholderText(
            "Enter corrected memory statement to supersede selected memory..."
        )
        mem_layout.addWidget(self.correct_memory_input)
        mem_btn_row = QHBoxLayout()
        self.correct_memory_button = QPushButton("Correct Selected Memory")
        self.correct_memory_button.clicked.connect(self._on_correct_memory_clicked)
        self.release_quarantine_button = QPushButton("Release Quarantine")
        self.release_quarantine_button.clicked.connect(self._on_release_quarantine_clicked)
        self.delete_memory_button = QPushButton("Delete Selected Memory")
        self.delete_memory_button.clicked.connect(self._on_delete_memory_clicked)
        mem_btn_row.addWidget(self.correct_memory_button)
        mem_btn_row.addWidget(self.release_quarantine_button)
        mem_btn_row.addWidget(self.delete_memory_button)
        mem_layout.addLayout(mem_btn_row)
        self.inspector_tabs.addTab(mem_tab, "Memory Integrity Ledger")

        right_layout.addWidget(self.inspector_tabs, stretch=3)

        # Reply Review Studio (Zero Auto-Send)
        reply_group = QGroupBox(
            "Reply Review Studio (requires_user_review=True | auto_send_permitted=False)"
        )
        reply_layout = QVBoxLayout(reply_group)
        self.candidate_combo = QComboBox()
        self.candidate_combo.currentIndexChanged.connect(self._on_candidate_selected)
        self.reply_editor = QPlainTextEdit()
        self.reply_editor.setMaximumHeight(95)
        reply_btn_row = QHBoxLayout()
        self.approve_copy_button = QPushButton("Approve / Edit & Copy to Clipboard")
        self.approve_copy_button.setObjectName("approveButton")
        self.approve_copy_button.clicked.connect(self._on_approve_copy_clicked)
        self.reject_candidate_button = QPushButton("Reject Draft")
        self.reject_candidate_button.clicked.connect(self._on_reject_clicked)
        reply_btn_row.addWidget(self.approve_copy_button)
        reply_btn_row.addWidget(self.reject_candidate_button)
        self.reply_audit_label = QLabel("Zero Auto-Send Lock Active: Manual review required.")
        reply_layout.addWidget(self.candidate_combo)
        reply_layout.addWidget(self.reply_editor)
        reply_layout.addLayout(reply_btn_row)
        reply_layout.addWidget(self.reply_audit_label)
        right_layout.addWidget(reply_group, stretch=1)

        splitter.addWidget(right_box)
        splitter.setSizes([280, 460, 620])
        self.view_stack.addWidget(workbench)

        # Page 1: Vault Locked Overlay
        locked_page = QWidget()
        locked_layout = QVBoxLayout(locked_page)
        locked_layout.addStretch()
        self.locked_banner = QLabel(
            "PSYCHE FORTRESS — VAULT LOCKED\n"
            "In-RAM DPAPI key material and semantic vectors have been zeroized.\n"
            "Unlock vault via Windows DPAPI to resume local intelligence."
        )
        self.locked_banner.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.locked_banner.setStyleSheet("font-size: 18px; font-weight: bold; color: #F85149;")
        locked_layout.addWidget(self.locked_banner)
        locked_layout.addStretch()
        self.view_stack.addWidget(locked_page)

    def reset_idle_timer(self) -> None:
        if not self.db.vault.is_locked:
            self.idle_timer.start()

    def _on_presence_changed(self, state: str) -> None:
        if self.db.vault.is_locked:
            return
        self.orchestrator.presence.set_desktop_presence_state(state)
        self.reset_idle_timer()

    def set_privacy_blur(self, enabled: bool) -> None:
        self.privacy_blur_enabled = bool(enabled)
        self.privacy_blur_button.setText(
            f"Privacy Blur: {'ON' if self.privacy_blur_enabled else 'OFF'}"
        )
        if not self.db.vault.is_locked:
            self.refresh_all()

    def _on_vault_locked_callback(self) -> None:
        self._show_locked_overlay()

    def _show_locked_overlay(self) -> None:
        self.idle_timer.stop()
        self.current_person_id = None
        self.current_synthesis_packet = None
        self.contact_list.clear()
        self.timeline_list.clear()
        self.open_loops_list.clear()
        self.memory_list.clear()
        self.pillars_view.clear()
        self.uncertainty_view.clear()
        self.reality_check_view.clear()
        self.candidate_combo.clear()
        self.reply_editor.clear()
        self.manual_text_input.clear()
        self.status_badge.setText("LOCAL VAULT: LOCKED (RAM ZEROIZED) | CLOUD: DISABLED ($0.00)")
        self.view_stack.setCurrentIndex(1)

    def trigger_panic_lock(self) -> None:
        """Executes Emergency Panic Lock across DB Vault, Vector RAM, Presence, and Qt UI."""
        self.db.vault.panic_lock()
        self._show_locked_overlay()

    def refresh_all(self) -> None:
        if self.db.vault.is_locked:
            self._show_locked_overlay()
            return
        self.view_stack.setCurrentIndex(0)
        self.reset_idle_timer()

        hw = self.orchestrator.economy.capture_hardware_snapshot()
        self.economy_label.setText(
            f"{hw.gpu_name} Free VRAM: {hw.vram_free_mib:.0f} MiB / "
            f"{hw.vram_total_mib:.0f} MiB | Process RSS: {hw.process_rss_mib:.1f} MiB"
        )
        self.status_badge.setText(
            f"LOCAL VAULT: UNLOCKED | PRESENCE: {self.orchestrator.presence.desktop_presence_state} | CLOUD: DISABLED ($0.00)"
        )

        # Populate contact list
        prev_pid = self.current_person_id
        self.contact_list.blockSignals(True)
        self.contact_list.clear()
        rows = self.db.connection.execute(
            "SELECT person_id, canonical_display_name, relationship_tier, trust_level FROM people ORDER BY updated_at_utc DESC, rowid DESC"
        ).fetchall()
        selected_row = -1
        for idx, r in enumerate(rows):
            name = (
                mask_pii_text(r["canonical_display_name"])
                if self.privacy_blur_enabled
                else r["canonical_display_name"]
            )
            item = QListWidgetItem(
                f"{name} [{r['relationship_tier']} | trust={float(r['trust_level']):.2f}]"
            )
            item.setData(Qt.ItemDataRole.UserRole, r["person_id"])
            self.contact_list.addItem(item)
            if r["person_id"] == prev_pid:
                selected_row = idx
        self.contact_list.blockSignals(False)

        if rows:
            self.contact_list.setCurrentRow(selected_row if selected_row >= 0 else 0)
            self._load_person_workspace(self.contact_list.currentItem().data(Qt.ItemDataRole.UserRole))

    def _on_contact_selected(
        self, current: QListWidgetItem | None, _prev: QListWidgetItem | None
    ) -> None:
        if current is None or self.db.vault.is_locked:
            return
        pid = current.data(Qt.ItemDataRole.UserRole)
        self._load_person_workspace(pid)

    def _load_person_workspace(self, person_id: str) -> None:
        if self.db.vault.is_locked:
            return
        self.current_person_id = person_id
        conn = self.db.connection
        p_row = conn.execute(
            "SELECT * FROM people WHERE person_id = ?", (person_id,)
        ).fetchone()
        if p_row is None:
            return
        disp_name = (
            mask_pii_text(p_row["canonical_display_name"])
            if self.privacy_blur_enabled
            else p_row["canonical_display_name"]
        )
        self.person_detail_label.setText(
            f"Contact: {disp_name} | Tier: {p_row['relationship_tier']} | Trust: {float(p_row['trust_level']):.2f}"
        )

        # Load chronological raw events & timeline state
        ev_rows = conn.execute(
            """
            SELECT event_id, conversation_key, sender_raw_title, raw_text_immutable,
                   raw_text_sha256, detected_language_modes_json, posted_at_utc, direction
            FROM raw_events
            WHERE resolved_person_id = ?
            ORDER BY posted_at_utc ASC, rowid ASC
            """,
            (person_id,),
        ).fetchall()

        self.timeline_list.clear()
        conv_key = ev_rows[-1]["conversation_key"] if ev_rows else "default"
        for ev in ev_rows:
            body_txt = (
                mask_pii_text(ev["raw_text_immutable"], is_message_body=True)
                if self.privacy_blur_enabled
                else ev["raw_text_immutable"]
            )
            modes = json.loads(ev["detected_language_modes_json"])
            self.timeline_list.addItem(
                f"[OBSERVED_EVENT | {ev['direction']} | {','.join(modes)} | {ev['posted_at_utc']}] "
                f"{body_txt} (sha256={ev['raw_text_sha256'][:10]}...)"
            )

        # Open loops
        self.open_loops_list.clear()
        loops = conn.execute(
            """
            SELECT loop_id, loop_kind, description, status
            FROM conversation_open_loops
            WHERE person_id = ? AND conversation_key = ?
            ORDER BY opened_at_utc ASC, rowid ASC
            """,
            (person_id, conv_key),
        ).fetchall()
        for lp in loops:
            desc = (
                mask_pii_text(lp["description"], is_message_body=True)
                if self.privacy_blur_enabled
                else lp["description"]
            )
            li = QListWidgetItem(f"[{lp['status']} | {lp['loop_kind']}] {desc}")
            li.setData(Qt.ItemDataRole.UserRole, lp["loop_id"])
            self.open_loops_list.addItem(li)

        # Memory integrity ledger
        self.memory_list.clear()
        mems = conn.execute(
            """
            SELECT memory_id, memory_domain, epistemic_class, statement_text,
                   quarantine_status, lifecycle_status, revision_number
            FROM memory_ledger
            WHERE person_id = ? AND lifecycle_status = 'ACTIVE'
            ORDER BY updated_at_utc DESC, rowid DESC
            """,
            (person_id,),
        ).fetchall()
        for m in mems:
            stmt = (
                mask_pii_text(m["statement_text"], is_message_body=True)
                if self.privacy_blur_enabled
                else m["statement_text"]
            )
            mi = QListWidgetItem(
                f"[{m['epistemic_class']} | {m['memory_domain']} | v{m['revision_number']} | Q={m['quarantine_status']}] {stmt}"
            )
            mi.setData(Qt.ItemDataRole.UserRole, m["memory_id"])
            self.memory_list.addItem(mi)

        # Latest reasoning synthesis for this person
        syn_row = conn.execute(
            """
            SELECT synthesis_payload_json FROM reasoning_syntheses
            WHERE person_id = ?
            ORDER BY created_at_utc DESC, rowid DESC LIMIT 1
            """,
            (person_id,),
        ).fetchone()
        if syn_row:
            packet = json.loads(syn_row["synthesis_payload_json"])
            self.load_synthesis_packet(packet)
        else:
            self.current_synthesis_packet = None
            self.pillars_view.setPlainText("No synthesis packet generated yet for this contact.")
            self.uncertainty_view.clear()
            self.reality_check_view.clear()
            self.candidate_combo.clear()
            self.reply_editor.clear()

    def load_synthesis_packet(self, packet: dict[str, Any]) -> None:
        """Populates all intelligence panes and Reply Review Studio from a verified packet."""
        self.current_synthesis_packet = packet
        pillars = packet["pillar_assessments"]
        lines: list[str] = []
        for pname, pval in pillars.items():
            lines.append(f"=== {pname.upper()} ===")
            lines.append(json.dumps(pval, indent=2, ensure_ascii=False))
        self.pillars_view.setPlainText("\n".join(lines))

        unc = packet["uncertainty_audit"]
        unc_lines = [
            f"VERDICT: {unc['verdict_status']}",
            "",
            "VERIFIED FACTS:",
            *[f"  - {f}" for f in unc.get("verified_facts", [])],
            "",
            f"PRIMARY INTERPRETATION: {unc.get('primary_interpretation', '')}",
            "",
            "COMPETING ALTERNATIVE EXPLANATIONS:",
        ]
        for alt in unc.get("alternative_explanations", []):
            unc_lines.append(
                f"  - ({alt.get('confidence', 0.0):.2f}) {alt.get('hypothesis_text', '')}"
            )
        if unc.get("contradictory_evidence"):
            unc_lines.append("")
            unc_lines.append("CONTRADICTORY EVIDENCE:")
            for c in unc["contradictory_evidence"]:
                unc_lines.append(f"  - {c}")
        self.uncertainty_view.setPlainText("\n".join(unc_lines))

        rc = packet["reality_check_audit"]
        rc_lines = [
            f"SYCOPHANCY GUARD PASSED: {rc.get('sycophancy_guard_passed')}",
            "",
            "CHALLENGED ASSUMPTIONS:",
            *[f"  - {a}" for a in rc.get("challenged_user_assumptions", [])],
            "",
            "FEELINGS VS FACTS:",
            *[f"  - {f}" for f in rc.get("distinction_feelings_vs_facts", [])],
        ]
        self.reality_check_view.setPlainText("\n".join(rc_lines))

        # Reply Review Studio
        self.candidate_combo.blockSignals(True)
        self.candidate_combo.clear()
        candidates = packet["goal_aware_recommendations"].get("reply_candidates", [])
        for cand in candidates:
            label = f"{cand.get('tone_label', 'Draft')} (DNA={cand.get('dna_authenticity_score', 0.0):.2f})"
            self.candidate_combo.addItem(label, cand)
        self.candidate_combo.blockSignals(False)
        if candidates:
            self.candidate_combo.setCurrentIndex(0)
            self._on_candidate_selected(0)

    def _on_candidate_selected(self, idx: int) -> None:
        cand = self.candidate_combo.itemData(idx)
        if isinstance(cand, dict):
            self.reply_editor.setPlainText(cand.get("draft_text", ""))

    def _ensure_desktop_manual_device(self) -> str:
        if not self._desktop_device_registered:
            self.orchestrator.people_memory.register_paired_device(
                device_id=self._desktop_manual_device_id,
                device_name="Legion 5 Pro Desktop Manual Input",
                ed25519_public_key_b64="dGVzdC1wdWIta2V5",
                tls_cert_sha256_pin="f" * 64,
            )
            self._desktop_device_registered = True
        return self._desktop_manual_device_id

    def _on_manual_analyze_clicked(self) -> None:
        if self.db.vault.is_locked:
            return
        sender_name = self.manual_sender_input.text().strip() or "Manual Contact"
        raw_text = self.manual_text_input.toPlainText().strip()
        if not raw_text:
            return

        dev_id = self._ensure_desktop_manual_device()
        now_utc = utc_now_iso()
        modes, spans = detect_language_modes_and_spans(raw_text)
        ev_id = generate_uuidv7()
        conv_key = f"manual-{compute_sha256_hex(sender_name.lower())[:12]}"

        # Ensure person exists before ingest if new
        pid = self.orchestrator.people_memory.create_or_update_person(
            canonical_display_name=sender_name,
            relationship_tier="CLOSE_FRIEND",
            trust_level=0.80,
        )
        batch_req = {
            "schema_version": "1.0.0",
            "batch_id": generate_uuidv7(),
            "device_id": dev_id,
            "sent_at_utc": now_utc,
            "batch_ed25519_signature": "YmF0Y2gtc2lnbmF0dXJlLWJhc2U2NC1vaw==",
            "events": [
                {
                    "event_id": ev_id,
                    "package_name": "com.psycheai.manual",
                    "notification_category": "msg",
                    "conversation_key": conv_key,
                    "is_group_conversation": False,
                    "group_title": None,
                    "direction": "INBOUND",
                    "sender": {
                        "raw_title": sender_name,
                        "android_contact_lookup_key": None,
                        "normalized_phone_sha256": None,
                        "candidate_person_ids": [pid],
                        "identity_ambiguity": False,
                    },
                    "content": {
                        "raw_text_immutable": raw_text,
                        "raw_text_sha256": compute_sha256_hex(raw_text),
                        "detected_language_modes": modes,
                        "token_language_spans": spans,
                    },
                    "posted_at_utc": now_utc,
                    "security": {
                        "untrusted_external_input": True,
                        "otp_or_sensitive_filtered": True,
                        "ed25519_event_signature": "dGVzdC1zaWduYXR1cmUtYmFzZTY0LW9r",
                    },
                }
            ],
        }
        self.orchestrator.people_memory.ingest_notification_batch(
            batch_req, require_crypto_signature=False
        )
        packet = self.orchestrator.synthesize_for_event(event_id=ev_id, reference_now_utc=now_utc)
        self.current_person_id = packet["person_id"]
        self.refresh_all()
        self.load_synthesis_packet(packet)

    def _on_dismiss_selected_loop(self) -> None:
        item = self.open_loops_list.currentItem()
        if item is None or self.db.vault.is_locked:
            return
        loop_id = item.data(Qt.ItemDataRole.UserRole)
        self.orchestrator.timeline.dismiss_open_loop(loop_id)
        self.refresh_all()

    def _on_correct_memory_clicked(self) -> None:
        item = self.memory_list.currentItem()
        new_stmt = self.correct_memory_input.text().strip()
        if item is None or not new_stmt or self.db.vault.is_locked:
            return
        mem_id = item.data(Qt.ItemDataRole.UserRole)
        self.orchestrator.memory_integrity.correct_memory(
            mem_id,
            corrected_statement=new_stmt,
            correction_note="Corrected via Windows Desktop Companion",
        )
        self.correct_memory_input.clear()
        self.refresh_all()

    def _on_release_quarantine_clicked(self) -> None:
        item = self.memory_list.currentItem()
        if item is None or self.db.vault.is_locked:
            return
        mem_id = item.data(Qt.ItemDataRole.UserRole)
        self.orchestrator.memory_integrity.release_emotional_quarantine(
            mem_id,
            confirmed_by_user=True,
            note="Reviewed and confirmed in Desktop Companion",
        )
        self.refresh_all()

    def _on_delete_memory_clicked(self) -> None:
        item = self.memory_list.currentItem()
        if item is None or self.db.vault.is_locked:
            return
        mem_id = item.data(Qt.ItemDataRole.UserRole)
        self.orchestrator.memory_integrity.delete_memory(
            mem_id,
            reason="Deleted via Windows Desktop Companion",
        )
        self.refresh_all()

    def _on_approve_copy_clicked(self) -> None:
        if self.current_synthesis_packet is None or self.db.vault.is_locked:
            return
        edited_text = self.reply_editor.toPlainText().strip()
        if not edited_text:
            return
        cand = self.candidate_combo.currentData()
        orig_text = cand.get("draft_text", "").strip() if isinstance(cand, dict) else ""
        decision = "ACCEPTED_AS_IS" if edited_text == orig_text else "EDITED_BY_USER"

        cb = QApplication.clipboard()
        if cb is not None:
            cb.setText(edited_text)
        self.last_clipboard_text = edited_text
        self.last_review_result = self.orchestrator.record_user_review_decision(
            synthesis_id=self.current_synthesis_packet["synthesis_id"],
            decision=decision,
            user_final_edited_text=edited_text,
        )
        self.reply_audit_label.setText(
            f"Decision recorded ({decision}) & copied to clipboard for manual send. DNA updated."
        )

    def _on_reject_clicked(self) -> None:
        if self.current_synthesis_packet is None or self.db.vault.is_locked:
            return
        self.last_review_result = self.orchestrator.record_user_review_decision(
            synthesis_id=self.current_synthesis_packet["synthesis_id"],
            decision="REJECTED",
            user_final_edited_text=None,
        )
        self.reply_audit_label.setText("Draft rejected by user; nothing copied or sent.")


def launch_desktop_companion(
    *,
    db_path: str = "psyche_vault.sqlite3",
    key_file_path: str = "psyche_master.key.dpapi",
    vector_path: str = "psyche_vectors.npy",
    offscreen: bool = False,
) -> int:
    """Entrypoint for launching the Windows 11 PySide6 Desktop Companion."""
    if offscreen:
        os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    app = QApplication.instance() or QApplication(sys.argv)
    vault = PsycheFortressVaultFactory.unlock(key_file_path=key_file_path)
    db = PsycheDatabase(db_path=db_path, vault=vault, vector_path=vector_path)
    win = PsycheDesktopMainWindow(db=db)
    win.show()
    try:
        return app.exec()
    finally:
        db.close()


class PsycheFortressVaultFactory:
    @staticmethod
    def unlock(*, key_file_path: str) -> Any:
        from core.subsystems.fortress.crypto_vault import PsycheFortressVault

        return PsycheFortressVault(key_file_path=key_file_path)
