"""Phase 5 Verification Tests — Windows 11 PySide6 Desktop Companion UI."""

from __future__ import annotations

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from pathlib import Path
import numpy as np
from PySide6.QtWidgets import QApplication, QPushButton

from core.storage.database import PsycheDatabase
from core.subsystems.fortress.crypto_vault import PsycheFortressVault
from windows_companion.ui.app import PsycheDesktopMainWindow, mask_pii_text


def _get_qt_app() -> QApplication:
    return QApplication.instance() or QApplication([])


def _make_unlocked_db(tmp_path: Path, name: str = "ui") -> PsycheDatabase:
    vault = PsycheFortressVault(key_file_path=tmp_path / f"{name}.key.dpapi")
    return PsycheDatabase(
        db_path=tmp_path / f"{name}.sqlite3",
        vault=vault,
        vector_path=tmp_path / f"{name}.npy",
    )


def test_desktop_ui_renders_pillars_timeline_reply_studio_and_zero_auto_send(
    tmp_path: Path,
) -> None:
    _get_qt_app()
    db = _make_unlocked_db(tmp_path, "ui_render")
    win: PsycheDesktopMainWindow | None = None
    try:
        win = PsycheDesktopMainWindow(db=db, idle_timeout_ms=60_000)

        # Verify no auto-send button exists anywhere in the UI
        button_texts = [b.text().lower() for b in win.findChildren(QPushButton)]
        assert all("auto" not in txt and "send now" not in txt for txt in button_texts)

        # Submit manual message through UI
        win.manual_sender_input.setText("Arjun Menon")
        win.manual_text_input.setPlainText("Eda tomorrow 9:30 PM call cheyyamo?")
        win.manual_analyze_button.click()

        assert win.contact_list.count() == 1
        assert win.timeline_list.count() >= 1
        assert win.open_loops_list.count() >= 1
        assert "HUMAN" in win.pillars_view.toPlainText()
        assert "INFLUENCE_AND_MENTOR" in win.pillars_view.toPlainText()
        assert "COMPETING ALTERNATIVE EXPLANATIONS" in win.uncertainty_view.toPlainText()
        assert "SYCOPHANCY GUARD PASSED: True" in win.reality_check_view.toPlainText()
        assert win.candidate_combo.count() >= 2
        assert "9:30" in win.reply_editor.toPlainText()

        # Edit reply in Reply Review Studio and approve/copy (trains COMMUNICATION DNA)
        win.reply_editor.setPlainText("sheri machane 9:30 PM nu vilikam")
        win.approve_copy_button.click()
        assert win.last_clipboard_text == "sheri machane 9:30 PM nu vilikam"
        assert win.last_review_result is not None
        assert win.last_review_result["user_review_decision"] == "EDITED_BY_USER"

        pid = win.current_person_id
        assert pid is not None
        dna = win.orchestrator.people_memory.get_comm_dna_profile(pid)
        assert dna is not None
        assert dna["transliteration_spelling_map"].get("vilikkam") == "vilikam"
    finally:
        if win is not None:
            win.idle_timer.stop()
            win.close()
        db.close()


def test_desktop_ui_memory_integrity_controls_and_open_loop_dismiss(tmp_path: Path) -> None:
    _get_qt_app()
    db = _make_unlocked_db(tmp_path, "ui_mem")
    win: PsycheDesktopMainWindow | None = None
    try:
        win = PsycheDesktopMainWindow(db=db, idle_timeout_ms=60_000)
        win.manual_sender_input.setText("Kavya Nair")
        win.manual_text_input.setPlainText("Tomorrow 7 PM meeting redo?")
        win.manual_analyze_button.click()

        pid = win.current_person_id
        assert pid is not None

        # Seed a quarantined memory for Kavya Nair so UI can inspect, release, correct, and delete
        mem = win.orchestrator.memory_integrity.record_memory(
            person_id=pid,
            memory_domain="RELATIONAL",
            epistemic_class="USER_REPORT",
            statement_text="Ini mindilla njan, completely fed up!",
            original_language_mode="ml-Latn",
            confidence_score=0.80,
            source_type="USER_EXPLICIT_INPUT",
            extractor_component="test.ui",
        )
        assert mem["quarantine"]["status"] == "EMOTIONAL_TRANSIENT"

        win.refresh_all()
        assert win.memory_list.count() >= 1
        win.memory_list.setCurrentRow(0)

        # 1. Release quarantine
        win.release_quarantine_button.click()
        released = win.orchestrator.memory_integrity.get_memory_record(mem["memory_id"])
        assert released["quarantine"]["status"] == "NONE"

        # 2. Correct memory -> creates v2 ACTIVE revision
        win.memory_list.setCurrentRow(0)
        win.correct_memory_input.setText("Kavya was temporarily stressed about sprint scope.")
        win.correct_memory_button.click()
        assert "v2" in win.memory_list.item(0).text()

        # 3. Dismiss open loop
        assert win.open_loops_list.count() >= 1
        win.open_loops_list.setCurrentRow(0)
        win.dismiss_loop_button.click()
        assert "DISMISSED_BY_USER" in win.open_loops_list.item(0).text()

        # 4. Delete memory -> removes active memory from list & zeroes vectors
        v2_id = win.memory_list.item(0).data(0x0100)  # Qt.ItemDataRole.UserRole
        win.memory_list.setCurrentRow(0)
        win.delete_memory_button.click()
        deleted = win.orchestrator.memory_integrity.get_memory_record(v2_id)
        assert deleted["lifecycle"]["status"] == "DELETED"
    finally:
        if win is not None:
            win.idle_timer.stop()
            win.close()
        db.close()


def test_desktop_ui_privacy_blur_idle_lock_and_panic_lock(tmp_path: Path) -> None:
    _get_qt_app()
    db = _make_unlocked_db(tmp_path, "ui_sec")
    win: PsycheDesktopMainWindow | None = None
    try:
        win = PsycheDesktopMainWindow(db=db, idle_timeout_ms=60_000)
        win.manual_sender_input.setText("Arjun Menon")
        win.manual_text_input.setPlainText("Private family topic for 8 PM call")
        win.manual_analyze_button.click()

        # 1. Privacy Blur masks PII across contact list and timeline
        win.privacy_blur_button.setChecked(True)
        assert win.privacy_blur_enabled is True
        masked_contact = win.contact_list.item(0).text()
        masked_tl = win.timeline_list.item(0).text()
        assert "Arjun" not in masked_contact
        assert mask_pii_text("Arjun Menon") in masked_contact
        assert "Private family topic" not in masked_tl
        assert "HIDDEN BY PRIVACY BLUR" in masked_tl

        win.privacy_blur_button.setChecked(False)
        assert "Arjun Menon" in win.contact_list.item(0).text()

        # 2. Idle timer timeout triggers Panic Lock
        win.idle_timer.timeout.emit()
        assert db.vault.is_locked is True
        assert win.view_stack.currentIndex() == 1
        assert win.contact_list.count() == 0
        assert win.timeline_list.count() == 0
        assert win.reply_editor.toPlainText() == ""
        assert float(np.linalg.norm(db._vectors)) == 0.0
    finally:
        if win is not None:
            win.idle_timer.stop()
            win.close()
        db.close()
