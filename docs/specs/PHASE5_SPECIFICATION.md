# PSYCHE AI — Phase 5 Engineering Specification (`legion/phase5-windows-desktop-ui`)

> **Phase**: 5 — Windows 11 Desktop Companion Workbench (`PySide6 6.12.0`)  
> **Branch**: `legion/phase5-windows-desktop-ui` (from `legion/phase4-windows-gateway-mtls` @ `043ed12`)  
> **Protected Baseline**: `main` (`06e9ed7`) & `/contracts/v1/*.schema.json` remain strictly unmodified.

---

## Stage 1 — Research & Discovery

1. **Calibrated Epistemic UI & Anti-Sycophancy Layout (`REQ-WIN-01`)**:
   - Standard messaging assistants collapse interpretation into a single confident bubble and offer 1-click auto-send, encouraging premature certainty and automation bias.
   - PSYCHE's Windows 11 Workbench uses a **three-pane cognitive separation layout** (`People Graph` | `Verbatim Timeline + Open Loops` | `6 Pillars + Uncertainty Hypotheses + Memory Integrity + Reply Review Studio`) so the user always sees **raw verbatim facts separately from AI interpretations and competing hypotheses**.
2. **Shoulder-Surfing & Endpoint Memory Hygiene (`SECURITY.md` §2.2–2.3)**:
   - Supports one-click **Privacy Blur Mode** (masking names and message previews without altering encrypted SQLite rows), **5-minute Idle Lock** (`QTimer`), and **Emergency Panic Lock** (`Ctrl+Shift+L` or button) that invokes `db.vault.panic_lock()` and clears every UI widget buffer immediately.

---

## Stage 2 — Requirements Traceability Matrix

| Req ID | Requirement Summary | Target Module | Acceptance Criteria |
| :--- | :--- | :--- | :--- |
| **`REQ-WIN-01`** | Multi-pane timeline, people graph, 6 pillars, competing hypotheses, memory correction/deletion, reply review studio | `windows_companion/ui/app.py` | Renders contacts, verbatim SHA-256 timeline, all 6 pillars, alternative explanations, and working memory edit/delete/quarantine actions. |
| **`REQ-WIN-02`** | Absolute prohibition on automatic message sending | `windows_companion/ui/app.py` | `requires_user_review = True`, `auto_send_permitted = False`; only `"Approve / Edit & Copy to Clipboard"` and `"Reject Draft"` actions exist. |
| **`SEC-WIN-01/02`** | Privacy Blur, Idle Auto-Lock, Emergency Panic Lock zeroizing RAM/vectors | `windows_companion/ui/app.py` | `trigger_panic_lock()` sets `db.vault.is_locked = True`, wipes UI widgets, and switches to Vault Locked overlay. |

---

## Stage 3 & Stage 4 — Component Architecture

- **`PsycheDesktopMainWindow(QMainWindow)`** (`windows_companion/ui/app.py`):
  - **Top Security & Telemetry Bar**: `economy_label`, `presence_combo`, `privacy_blur_button`, `panic_lock_button` (`Ctrl+Shift+L`), configurable `idle_timer`.
  - **Left Pane**: `contact_list` + `refresh_button`.
  - **Center Pane**: `timeline_list` (`[OBSERVED_EVENT]`/`[INFERRED_EVENT]`, 7 language modes, verbatim text), `open_loops_list` + `dismiss_loop_button`, and **Manual Message Analysis** form (`manual_sender_input`, `manual_text_input`, `manual_analyze_button`).
  - **Right Pane**: Tabbed/stacked inspector for `pillars_view`, `uncertainty_view`, `reality_check_view`, **Memory Integrity Controls** (`memory_list`, `correct_memory_input`, `correct_memory_button`, `delete_memory_button`, `release_quarantine_button`), and **Reply Review Studio** (`candidate_combo`, `reply_editor`, `approve_copy_button`, `reject_candidate_button`).

---

## Stage 5 — Differentiation

Combines live `PySide6 6.12.0` desktop ergonomics with strict epistemic provenance visualization, direct `COMMUNICATION DNA` feedback training upon manual draft approval/edit, hardware VRAM telemetry governance, and instant cryptographic Panic Lock across UI, RAM vectors, and SQLite vault.
