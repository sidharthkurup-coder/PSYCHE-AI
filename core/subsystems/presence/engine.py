"""PSYCHE PRESENCE — Cross-Device Ambient Availability & Interruption Triage (REQ-SUB-06).

Implements:
- Validation and processing of `PresenceHeartbeatRequest` / `PresenceHeartbeatResponse`
  conforming to `contracts/v1/presence_heartbeat.schema.json`.
- Real-time synchronization with `PSYCHE FORTRESS` vault lock state (`VAULT_LOCKED` ->
  `HOLD_UNTIL_UNLOCKED`).
- Desktop focus/DND state management (`ACTIVE_DESKTOP`, `FOCUS_LOCKED`, `IDLE_DESKTOP`,
  `VAULT_LOCKED`) and `recommended_sync_mode` negotiation (`REALTIME_STREAM`,
  `BATCH_LOW_PRIORITY`, `HOLD_UNTIL_UNLOCKED`).
- Notification interruption urgency triage combining user presence state with relationship
  tier and pragmatic speech acts.
"""

from __future__ import annotations

from typing import Any

from core.contracts.validator import ContractValidator
from core.storage.database import PsycheDatabase, utc_now_iso
from core.subsystems.fortress.pairing import (
    FortressPairingManager,
    canonical_presence_heartbeat_bytes,
)


class PsychePresenceEngine:
    """Manages desktop and mobile presence states and notification interruption triage."""

    VALID_DESKTOP_STATES = {"ACTIVE_DESKTOP", "FOCUS_LOCKED", "IDLE_DESKTOP", "VAULT_LOCKED"}

    def __init__(
        self,
        *,
        db: PsycheDatabase,
        validator: ContractValidator | None = None,
        pairing_manager: FortressPairingManager | None = None,
    ) -> None:
        self.db = db
        self.validator = validator or ContractValidator()
        self.pairing = pairing_manager or FortressPairingManager(
            db=self.db, validator=self.validator
        )
        self._desktop_state: str = "ACTIVE_DESKTOP"
        self._mobile_heartbeats: dict[str, dict[str, Any]] = {}

    @property
    def desktop_presence_state(self) -> str:
        """Returns effective desktop state, automatically reflecting vault lock status."""
        if self.db.vault.is_locked:
            return "VAULT_LOCKED"
        return self._desktop_state

    def set_desktop_presence_state(self, state: str) -> str:
        """Sets desktop focus/idle state (overridden automatically when vault is locked)."""
        if state not in self.VALID_DESKTOP_STATES:
            raise ValueError(
                f"Invalid desktop presence state '{state}'; expected one of {self.VALID_DESKTOP_STATES}"
            )
        self._desktop_state = state
        return self.desktop_presence_state

    def get_recommended_sync_mode(self, mobile_state: dict[str, Any] | None = None) -> str:
        """Determines optimal sync cadence from desktop vault/focus state and mobile DND/battery."""
        d_state = self.desktop_presence_state
        if d_state == "VAULT_LOCKED":
            return "HOLD_UNTIL_UNLOCKED"
        if d_state in {"FOCUS_LOCKED", "IDLE_DESKTOP"}:
            return "BATCH_LOW_PRIORITY"
        if mobile_state:
            battery = mobile_state.get("battery_percent")
            if mobile_state.get("dnd_active") or mobile_state.get("user_presence_state") == "SLEEPING":
                return "BATCH_LOW_PRIORITY"
            if battery is not None and battery < 15:
                return "BATCH_LOW_PRIORITY"
        return "REALTIME_STREAM"

    def process_heartbeat(
        self,
        request_payload: dict[str, Any],
        *,
        require_crypto_signature: bool = False,
    ) -> dict[str, Any]:
        """Validates a PresenceHeartbeatRequest, updates device presence, and returns PresenceHeartbeatResponse."""
        self.validator.validate(
            "presence_heartbeat.schema.json", "PresenceHeartbeatRequest", request_payload
        )
        device_id = request_payload["device_id"]
        self.pairing.verify_device_signature(
            device_id=device_id,
            canonical_payload=canonical_presence_heartbeat_bytes(request_payload),
            signature_b64=request_payload["ed25519_signature"],
            require_crypto=require_crypto_signature,
        )

        # Record heartbeat snapshot in memory and update paired_devices.last_seen_at_utc if vault is unlocked
        snapshot = {
            "device_id": device_id,
            "timestamp_utc": request_payload["timestamp_utc"],
            "user_presence_state": request_payload["user_presence_state"],
            "dnd_active": bool(request_payload["dnd_active"]),
            "pending_queue_count": int(request_payload["pending_queue_count"]),
            "battery_percent": request_payload.get("battery_percent"),
        }
        self._mobile_heartbeats[device_id] = snapshot

        if not self.db.vault.is_locked:
            self.db.connection.execute(
                "UPDATE paired_devices SET last_seen_at_utc = ? WHERE device_id = ?",
                (utc_now_iso(), device_id),
            )
            self.db.connection.commit()

        d_state = self.desktop_presence_state
        sync_mode = self.get_recommended_sync_mode(snapshot)
        resp = {
            "schema_version": "1.0.0",
            "timestamp_utc": utc_now_iso(),
            "desktop_presence_state": d_state,
            "recommended_sync_mode": sync_mode,
        }
        self.validator.validate(
            "presence_heartbeat.schema.json", "PresenceHeartbeatResponse", resp
        )
        return resp

    def get_latest_mobile_presence(self, device_id: str | None = None) -> dict[str, Any] | None:
        """Returns the latest recorded heartbeat snapshot for a given or most recent mobile device."""
        if device_id is not None:
            return self._mobile_heartbeats.get(device_id)
        if not self._mobile_heartbeats:
            return None
        latest_key = list(self._mobile_heartbeats.keys())[-1]
        return self._mobile_heartbeats[latest_key]

    def evaluate_interruption_urgency(
        self,
        *,
        relationship_tier: str,
        speech_acts: list[str],
        boundary_pressure: bool = False,
        device_id: str | None = None,
    ) -> dict[str, Any]:
        """Determines notification surface priority respecting FOCUS_LOCKED, DND, and VAULT_LOCKED."""
        d_state = self.desktop_presence_state
        mobile = self.get_latest_mobile_presence(device_id)
        mobile_dnd = bool(mobile and (mobile.get("dnd_active") or mobile.get("user_presence_state") == "DO_NOT_DISTURB"))

        if d_state == "VAULT_LOCKED":
            return {
                "surface_action": "HOLD_UNTIL_UNLOCKED",
                "urgency_level": "DEFERRED",
                "reason": "PSYCHE FORTRESS vault is locked; holding UI notification surface.",
            }

        is_high_trust_inner = relationship_tier in {"INNER_CIRCLE", "FAMILY"}
        if (d_state == "FOCUS_LOCKED" or mobile_dnd) and not is_high_trust_inner:
            return {
                "surface_action": "BATCH_QUIETLY",
                "urgency_level": "LOW",
                "reason": (
                    f"Presence protection active (desktop={d_state}, mobile_dnd={mobile_dnd}); "
                    f"deferring interruption from tier={relationship_tier}."
                ),
            }

        if is_high_trust_inner and ("SCHEDULING_COORDINATION" in speech_acts or "QUESTION_INQUIRY" in speech_acts):
            return {
                "surface_action": "SURFACE_IMMEDIATELY",
                "urgency_level": "HIGH",
                "reason": f"High-trust ({relationship_tier}) direct coordination or inquiry.",
            }

        if boundary_pressure:
            return {
                "surface_action": "QUEUE_FOR_CALM_REVIEW",
                "urgency_level": "NORMAL",
                "reason": "Boundary-pressured demand queued calmly to protect user deliberate review.",
            }

        return {
            "surface_action": "SURFACE_IN_INBOX",
            "urgency_level": "NORMAL",
            "reason": f"Standard desktop delivery under presence={d_state}.",
        }
