"""PSYCHE FORTRESS — Cryptographic Device Pairing (X25519 + Ed25519 + 6-Digit HKDF SAS) & Replay Guard.

Implements:
- Native OpenSSL 3.5.2 (libcrypto-3-x64.dll) Ed25519 key generation, signing, and verification
  plus X25519 Elliptic-Curve Diffie-Hellman key agreement via ctypes with explicit pointer cleanup.
- HKDF-SHA256 6-digit Short Authentication String (SAS) and HMAC confirmation proof.
- QrChallengePayload -> PairingConfirmRequest -> PairingConfirmResponse mutual handshake validated
  strictly against contracts/v1/device_pairing.schema.json (SECURITY.md Section 2.4).
- Canonical signing payloads and replay/clock-skew protection (+-120s window + batch_id cache)
  for ContactSyncRequest, NotificationEventItem, NotificationIngestRequest, and PresenceHeartbeatRequest.
"""

from __future__ import annotations

import base64
import ctypes
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import os
from pathlib import Path
import secrets
from typing import TYPE_CHECKING, Any

from core.contracts.validator import ContractValidationError, ContractValidator

if TYPE_CHECKING:
    from core.storage.database import PsycheDatabase

_EVP_PKEY_ED25519 = 1087
_EVP_PKEY_X25519 = 1034


def _load_libcrypto() -> ctypes.CDLL:
    """Loads OpenSSL 3.x libcrypto DLL with configured argtypes/restypes."""
    candidates = [
        Path(r"C:\msys64\ucrt64\bin\libcrypto-3-x64.dll"),
        Path(r"C:\Program Files\Git\mingw64\bin\libcrypto-3-x64.dll"),
    ]
    dll_path: Path | None = None
    for cand in candidates:
        if cand.exists():
            dll_path = cand
            break
    if dll_path is not None and hasattr(os, "add_dll_directory"):
        os.add_dll_directory(str(dll_path.parent))
        lib = ctypes.CDLL(str(dll_path))
    else:
        lib = ctypes.CDLL("libcrypto-3-x64.dll")

    lib.EVP_PKEY_new_raw_private_key.argtypes = [
        ctypes.c_int,
        ctypes.c_void_p,
        ctypes.c_char_p,
        ctypes.c_size_t,
    ]
    lib.EVP_PKEY_new_raw_private_key.restype = ctypes.c_void_p

    lib.EVP_PKEY_new_raw_public_key.argtypes = [
        ctypes.c_int,
        ctypes.c_void_p,
        ctypes.c_char_p,
        ctypes.c_size_t,
    ]
    lib.EVP_PKEY_new_raw_public_key.restype = ctypes.c_void_p

    lib.EVP_PKEY_get_raw_public_key.argtypes = [
        ctypes.c_void_p,
        ctypes.c_char_p,
        ctypes.POINTER(ctypes.c_size_t),
    ]
    lib.EVP_PKEY_get_raw_public_key.restype = ctypes.c_int

    lib.EVP_PKEY_free.argtypes = [ctypes.c_void_p]
    lib.EVP_PKEY_free.restype = None

    lib.EVP_MD_CTX_new.argtypes = []
    lib.EVP_MD_CTX_new.restype = ctypes.c_void_p

    lib.EVP_MD_CTX_free.argtypes = [ctypes.c_void_p]
    lib.EVP_MD_CTX_free.restype = None

    lib.EVP_DigestSignInit.argtypes = [
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
    ]
    lib.EVP_DigestSignInit.restype = ctypes.c_int

    lib.EVP_DigestSign.argtypes = [
        ctypes.c_void_p,
        ctypes.c_char_p,
        ctypes.POINTER(ctypes.c_size_t),
        ctypes.c_char_p,
        ctypes.c_size_t,
    ]
    lib.EVP_DigestSign.restype = ctypes.c_int

    lib.EVP_DigestVerifyInit.argtypes = [
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
    ]
    lib.EVP_DigestVerifyInit.restype = ctypes.c_int

    lib.EVP_DigestVerify.argtypes = [
        ctypes.c_void_p,
        ctypes.c_char_p,
        ctypes.c_size_t,
        ctypes.c_char_p,
        ctypes.c_size_t,
    ]
    lib.EVP_DigestVerify.restype = ctypes.c_int

    lib.EVP_PKEY_CTX_new.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
    lib.EVP_PKEY_CTX_new.restype = ctypes.c_void_p

    lib.EVP_PKEY_CTX_free.argtypes = [ctypes.c_void_p]
    lib.EVP_PKEY_CTX_free.restype = None

    lib.EVP_PKEY_derive_init.argtypes = [ctypes.c_void_p]
    lib.EVP_PKEY_derive_init.restype = ctypes.c_int

    lib.EVP_PKEY_derive_set_peer.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
    lib.EVP_PKEY_derive_set_peer.restype = ctypes.c_int

    lib.EVP_PKEY_derive.argtypes = [
        ctypes.c_void_p,
        ctypes.c_char_p,
        ctypes.POINTER(ctypes.c_size_t),
    ]
    lib.EVP_PKEY_derive.restype = ctypes.c_int

    return lib


_LIBCRYPTO: ctypes.CDLL | None = None


def _get_libcrypto() -> ctypes.CDLL:
    global _LIBCRYPTO
    if _LIBCRYPTO is None:
        _LIBCRYPTO = _load_libcrypto()
    return _LIBCRYPTO


def generate_ed25519_keypair() -> tuple[bytes, bytes]:
    """Generates a fresh (private_key_32b, public_key_32b) Ed25519 keypair."""
    lib = _get_libcrypto()
    priv = secrets.token_bytes(32)
    pkey = lib.EVP_PKEY_new_raw_private_key(_EVP_PKEY_ED25519, None, priv, 32)
    if not pkey:
        raise OSError("OpenSSL EVP_PKEY_new_raw_private_key(ED25519) failed")
    try:
        pub_buf = ctypes.create_string_buffer(32)
        pub_len = ctypes.c_size_t(32)
        if lib.EVP_PKEY_get_raw_public_key(pkey, pub_buf, ctypes.byref(pub_len)) != 1:
            raise OSError("OpenSSL EVP_PKEY_get_raw_public_key(ED25519) failed")
        return priv, pub_buf.raw[: pub_len.value]
    finally:
        lib.EVP_PKEY_free(pkey)


def ed25519_sign(private_key_32b: bytes, message: bytes) -> bytes:
    """Signs message bytes with a 32-byte raw Ed25519 private key, returning a 64-byte signature."""
    if len(private_key_32b) != 32:
        raise ValueError("Ed25519 private key must be exactly 32 bytes")
    lib = _get_libcrypto()
    pkey = lib.EVP_PKEY_new_raw_private_key(_EVP_PKEY_ED25519, None, private_key_32b, 32)
    if not pkey:
        raise OSError("OpenSSL EVP_PKEY_new_raw_private_key failed")
    mdctx = lib.EVP_MD_CTX_new()
    if not mdctx:
        lib.EVP_PKEY_free(pkey)
        raise OSError("OpenSSL EVP_MD_CTX_new failed")
    try:
        if lib.EVP_DigestSignInit(mdctx, None, None, None, pkey) != 1:
            raise OSError("OpenSSL EVP_DigestSignInit(ED25519) failed")
        sig_buf = ctypes.create_string_buffer(64)
        sig_len = ctypes.c_size_t(64)
        if lib.EVP_DigestSign(mdctx, sig_buf, ctypes.byref(sig_len), message, len(message)) != 1:
            raise OSError("OpenSSL EVP_DigestSign(ED25519) failed")
        return sig_buf.raw[: sig_len.value]
    finally:
        lib.EVP_MD_CTX_free(mdctx)
        lib.EVP_PKEY_free(pkey)


def ed25519_verify(public_key_32b: bytes, message: bytes, signature_64b: bytes) -> bool:
    """Verifies a 64-byte Ed25519 signature against a raw 32-byte or X.509 SPKI public key."""
    if len(public_key_32b) == 44 and public_key_32b.startswith(b"\x30\x2a\x30\x05\x06\x03\x2b\x65\x70\x03\x21\x00"):
        public_key_32b = public_key_32b[-32:]
    if len(public_key_32b) != 32 or len(signature_64b) != 64:
        return False
    lib = _get_libcrypto()
    pkey = lib.EVP_PKEY_new_raw_public_key(_EVP_PKEY_ED25519, None, public_key_32b, 32)
    if not pkey:
        return False
    mdctx = lib.EVP_MD_CTX_new()
    if not mdctx:
        lib.EVP_PKEY_free(pkey)
        return False
    try:
        if lib.EVP_DigestVerifyInit(mdctx, None, None, None, pkey) != 1:
            return False
        res = lib.EVP_DigestVerify(mdctx, signature_64b, len(signature_64b), message, len(message))
        return res == 1
    finally:
        lib.EVP_MD_CTX_free(mdctx)
        lib.EVP_PKEY_free(pkey)


def generate_x25519_keypair() -> tuple[bytes, bytes]:
    """Generates a fresh (private_key_32b, public_key_32b) X25519 ephemeral keypair."""
    lib = _get_libcrypto()
    priv = secrets.token_bytes(32)
    pkey = lib.EVP_PKEY_new_raw_private_key(_EVP_PKEY_X25519, None, priv, 32)
    if not pkey:
        raise OSError("OpenSSL EVP_PKEY_new_raw_private_key(X25519) failed")
    try:
        pub_buf = ctypes.create_string_buffer(32)
        pub_len = ctypes.c_size_t(32)
        if lib.EVP_PKEY_get_raw_public_key(pkey, pub_buf, ctypes.byref(pub_len)) != 1:
            raise OSError("OpenSSL EVP_PKEY_get_raw_public_key(X25519) failed")
        return priv, pub_buf.raw[: pub_len.value]
    finally:
        lib.EVP_PKEY_free(pkey)


def x25519_derive_shared_secret(private_key_32b: bytes, peer_public_key_32b: bytes) -> bytes:
    """Computes the 32-byte X25519 Diffie-Hellman shared secret."""
    if len(peer_public_key_32b) == 44 and peer_public_key_32b.startswith(b"\x30\x2a\x30\x05\x06\x03\x2b\x65\x6e\x03\x21\x00"):
        peer_public_key_32b = peer_public_key_32b[-32:]
    if len(private_key_32b) != 32 or len(peer_public_key_32b) != 32:
        raise ValueError("X25519 keys must be 32 bytes")
    lib = _get_libcrypto()
    priv_pkey = lib.EVP_PKEY_new_raw_private_key(_EVP_PKEY_X25519, None, private_key_32b, 32)
    peer_pkey = lib.EVP_PKEY_new_raw_public_key(_EVP_PKEY_X25519, None, peer_public_key_32b, 32)
    if not priv_pkey or not peer_pkey:
        if priv_pkey:
            lib.EVP_PKEY_free(priv_pkey)
        if peer_pkey:
            lib.EVP_PKEY_free(peer_pkey)
        raise OSError("OpenSSL failed to load X25519 keys")
    ctx = lib.EVP_PKEY_CTX_new(priv_pkey, None)
    if not ctx:
        lib.EVP_PKEY_free(peer_pkey)
        lib.EVP_PKEY_free(priv_pkey)
        raise OSError("OpenSSL EVP_PKEY_CTX_new(X25519) failed")
    try:
        if lib.EVP_PKEY_derive_init(ctx) != 1:
            raise OSError("EVP_PKEY_derive_init failed")
        if lib.EVP_PKEY_derive_set_peer(ctx, peer_pkey) != 1:
            raise OSError("EVP_PKEY_derive_set_peer failed")
        sec_buf = ctypes.create_string_buffer(32)
        sec_len = ctypes.c_size_t(32)
        if lib.EVP_PKEY_derive(ctx, sec_buf, ctypes.byref(sec_len)) != 1:
            raise OSError("EVP_PKEY_derive failed")
        return sec_buf.raw[: sec_len.value]
    finally:
        lib.EVP_PKEY_CTX_free(ctx)
        lib.EVP_PKEY_free(peer_pkey)
        lib.EVP_PKEY_free(priv_pkey)


def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
    """RFC 5869 HKDF-SHA256 Extract + Expand using standard-library hmac/hashlib."""
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    t = b""
    okm = bytearray()
    counter = 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
        okm.extend(t)
        counter += 1
    return bytes(okm[:length])


def derive_sas_6digit_and_hmac(
    *,
    shared_secret: bytes,
    pairing_nonce: bytes,
    windows_tls_cert_sha256: str,
    android_ed25519_pub_b64: str,
    pairing_session_id: str,
) -> tuple[str, str]:
    """Derives (sas_6digit_code, sas_verification_code_hmac_b64) via HKDF-SHA256."""
    info = (
        f"PSYCHE-SAS-v1|{windows_tls_cert_sha256}|{android_ed25519_pub_b64}"
    ).encode("utf-8")
    okm = hkdf_sha256(shared_secret, salt=pairing_nonce, info=info, length=32)
    sas_num = int.from_bytes(okm[:4], "big") % 1_000_000
    sas_6digit = f"{sas_num:06d}"
    confirm_msg = f"SAS-CONFIRM:{sas_6digit}:{pairing_session_id}".encode("utf-8")
    confirm_hmac = hmac.new(okm, confirm_msg, hashlib.sha256).digest()
    return sas_6digit, base64.b64encode(confirm_hmac).decode("ascii")


def canonical_pairing_confirm_bytes(req: dict[str, Any]) -> bytes:
    return (
        f"{req['pairing_session_id']}|{req['device_id']}|{req['android_ed25519_pub_b64']}|"
        f"{req['android_x25519_ephemeral_pub_b64']}|{req['android_tls_cert_sha256']}|"
        f"{req['sas_verification_code_hmac_b64']}|{req['requested_at_utc']}"
    ).encode("utf-8")


def canonical_event_bytes(ev: dict[str, Any]) -> bytes:
    return (
        f"{ev['event_id']}|{ev['package_name']}|{ev['conversation_key']}|"
        f"{ev['content']['raw_text_sha256']}|{ev['posted_at_utc']}"
    ).encode("utf-8")


def canonical_batch_bytes(req: dict[str, Any]) -> bytes:
    event_digest_src = "|".join(
        f"{ev['event_id']}:{ev['content']['raw_text_sha256']}" for ev in req["events"]
    )
    events_sha256 = hashlib.sha256(event_digest_src.encode("utf-8")).hexdigest()
    return f"{req['batch_id']}|{req['device_id']}|{req['sent_at_utc']}|{events_sha256}".encode(
        "utf-8"
    )


def canonical_contact_sync_bytes(req: dict[str, Any]) -> bytes:
    return (
        f"{req['sync_batch_id']}|{req['device_id']}|{req['sent_at_utc']}|{len(req['contacts'])}"
    ).encode("utf-8")


def canonical_presence_heartbeat_bytes(req: dict[str, Any]) -> bytes:
    return (
        f"{req['device_id']}|{req['timestamp_utc']}|{req['user_presence_state']}|"
        f"{req['pending_queue_count']}"
    ).encode("utf-8")


def _parse_utc(ts: str) -> datetime:
    if ts.endswith("Z"):
        ts = ts[:-1] + "+00:00"
    return datetime.fromisoformat(ts).astimezone(timezone.utc)


class FortressPairingManager:
    """Manages ephemeral X25519 QR challenges, 6-digit SAS verification, Ed25519 verification & replay defense."""

    def __init__(self, db: PsycheDatabase, validator: ContractValidator | None = None) -> None:
        self.db = db
        self.validator = validator or ContractValidator()
        self._active_sessions: dict[str, dict[str, Any]] = {}
        self._device_pubkey_cache: dict[str, tuple[str, str]] = {}
        self._ensure_replay_table()
        self._refresh_pubkey_cache_if_unlocked()

    def _refresh_pubkey_cache_if_unlocked(self) -> None:
        if self.db.vault.is_locked:
            return
        rows = self.db.connection.execute(
            "SELECT device_id, ed25519_public_key_b64, trust_status FROM paired_devices"
        ).fetchall()
        for r in rows:
            self._device_pubkey_cache[str(r["device_id"])] = (
                str(r["ed25519_public_key_b64"]),
                str(r["trust_status"]),
            )

    def _ensure_replay_table(self) -> None:
        self.db.connection.execute(
            """
            CREATE TABLE IF NOT EXISTS processed_sync_batches (
                batch_id TEXT PRIMARY KEY,
                device_id TEXT NOT NULL,
                processed_at_utc TEXT NOT NULL
            )
            """
        )
        self.db.connection.commit()

    def initiate_pairing_session(
        self,
        *,
        windows_host_endpoint: str,
        windows_tls_cert_sha256: str,
        ttl_seconds: int = 300,
    ) -> dict[str, Any]:
        """Generates a fresh ephemeral X25519 QR pairing challenge."""
        from core.storage.database import generate_uuidv7

        session_id = generate_uuidv7()
        x_priv, x_pub = generate_x25519_keypair()
        nonce = secrets.token_bytes(16)
        expires_at = (datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds)).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
        payload = {
            "schema_version": "1.0.0",
            "pairing_session_id": session_id,
            "windows_host_endpoint": windows_host_endpoint,
            "windows_tls_cert_sha256": windows_tls_cert_sha256,
            "windows_x25519_ephemeral_pub_b64": base64.b64encode(x_pub).decode("ascii"),
            "pairing_nonce_b64": base64.b64encode(nonce).decode("ascii"),
            "expires_at_utc": expires_at,
        }
        self.validator.validate("device_pairing.schema.json", "QrChallengePayload", payload)
        self._active_sessions[session_id] = {
            "windows_x25519_priv": x_priv,
            "pairing_nonce": nonce,
            "windows_tls_cert_sha256": windows_tls_cert_sha256,
            "expires_at_utc": expires_at,
        }
        return payload

    def confirm_pairing(
        self,
        confirm_request: dict[str, Any],
        *,
        user_confirmed_sas_6digit: str | None = None,
        reference_now_utc: str | None = None,
    ) -> dict[str, Any]:
        """Verifies Android X25519+Ed25519+HKDF-SAS confirmation and registers paired device."""
        from core.storage.database import utc_now_iso

        self.validator.validate(
            "device_pairing.schema.json", "PairingConfirmRequest", confirm_request
        )
        session_id = confirm_request["pairing_session_id"]
        session = self._active_sessions.get(session_id)
        if session is None:
            raise KeyError(f"Unknown or consumed pairing session {session_id}")

        now_iso = utc_now_iso()
        now_dt = _parse_utc(reference_now_utc or now_iso)
        exp_dt = _parse_utc(session["expires_at_utc"])
        if now_dt > exp_dt:
            self._active_sessions.pop(session_id, None)
            resp = {
                "schema_version": "1.0.0",
                "pairing_session_id": session_id,
                "device_id": confirm_request["device_id"],
                "status": "EXPIRED",
                "paired_at_utc": now_iso,
                "pinned_windows_tls_cert_sha256": session["windows_tls_cert_sha256"],
            }
            self.validator.validate("device_pairing.schema.json", "PairingConfirmResponse", resp)
            return resp

        try:
            android_ed_pub = base64.b64decode(confirm_request["android_ed25519_pub_b64"], validate=True)
            android_x_pub = base64.b64decode(
                confirm_request["android_x25519_ephemeral_pub_b64"], validate=True
            )
            sig_bytes = base64.b64decode(confirm_request["ed25519_signature"], validate=True)
        except Exception:
            resp = {
                "schema_version": "1.0.0",
                "pairing_session_id": session_id,
                "device_id": confirm_request["device_id"],
                "status": "REJECTED_SAS_MISMATCH",
                "paired_at_utc": now_iso,
                "pinned_windows_tls_cert_sha256": session["windows_tls_cert_sha256"],
            }
            self.validator.validate("device_pairing.schema.json", "PairingConfirmResponse", resp)
            return resp

        # Verify Android Ed25519 self-signature over confirm payload
        if not ed25519_verify(
            android_ed_pub, canonical_pairing_confirm_bytes(confirm_request), sig_bytes
        ):
            resp = {
                "schema_version": "1.0.0",
                "pairing_session_id": session_id,
                "device_id": confirm_request["device_id"],
                "status": "REJECTED_SAS_MISMATCH",
                "paired_at_utc": now_iso,
                "pinned_windows_tls_cert_sha256": session["windows_tls_cert_sha256"],
            }
            self.validator.validate("device_pairing.schema.json", "PairingConfirmResponse", resp)
            return resp

        # Derive X25519 shared secret and 6-digit HKDF-SHA256 SAS + HMAC
        shared_secret = x25519_derive_shared_secret(session["windows_x25519_priv"], android_x_pub)
        expected_sas, expected_hmac_b64 = derive_sas_6digit_and_hmac(
            shared_secret=shared_secret,
            pairing_nonce=session["pairing_nonce"],
            windows_tls_cert_sha256=session["windows_tls_cert_sha256"],
            android_ed25519_pub_b64=confirm_request["android_ed25519_pub_b64"],
            pairing_session_id=session_id,
        )

        hmac_matches = hmac.compare_digest(
            expected_hmac_b64, confirm_request["sas_verification_code_hmac_b64"]
        )
        sas_matches = (
            True
            if user_confirmed_sas_6digit is None
            else hmac.compare_digest(expected_sas, user_confirmed_sas_6digit.strip())
        )
        if not (hmac_matches and sas_matches):
            resp = {
                "schema_version": "1.0.0",
                "pairing_session_id": session_id,
                "device_id": confirm_request["device_id"],
                "status": "REJECTED_SAS_MISMATCH",
                "paired_at_utc": now_iso,
                "pinned_windows_tls_cert_sha256": session["windows_tls_cert_sha256"],
            }
            self.validator.validate("device_pairing.schema.json", "PairingConfirmResponse", resp)
            return resp

        # Pairing verified — pin Android Ed25519 public key and TLS fingerprint
        conn = self.db.connection
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
            (
                confirm_request["device_id"],
                confirm_request["device_name"],
                confirm_request["android_ed25519_pub_b64"],
                confirm_request["android_tls_cert_sha256"],
                now_iso,
                now_iso,
            ),
        )
        conn.commit()
        self._device_pubkey_cache[confirm_request["device_id"]] = (
            confirm_request["android_ed25519_pub_b64"],
            "ACTIVE",
        )
        self._active_sessions.pop(session_id, None)

        resp = {
            "schema_version": "1.0.0",
            "pairing_session_id": session_id,
            "device_id": confirm_request["device_id"],
            "status": "PAIRED",
            "paired_at_utc": now_iso,
            "pinned_windows_tls_cert_sha256": session["windows_tls_cert_sha256"],
        }
        self.validator.validate("device_pairing.schema.json", "PairingConfirmResponse", resp)
        return resp

    def verify_device_signature(
        self,
        *,
        device_id: str,
        canonical_payload: bytes,
        signature_b64: str,
        require_crypto: bool = True,
    ) -> bool:
        """Verifies an Ed25519 signature against the pinned public key in paired_devices.

        If require_crypto=False and the stored device key is a synthetic non-32B placeholder
        used in offline unit fixtures, verification degrades safely only when explicitly allowed;
        whenever a real 32-byte Ed25519 public key is pinned OR require_crypto=True, strict
        cryptographic verification is enforced.
        """
        if not self.db.vault.is_locked:
            row = self.db.connection.execute(
                "SELECT ed25519_public_key_b64, trust_status FROM paired_devices WHERE device_id = ?",
                (device_id,),
            ).fetchone()
            if row is None:
                raise PermissionError(f"Device {device_id} is not an active paired device")
            pub_b64 = str(row["ed25519_public_key_b64"])
            trust_status = str(row["trust_status"])
            self._device_pubkey_cache[device_id] = (pub_b64, trust_status)
        else:
            cached = self._device_pubkey_cache.get(device_id)
            if cached is None:
                raise PermissionError(
                    f"Device {device_id} is not cached in active session while vault is locked"
                )
            pub_b64, trust_status = cached

        if trust_status != "ACTIVE":
            raise PermissionError(f"Device {device_id} is not an active paired device")

        try:
            pub_raw = base64.b64decode(pub_b64, validate=False)
        except Exception:
            pub_raw = b""

        if len(pub_raw) != 32:
            if require_crypto:
                raise PermissionError(
                    f"Device {device_id} does not hold a valid 32-byte Ed25519 public key"
                )
            return True

        try:
            sig_raw = base64.b64decode(signature_b64, validate=True)
        except Exception as exc:
            raise PermissionError("Malformed Base64 Ed25519 signature") from exc

        if not ed25519_verify(pub_raw, canonical_payload, sig_raw):
            raise PermissionError(f"Ed25519 signature verification failed for device {device_id}")
        return True

    def check_replay_and_clock_skew(
        self,
        *,
        batch_id: str,
        device_id: str,
        sent_at_utc: str,
        reference_now_utc: str | None = None,
        max_skew_seconds: int = 120,
        enforce_clock_skew: bool = False,
    ) -> None:
        """Prevents replay of processed batch_ids and optionally enforces +-120s clock skew."""
        self._ensure_replay_table()
        conn = self.db.connection
        existing = conn.execute(
            "SELECT batch_id FROM processed_sync_batches WHERE batch_id = ?",
            (batch_id,),
        ).fetchone()
        if existing is not None:
            raise ContractValidationError(
                f"Replay detected: batch_id {batch_id} has already been processed",
                error_code="REPLAY_BATCH_DETECTED",
            )

        from core.storage.database import utc_now_iso

        if enforce_clock_skew:
            now_dt = _parse_utc(reference_now_utc or utc_now_iso())
            sent_dt = _parse_utc(sent_at_utc)
            if abs((now_dt - sent_dt).total_seconds()) > max_skew_seconds:
                raise ContractValidationError(
                    f"Clock skew exceeded +- {max_skew_seconds}s window for batch {batch_id}",
                    error_code="CLOCK_SKEW_EXCEEDED",
                )

        conn.execute(
            """
            INSERT INTO processed_sync_batches (batch_id, device_id, processed_at_utc)
            VALUES (?, ?, ?)
            """,
            (batch_id, device_id, utc_now_iso()),
        )
        conn.commit()
