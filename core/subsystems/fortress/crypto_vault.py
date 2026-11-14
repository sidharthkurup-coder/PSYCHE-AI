"""PSYCHE FORTRESS — Cryptographic Vault, Windows DPAPI Key Custody & Prompt-Injection Sandbox.

Implements:
- Native Windows DPAPI (crypt32.dll CryptProtectData / CryptUnprotectData) master key sealing
  with explicit ctypes memory zeroization before LocalFree.
- Native Windows CNG (bcrypt.dll) hardware-accelerated AES-256-GCM authenticated encryption
  using zero-copy bytearray buffers and deterministic buffer wiping in finally blocks.
- Panic Lock with immediate in-memory key and attached database vector buffer zeroization
  (SECURITY.md Section 2.2).
- Untrusted notification sandboxing with randomized cryptographic nonces and prompt-injection
  detection (SECURITY.md Section 2.6).
"""

from __future__ import annotations

from collections.abc import Callable
import ctypes
from ctypes import wintypes
import os
from pathlib import Path
import re
import secrets

_CRYPTPROTECT_UI_FORBIDDEN = 0x01
_NONCE_LEN = 12
_TAG_LEN = 16
_KEY_LEN = 32
_ENVELOPE_MAGIC = b"PSYC1"


class VaultLockedError(RuntimeError):
    """Raised when attempting cryptographic operations while PSYCHE FORTRESS is locked."""


class TamperDetectedError(ValueError):
    """Raised when AES-256-GCM authentication tag or AAD verification fails."""


class _DATA_BLOB(ctypes.Structure):
    _fields_ = [
        ("cbData", wintypes.DWORD),
        ("pbData", ctypes.POINTER(ctypes.c_char)),
    ]


class _BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO(ctypes.Structure):
    _fields_ = [
        ("cbSize", ctypes.c_ulong),
        ("dwInfoVersion", ctypes.c_ulong),
        ("pbNonce", ctypes.c_void_p),
        ("cbNonce", ctypes.c_ulong),
        ("pbAuthData", ctypes.c_void_p),
        ("cbAuthData", ctypes.c_ulong),
        ("pbTag", ctypes.c_void_p),
        ("cbTag", ctypes.c_ulong),
        ("pbMacContext", ctypes.c_void_p),
        ("cbMacContext", ctypes.c_ulong),
        ("cbAAD", ctypes.c_ulong),
        ("cbData", ctypes.c_ulonglong),
        ("dwFlags", ctypes.c_ulong),
    ]


def _secure_zero_ctypes(buf: ctypes.Array[ctypes.c_char] | None) -> None:
    """Zeroizes a ctypes char array in-place in RAM."""
    if buf is not None and ctypes.sizeof(buf) > 0:
        ctypes.memset(ctypes.addressof(buf), 0, ctypes.sizeof(buf))


def _secure_zero_bytearray(ba: bytearray | None) -> None:
    """Zeroizes a mutable bytearray in-place in RAM."""
    if ba is not None:
        for i in range(len(ba)):
            ba[i] = 0


class DPAPIMasterKeyManager:
    """Seals and unseals 256-bit master keys using Windows DPAPI (crypt32.dll)."""

    @staticmethod
    def protect_bytes(plaintext: bytes | bytearray, entropy: bytes | None = None) -> bytes:
        crypt32 = ctypes.windll.crypt32
        kernel32 = ctypes.windll.kernel32

        pt_len = len(plaintext)
        in_buf = ctypes.create_string_buffer(bytes(plaintext), pt_len)
        in_blob = _DATA_BLOB(pt_len, in_buf)
        out_blob = _DATA_BLOB()

        ent_buf = None
        entropy_blob_ref = None
        if entropy:
            ent_buf = ctypes.create_string_buffer(entropy, len(entropy))
            ent_blob = _DATA_BLOB(len(entropy), ent_buf)
            entropy_blob_ref = ctypes.byref(ent_blob)

        try:
            ok = crypt32.CryptProtectData(
                ctypes.byref(in_blob),
                None,
                entropy_blob_ref,
                None,
                None,
                _CRYPTPROTECT_UI_FORBIDDEN,
                ctypes.byref(out_blob),
            )
            if not ok:
                raise OSError("Windows DPAPI CryptProtectData failed")
            return ctypes.string_at(out_blob.pbData, out_blob.cbData)
        finally:
            _secure_zero_ctypes(in_buf)
            _secure_zero_ctypes(ent_buf)
            if out_blob.pbData:
                ctypes.memset(out_blob.pbData, 0, out_blob.cbData)
                kernel32.LocalFree(out_blob.pbData)

    @staticmethod
    def unprotect_to_bytearray(sealed_blob: bytes, entropy: bytes | None = None) -> bytearray:
        """Unseals a DPAPI blob into a mutable bytearray and wipes the Win32 LocalAlloc buffer."""
        crypt32 = ctypes.windll.crypt32
        kernel32 = ctypes.windll.kernel32

        in_buf = ctypes.create_string_buffer(sealed_blob, len(sealed_blob))
        in_blob = _DATA_BLOB(len(sealed_blob), in_buf)
        out_blob = _DATA_BLOB()

        ent_buf = None
        entropy_blob_ref = None
        if entropy:
            ent_buf = ctypes.create_string_buffer(entropy, len(entropy))
            ent_blob = _DATA_BLOB(len(entropy), ent_buf)
            entropy_blob_ref = ctypes.byref(ent_blob)

        try:
            ok = crypt32.CryptUnprotectData(
                ctypes.byref(in_blob),
                None,
                entropy_blob_ref,
                None,
                None,
                _CRYPTPROTECT_UI_FORBIDDEN,
                ctypes.byref(out_blob),
            )
            if not ok:
                raise TamperDetectedError(
                    "Windows DPAPI CryptUnprotectData failed or blob tampered"
                )
            result = bytearray(out_blob.cbData)
            if out_blob.cbData > 0:
                ctypes.memmove(
                    (ctypes.c_char * out_blob.cbData).from_buffer(result),
                    out_blob.pbData,
                    out_blob.cbData,
                )
            return result
        finally:
            _secure_zero_ctypes(ent_buf)
            if out_blob.pbData:
                ctypes.memset(out_blob.pbData, 0, out_blob.cbData)
                kernel32.LocalFree(out_blob.pbData)

    @staticmethod
    def unprotect_bytes(sealed_blob: bytes, entropy: bytes | None = None) -> bytes:
        ba = DPAPIMasterKeyManager.unprotect_to_bytearray(sealed_blob, entropy=entropy)
        try:
            return bytes(ba)
        finally:
            _secure_zero_bytearray(ba)


class AES256GCMCipher:
    """Native Windows CNG (bcrypt.dll) AES-256-GCM authenticated cipher."""

    def __init__(self, key_32_bytes: bytes | bytearray) -> None:
        if len(key_32_bytes) != _KEY_LEN:
            raise ValueError("AES-256-GCM requires a 32-byte key")
        self._key_buffer = bytearray(key_32_bytes)
        self._locked = False

    @property
    def is_locked(self) -> bool:
        return self._locked

    def zeroize_and_lock(self) -> None:
        """Overwrites in-memory key buffer with zeros (Panic Lock)."""
        _secure_zero_bytearray(self._key_buffer)
        self._locked = True

    def encrypt(self, plaintext: bytes, aad: bytes = b"") -> bytes:
        """Encrypts plaintext and returns envelope: MAGIC(5B) || NONCE(12B) || TAG(16B) || CIPHERTEXT."""
        if self._locked:
            raise VaultLockedError("Cannot encrypt: PSYCHE FORTRESS cipher is locked")

        bcrypt = ctypes.windll.bcrypt
        alg = ctypes.c_void_p()
        hkey = ctypes.c_void_p()
        pt_buf = None
        try:
            if (
                bcrypt.BCryptOpenAlgorithmProvider(
                    ctypes.byref(alg), ctypes.c_wchar_p("AES"), None, 0
                )
                != 0
            ):
                raise OSError("BCryptOpenAlgorithmProvider(AES) failed")
            gcm_mode = ctypes.create_unicode_buffer("ChainingModeGCM")
            if (
                bcrypt.BCryptSetProperty(
                    alg,
                    ctypes.c_wchar_p("ChainingMode"),
                    gcm_mode,
                    ctypes.sizeof(gcm_mode),
                    0,
                )
                != 0
            ):
                raise OSError("BCryptSetProperty(ChainingModeGCM) failed")

            # Zero-copy view over mutable self._key_buffer (no immutable bytes allocation)
            key_view = (ctypes.c_char * _KEY_LEN).from_buffer(self._key_buffer)
            if (
                bcrypt.BCryptGenerateSymmetricKey(
                    alg, ctypes.byref(hkey), None, 0, key_view, _KEY_LEN, 0
                )
                != 0
            ):
                raise OSError("BCryptGenerateSymmetricKey failed")

            nonce = os.urandom(_NONCE_LEN)
            nonce_buf = ctypes.create_string_buffer(nonce, _NONCE_LEN)
            tag_buf = ctypes.create_string_buffer(_TAG_LEN)
            aad_buf = ctypes.create_string_buffer(aad, len(aad)) if aad else None

            info = _BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO()
            info.cbSize = ctypes.sizeof(_BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO)
            info.dwInfoVersion = 1
            info.pbNonce = ctypes.cast(nonce_buf, ctypes.c_void_p)
            info.cbNonce = _NONCE_LEN
            info.pbAuthData = ctypes.cast(aad_buf, ctypes.c_void_p) if aad_buf else None
            info.cbAuthData = len(aad)
            info.pbTag = ctypes.cast(tag_buf, ctypes.c_void_p)
            info.cbTag = _TAG_LEN

            pt_len = len(plaintext)
            pt_buf = ctypes.create_string_buffer(plaintext, pt_len)
            ct_buf = ctypes.create_string_buffer(max(pt_len, 1))
            cb_res = ctypes.c_ulong()

            status = bcrypt.BCryptEncrypt(
                hkey,
                pt_buf,
                pt_len,
                ctypes.byref(info),
                None,
                0,
                ct_buf,
                pt_len,
                ctypes.byref(cb_res),
                0,
            )
            if status != 0:
                raise OSError(f"BCryptEncrypt failed with NTSTATUS 0x{status & 0xFFFFFFFF:08x}")

            ciphertext = ct_buf.raw[:pt_len]
            return _ENVELOPE_MAGIC + nonce + tag_buf.raw + ciphertext
        finally:
            _secure_zero_ctypes(pt_buf)
            if hkey.value:
                bcrypt.BCryptDestroyKey(hkey)
            if alg.value:
                bcrypt.BCryptCloseAlgorithmProvider(alg, 0)

    def decrypt(self, envelope: bytes, aad: bytes = b"") -> bytes:
        """Verifies AES-256-GCM tag and AAD, returning plaintext or raising TamperDetectedError."""
        if self._locked:
            raise VaultLockedError("Cannot decrypt: PSYCHE FORTRESS cipher is locked")

        header_len = len(_ENVELOPE_MAGIC) + _NONCE_LEN + _TAG_LEN
        if len(envelope) < header_len or not envelope.startswith(_ENVELOPE_MAGIC):
            raise TamperDetectedError("Invalid PSYCHE FORTRESS ciphertext envelope header")

        offset = len(_ENVELOPE_MAGIC)
        nonce = envelope[offset : offset + _NONCE_LEN]
        offset += _NONCE_LEN
        tag = envelope[offset : offset + _TAG_LEN]
        offset += _TAG_LEN
        ciphertext = envelope[offset:]
        ct_len = len(ciphertext)

        bcrypt = ctypes.windll.bcrypt
        alg = ctypes.c_void_p()
        hkey = ctypes.c_void_p()
        pt_buf = None
        try:
            if (
                bcrypt.BCryptOpenAlgorithmProvider(
                    ctypes.byref(alg), ctypes.c_wchar_p("AES"), None, 0
                )
                != 0
            ):
                raise OSError("BCryptOpenAlgorithmProvider(AES) failed")
            gcm_mode = ctypes.create_unicode_buffer("ChainingModeGCM")
            if (
                bcrypt.BCryptSetProperty(
                    alg,
                    ctypes.c_wchar_p("ChainingMode"),
                    gcm_mode,
                    ctypes.sizeof(gcm_mode),
                    0,
                )
                != 0
            ):
                raise OSError("BCryptSetProperty(ChainingModeGCM) failed")

            key_view = (ctypes.c_char * _KEY_LEN).from_buffer(self._key_buffer)
            if (
                bcrypt.BCryptGenerateSymmetricKey(
                    alg, ctypes.byref(hkey), None, 0, key_view, _KEY_LEN, 0
                )
                != 0
            ):
                raise OSError("BCryptGenerateSymmetricKey failed")

            nonce_buf = ctypes.create_string_buffer(nonce, _NONCE_LEN)
            tag_buf = ctypes.create_string_buffer(tag, _TAG_LEN)
            aad_buf = ctypes.create_string_buffer(aad, len(aad)) if aad else None

            info = _BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO()
            info.cbSize = ctypes.sizeof(_BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO)
            info.dwInfoVersion = 1
            info.pbNonce = ctypes.cast(nonce_buf, ctypes.c_void_p)
            info.cbNonce = _NONCE_LEN
            info.pbAuthData = ctypes.cast(aad_buf, ctypes.c_void_p) if aad_buf else None
            info.cbAuthData = len(aad)
            info.pbTag = ctypes.cast(tag_buf, ctypes.c_void_p)
            info.cbTag = _TAG_LEN

            ct_buf = ctypes.create_string_buffer(ciphertext, ct_len)
            pt_buf = ctypes.create_string_buffer(max(ct_len, 1))
            cb_res = ctypes.c_ulong()

            status = bcrypt.BCryptDecrypt(
                hkey,
                ct_buf,
                ct_len,
                ctypes.byref(info),
                None,
                0,
                pt_buf,
                ct_len,
                ctypes.byref(cb_res),
                0,
            )
            if status != 0:
                raise TamperDetectedError(
                    f"AES-256-GCM authentication tag or AAD verification failed (0x{status & 0xFFFFFFFF:08x})"
                )

            return pt_buf.raw[:ct_len]
        finally:
            _secure_zero_ctypes(pt_buf)
            if hkey.value:
                bcrypt.BCryptDestroyKey(hkey)
            if alg.value:
                bcrypt.BCryptCloseAlgorithmProvider(alg, 0)


class PsycheFortressVault:
    """Manages DPAPI-backed master key lifecycle, record encryption, and Panic Lock."""

    _ENTROPY = b"PSYCHE-AI-FORTRESS-V1-DPAPI-ENTROPY"

    def __init__(self, key_file_path: str | Path | None = None) -> None:
        self._key_file_path = Path(key_file_path) if key_file_path else None
        self._cipher: AES256GCMCipher | None = None
        self._on_lock_callbacks: list[Callable[[], None]] = []
        self._on_unlock_callbacks: list[Callable[[], None]] = []
        self._unlock_or_initialize()

    def register_lifecycle_callbacks(
        self,
        *,
        on_lock: Callable[[], None] | None = None,
        on_unlock: Callable[[], None] | None = None,
    ) -> None:
        """Registers callbacks invoked on panic_lock() and unlock() (e.g., to zeroize RAM vectors)."""
        if on_lock is not None:
            self._on_lock_callbacks.append(on_lock)
        if on_unlock is not None:
            self._on_unlock_callbacks.append(on_unlock)

    def _unlock_or_initialize(self) -> None:
        raw_key_ba: bytearray | None = None
        try:
            if self._key_file_path is None:
                raw_key_ba = bytearray(secrets.token_bytes(_KEY_LEN))
                self._cipher = AES256GCMCipher(raw_key_ba)
                return

            self._key_file_path.parent.mkdir(parents=True, exist_ok=True)
            if self._key_file_path.exists():
                sealed = self._key_file_path.read_bytes()
                raw_key_ba = DPAPIMasterKeyManager.unprotect_to_bytearray(
                    sealed, entropy=self._ENTROPY
                )
            else:
                raw_key_ba = bytearray(secrets.token_bytes(_KEY_LEN))
                sealed = DPAPIMasterKeyManager.protect_bytes(raw_key_ba, entropy=self._ENTROPY)
                self._key_file_path.write_bytes(sealed)
            self._cipher = AES256GCMCipher(raw_key_ba)
        finally:
            _secure_zero_bytearray(raw_key_ba)

    @property
    def is_locked(self) -> bool:
        return self._cipher is None or self._cipher.is_locked

    def panic_lock(self) -> None:
        """Immediately zeroizes decrypted key material and attached vector buffers in RAM."""
        if self._cipher is not None:
            self._cipher.zeroize_and_lock()
        self._cipher = None
        for cb in self._on_lock_callbacks:
            cb()

    def unlock(self) -> None:
        """Re-unseals the DPAPI master key file and notifies attached stores."""
        self._unlock_or_initialize()
        for cb in self._on_unlock_callbacks:
            cb()

    def encrypt_blob(self, plaintext: bytes, context_aad: str = "") -> bytes:
        if self._cipher is None or self._cipher.is_locked:
            raise VaultLockedError("PSYCHE FORTRESS vault is locked")
        return self._cipher.encrypt(plaintext, aad=context_aad.encode("utf-8"))

    def decrypt_blob(self, envelope: bytes, context_aad: str = "") -> bytes:
        if self._cipher is None or self._cipher.is_locked:
            raise VaultLockedError("PSYCHE FORTRESS vault is locked")
        return self._cipher.decrypt(envelope, aad=context_aad.encode("utf-8"))

    def encrypt_text(self, text: str, context_aad: str = "") -> bytes:
        return self.encrypt_blob(text.encode("utf-8"), context_aad=context_aad)

    def decrypt_text(self, envelope: bytes, context_aad: str = "") -> str:
        return self.decrypt_blob(envelope, context_aad=context_aad).decode("utf-8")


# Adversarial Prompt-Injection Detection Patterns (SECURITY.md Section 2.6)
_INJECTION_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(
        r"\b(?:ignore|disregard|override|forget)\s+(?:all\s+)?(?:previous|prior|above|system)\s+"
        r"(?:instructions|prompts|rules|safeguards)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(?:system\s+prompt|you\s+are\s+now\s+in\s+developer\s+mode|mark\s+me\s+as\s+inner_circle|"
        r"set\s+trust_level|auto_send_permitted)\b",
        re.IGNORECASE,
    ),
    re.compile(r"</?\s*untrusted_external_message", re.IGNORECASE),
)


def detect_prompt_injection_attempt(raw_text: str) -> tuple[bool, str | None]:
    """Inspects untrusted message text for adversarial prompt-injection directives."""
    for pat in _INJECTION_PATTERNS:
        match = pat.search(raw_text)
        if match:
            return True, f"Detected adversarial instruction override pattern: '{match.group(0)}'"
    return False, None


def sandbox_untrusted_message(raw_text: str, event_id: str) -> tuple[str, str]:
    """Wraps untrusted external message text inside randomized cryptographic nonce delimiters."""
    nonce = secrets.token_hex(8)
    sanitized_body = re.sub(
        r"(</?\s*untrusted_external_message)",
        r"[ESCAPED_TAG:\1]",
        raw_text,
        flags=re.IGNORECASE,
    )
    wrapped = (
        f'<untrusted_external_message event_id="{event_id}" nonce="{nonce}" '
        f'privilege="PASSIVE_DATA_ONLY">\n{sanitized_body}\n'
        f'</untrusted_external_message nonce="{nonce}">'
    )
    return wrapped, nonce
