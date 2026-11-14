"""PSYCHE FORTRESS — Zero-Trust Security, DPAPI/AES-256-GCM Vault, Pairing & Prompt-Injection Sandbox."""

from core.subsystems.fortress.crypto_vault import (
    AES256GCMCipher,
    DPAPIMasterKeyManager,
    PsycheFortressVault,
    TamperDetectedError,
    VaultLockedError,
    detect_prompt_injection_attempt,
    sandbox_untrusted_message,
)
from core.subsystems.fortress.pairing import (
    FortressPairingManager,
    canonical_batch_bytes,
    canonical_contact_sync_bytes,
    canonical_event_bytes,
    canonical_pairing_confirm_bytes,
    canonical_presence_heartbeat_bytes,
    derive_sas_6digit_and_hmac,
    ed25519_sign,
    ed25519_verify,
    generate_ed25519_keypair,
    generate_x25519_keypair,
    hkdf_sha256,
    x25519_derive_shared_secret,
)

__all__ = [
    "AES256GCMCipher",
    "DPAPIMasterKeyManager",
    "FortressPairingManager",
    "PsycheFortressVault",
    "TamperDetectedError",
    "VaultLockedError",
    "canonical_batch_bytes",
    "canonical_contact_sync_bytes",
    "canonical_event_bytes",
    "canonical_pairing_confirm_bytes",
    "canonical_presence_heartbeat_bytes",
    "derive_sas_6digit_and_hmac",
    "detect_prompt_injection_attempt",
    "ed25519_sign",
    "ed25519_verify",
    "generate_ed25519_keypair",
    "generate_x25519_keypair",
    "hkdf_sha256",
    "sandbox_untrusted_message",
    "x25519_derive_shared_secret",
]
