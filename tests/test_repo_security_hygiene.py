"""Repository Security Hygiene & Zero-Cloud Enforcement Tests (SECURITY.md / AC-07)."""

from __future__ import annotations

from pathlib import Path
import re
import subprocess

from core.subsystems.economy.governor import ExternalProviderBlockedError, PsycheEconomyGovernor
from core.subsystems.local_core.runtime import DEFAULT_LLAMA_ENDPOINT, PsycheLocalCoreRuntime

REPO_ROOT = Path(__file__).resolve().parent.parent

FORBIDDEN_TRACKED_EXTENSIONS = {
    ".pem",
    ".key",
    ".crt",
    ".cer",
    ".pfx",
    ".p12",
    ".jks",
    ".keystore",
    ".db",
    ".sqlite",
    ".sqlite3",
    ".sqlcipher",
    ".npy",
    ".npz",
    ".gguf",
    ".safetensors",
    ".env",
}

SECRET_SCAN_PATTERNS = (
    re.compile(r"BEGIN\s+(?:RSA\s+|EC\s+|OPENSSH\s+)?PRIVATE\s+KEY"),
    re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bAIza[0-9A-Za-z\-_]{30,}\b"),
)


def test_gitignore_contains_mandatory_security_rules() -> None:
    gitignore_text = (REPO_ROOT / ".gitignore").read_text(encoding="utf-8")
    required_entries = [
        "*.pem",
        "*.key",
        ".env",
        "*.db",
        "*.sqlite",
        "*.npy",
        "*.gguf",
        "*.safetensors",
    ]
    for entry in required_entries:
        assert entry in gitignore_text, f"Missing '{entry}' rule in .gitignore"


def test_tracked_git_files_contain_no_secrets_keys_or_databases() -> None:
    proc = subprocess.run(
        ["git", "ls-files"],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        check=True,
    )
    tracked_files = [line.strip() for line in proc.stdout.splitlines() if line.strip()]
    assert len(tracked_files) > 0

    for rel_path in tracked_files:
        path = REPO_ROOT / rel_path
        assert path.suffix.lower() not in FORBIDDEN_TRACKED_EXTENSIONS, (
            f"Forbidden tracked file extension detected: {rel_path}"
        )
        assert path.name != ".env" and path.name != "local.properties", (
            f"Forbidden secret configuration file tracked: {rel_path}"
        )
        # Skip test files themselves when scanning literal secret-regex patterns
        if rel_path.startswith("tests/") or rel_path.endswith(".md"):
            continue
        if path.is_file():
            content = path.read_text(encoding="utf-8", errors="ignore")
            for pat in SECRET_SCAN_PATTERNS:
                assert not pat.search(content), (
                    f"Potential secret/private-key pattern matched in tracked file: {rel_path}"
                )


def test_local_only_zero_cloud_defaults() -> None:
    governor = PsycheEconomyGovernor()
    assert governor.external_providers_enabled is False
    assert governor.paid_api_spend_usd == 0.0
    assert DEFAULT_LLAMA_ENDPOINT == "http://127.0.0.1:8089"

    runtime = PsycheLocalCoreRuntime(economy=governor)
    assert runtime.local_llama_endpoint == "http://127.0.0.1:8089"

    for remote_url in (
        "https://api.openai.com/v1/chat/completions",
        "https://generativelanguage.googleapis.com",
        "https://api.anthropic.com/v1/messages",
    ):
        try:
            governor.assert_local_only_execution(remote_url)
            raise AssertionError(f"Expected ExternalProviderBlockedError for {remote_url}")
        except ExternalProviderBlockedError:
            pass
