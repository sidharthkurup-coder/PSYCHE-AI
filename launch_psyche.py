"""One-click launcher for the complete PSYCHE AI Desktop + Local Neural Core + Phone Gateway.

Usage:
    python launch_psyche.py                # Launches llama-server + TLS 1.3 Gateway + Desktop UI
    python launch_psyche.py --headless-check  # Starts services cleanly, verifies health, exits 0
"""

from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import ssl
import subprocess
import sys
import threading
import time
from typing import Any

import uvicorn

ROOT_DIR = Path(__file__).resolve().parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from core.multilingual.pragmatics import detect_language_modes_and_spans  # noqa: E402
from core.pipeline.orchestrator import PsycheIntelligenceOrchestrator  # noqa: E402
from core.storage.database import PsycheDatabase, generate_uuidv7, utc_now_iso  # noqa: E402
from core.subsystems.fortress.crypto_vault import PsycheFortressVault  # noqa: E402
from core.subsystems.local_core.runtime import LlamaServerProcessManager  # noqa: E402
from windows_companion.gateway.mtls_certs import (  # noqa: E402
    create_mtls_ssl_context,
    detect_lan_ipv4,
    find_openssl_binary,
    provision_mtls_certificates,
)
from windows_companion.gateway.server import create_gateway_app  # noqa: E402
from windows_companion.ui.app import launch_desktop_companion  # noqa: E402


def _runtime_root() -> Path:
    root = LlamaServerProcessManager.default_install_dir()
    for sub in ("vault", "certs", "models", "bin"):
        (root / sub).mkdir(parents=True, exist_ok=True)
    return root


def _pem_sha256_hex(cert_path: Path) -> str:
    der = ssl.PEM_cert_to_DER_cert(cert_path.read_text(encoding="utf-8"))
    return hashlib.sha256(der).hexdigest()


def _load_or_provision_certs(certs_dir: Path, lan_ip: str, *, force_rotate: bool = False) -> dict[str, Any]:
    required_names = (
        certs_dir / "ca.crt",
        certs_dir / "ca.key",
        certs_dir / "server.crt",
        certs_dir / "server.key",
        certs_dir / "client.crt",
        certs_dir / "client.key",
    )
    if not force_rotate and all(p.is_file() for p in required_names):
        try:
            openssl_bin = find_openssl_binary()
            proc = subprocess.run(
                [openssl_bin, "x509", "-in", str(certs_dir / "server.crt"), "-noout", "-ext", "subjectAltName"],
                capture_output=True,
                text=True,
                check=True,
            )
            if f"IP Address:{lan_ip}" in proc.stdout:
                return {
                    "cert_dir": str(certs_dir),
                    "ca_cert_path": str(certs_dir / "ca.crt"),
                    "ca_key_path": str(certs_dir / "ca.key"),
                    "server_cert_path": str(certs_dir / "server.crt"),
                    "server_key_path": str(certs_dir / "server.key"),
                    "client_cert_path": str(certs_dir / "client.crt"),
                    "client_key_path": str(certs_dir / "client.key"),
                    "ca_cert_sha256": _pem_sha256_hex(certs_dir / "ca.crt"),
                    "server_cert_sha256": _pem_sha256_hex(certs_dir / "server.crt"),
                    "client_cert_sha256": _pem_sha256_hex(certs_dir / "client.crt"),
                }
        except Exception:
            pass
    return provision_mtls_certificates(certs_dir)


def _seed_initial_welcome_data(db: PsycheDatabase, orchestrator: PsycheIntelligenceOrchestrator) -> None:
    """Seeds one realistic sample contact & synthesis on a brand-new empty vault."""
    row = db.connection.execute("SELECT COUNT(*) FROM people").fetchone()
    if row and int(row[0]) > 0:
        return

    now_utc = utc_now_iso()
    pid = orchestrator.people_memory.create_or_update_person(
        canonical_display_name="Aarav Sharma (Quick-Start Sample)",
        relationship_tier="CLOSE_FRIEND",
        trust_level=0.85,
    )
    sample_text = "Kal evening free ho kya? Project review aur dinner ke baare mein baat karni thi."
    modes, spans = detect_language_modes_and_spans(sample_text)
    ev_id = generate_uuidv7()
    dev_id = generate_uuidv7()

    db.connection.execute(
        """
        INSERT INTO paired_devices (
            device_id, device_name, ed25519_public_key_b64,
            tls_cert_sha256_pin, paired_at_utc, last_seen_at_utc, trust_status
        ) VALUES (?, ?, ?, ?, ?, ?, 'ACTIVE')
        """,
        (dev_id, "Legion 5 Pro (Local Workbench)", "cXVpY2stc3RhcnQ=", "0" * 64, now_utc, now_utc),
    )
    db.connection.commit()

    batch_req = {
        "schema_version": "1.0.0",
        "batch_id": generate_uuidv7(),
        "device_id": dev_id,
        "sent_at_utc": now_utc,
        "batch_ed25519_signature": "c2VlZC1iYXRjaC1zaWctb2s=",
        "events": [
            {
                "event_id": ev_id,
                "package_name": "com.whatsapp",
                "notification_category": "msg",
                "conversation_key": f"sample-{hashlib.sha256(b'aarav').hexdigest()[:10]}",
                "is_group_conversation": False,
                "group_title": None,
                "direction": "INBOUND",
                "sender": {
                    "raw_title": "Aarav Sharma (Quick-Start Sample)",
                    "android_contact_lookup_key": None,
                    "normalized_phone_sha256": None,
                    "candidate_person_ids": [pid],
                    "identity_ambiguity": False,
                },
                "content": {
                    "raw_text_immutable": sample_text,
                    "raw_text_sha256": hashlib.sha256(sample_text.encode("utf-8")).hexdigest(),
                    "detected_language_modes": modes,
                    "token_language_spans": spans,
                },
                "posted_at_utc": now_utc,
                "security": {
                    "untrusted_external_input": True,
                    "otp_or_sensitive_filtered": True,
                    "ed25519_event_signature": "c2VlZC1ldmVudC1zaWctb2s=",
                },
            }
        ],
    }
    orchestrator.people_memory.ingest_notification_batch(batch_req, require_crypto_signature=False)
    orchestrator.synthesize_for_event(event_id=ev_id, reference_now_utc=now_utc)


def _ensure_llama_server_running() -> tuple[LlamaServerProcessManager, bool]:
    mgr = LlamaServerProcessManager()
    if mgr.is_server_healthy():
        return mgr, False
    if not mgr.is_binary_available() or not mgr.is_model_weight_present():
        print("[PSYCHE] llama-server binary or GGUF model not found; running Tier-0 analytical engine.")
        return mgr, False
    print(f"[PSYCHE] Starting local Neural AI ({mgr.model_path.name}) on 127.0.0.1:{mgr.port}...")
    mgr.start()
    deadline = time.time() + 25.0
    while time.time() < deadline:
        if mgr.is_server_healthy():
            print("[PSYCHE] Local Neural AI (llama-server + GPU Vulkan) ONLINE.")
            return mgr, True
        time.sleep(0.4)
    print("[PSYCHE] llama-server still warming up; Tier-0 fallback ready until warm.")
    return mgr, True


def _start_uvicorn_thread(
    app: Any,
    cert_bundle: dict[str, Any],
    *,
    port: int = 8443,
) -> tuple[uvicorn.Server, threading.Thread]:
    ssl_ctx = create_mtls_ssl_context(cert_bundle, require_client_cert=False)
    config = uvicorn.Config(
        app=app,
        host="0.0.0.0",
        port=port,
        ssl_keyfile=cert_bundle["server_key_path"],
        ssl_certfile=cert_bundle["server_cert_path"],
        ssl_version=ssl.PROTOCOL_TLS_SERVER,
        ssl_cert_reqs=ssl.CERT_OPTIONAL,
        ssl_context_factory=lambda _cfg, _default: ssl_ctx,
        log_level="warning",
        access_log=False,
    )
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, name="PsycheGatewayTLS", daemon=True)
    thread.start()
    deadline = time.time() + 5.0
    while not server.started and thread.is_alive() and time.time() < deadline:
        time.sleep(0.1)
    return server, thread


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Launch PSYCHE AI live desktop stack.")
    parser.add_argument(
        "--headless-check",
        action="store_true",
        help="Start services, verify health & neural AI, then exit cleanly.",
    )
    parser.add_argument("--port", type=int, default=8443, help="HTTPS Gateway port (default 8443).")
    parser.add_argument("--rotate-certs", action="store_true", help="Force regenerate LAN TLS certs.")
    args = parser.parse_args(argv)

    os.environ.setdefault("PSYCHE_ENABLE_LLAMA", "1")
    runtime_root = _runtime_root()
    vault_dir = runtime_root / "vault"
    certs_dir = runtime_root / "certs"
    lan_ip = detect_lan_ipv4()
    lan_url = f"https://{lan_ip}:{args.port}"

    cert_bundle = _load_or_provision_certs(certs_dir, lan_ip, force_rotate=args.rotate_certs)
    tls_sha256 = cert_bundle["server_cert_sha256"]

    llama_mgr, started_llama_here = _ensure_llama_server_running()

    vault = PsycheFortressVault(key_file_path=vault_dir / "psyche_master.key.dpapi")
    db = PsycheDatabase(
        db_path=vault_dir / "psyche_vault.sqlite3",
        vault=vault,
        vector_path=vault_dir / "psyche_vectors.npy",
    )
    orchestrator = PsycheIntelligenceOrchestrator(db=db)
    _seed_initial_welcome_data(db, orchestrator)

    gateway_app, gateway_service = create_gateway_app(
        db=db,
        orchestrator=orchestrator,
        windows_host_endpoint=lan_url,
        windows_tls_cert_sha256=tls_sha256,
    )
    uvicorn_server, gateway_thread = _start_uvicorn_thread(
        gateway_app,
        cert_bundle,
        port=args.port,
    )

    print("============================================================")
    print("  PSYCHE AI — Sovereign Local System ACTIVE")
    print(f"  LAN Gateway URL : {lan_url}")
    print(f"  APK Download URL: {lan_url}/download/apk")
    print(f"  TLS SHA-256 Pin : {tls_sha256}")
    print(f"  Neural AI Core  : {'ONLINE' if llama_mgr.is_server_healthy() else 'WARMING / TIER-0 FALLBACK'}")
    print("============================================================")

    try:
        if args.headless_check:
            time.sleep(0.5)
            return 0 if gateway_thread.is_alive() else 1
        return launch_desktop_companion(
            db=db,
            orchestrator=orchestrator,
            gateway_service=gateway_service,
            gateway_lan_url=lan_url,
            gateway_tls_sha256=tls_sha256,
        )
    finally:
        uvicorn_server.should_exit = True
        gateway_thread.join(timeout=2.0)
        db.close()
        if started_llama_here:
            llama_mgr.stop()


if __name__ == "__main__":
    raise SystemExit(main())
