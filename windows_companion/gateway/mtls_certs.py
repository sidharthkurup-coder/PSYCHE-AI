"""PSYCHE FORTRESS — Automated X.509 mTLS 1.3 Certificate Provisioning & SSLContext Builder."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import shutil
import ssl
import subprocess
from typing import Any


def find_openssl_binary() -> str:
    """Finds OpenSSL CLI binary installed on Windows (MSYS2 / Git / PATH)."""
    candidates = [
        Path(r"C:\msys64\ucrt64\bin\openssl.exe"),
        Path(r"C:\Program Files\Git\mingw64\bin\openssl.exe"),
    ]
    for cand in candidates:
        if cand.exists():
            return str(cand)
    found = shutil.which("openssl")
    if found:
        return found
    raise FileNotFoundError("OpenSSL CLI binary not found on system")


def _run_openssl(args: list[str], cwd: Path) -> bytes:
    exe = find_openssl_binary()
    proc = subprocess.run(
        [exe, *args],
        cwd=str(cwd),
        capture_output=True,
        check=False,
    )
    if proc.returncode != 0:
        err = proc.stderr.decode("utf-8", errors="replace").strip()
        raise RuntimeError(f"OpenSSL failed ({' '.join(args)}): {err}")
    return proc.stdout


def _cert_der_sha256(cert_pem_path: Path, cwd: Path) -> str:
    der = _run_openssl(
        ["x509", "-in", str(cert_pem_path), "-outform", "DER"],
        cwd=cwd,
    )
    return hashlib.sha256(der).hexdigest()


def provision_mtls_certificates(
    cert_dir: Path | str,
    *,
    common_name: str = "psyche-windows-gateway.local",
    validity_days: int = 365,
) -> dict[str, Any]:
    """Provisions a local Root CA plus CA-signed TLS 1.3 server and Android client certificates."""
    out_dir = Path(cert_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    ca_cnf = out_dir / "ca.cnf"
    srv_cnf = out_dir / "server.cnf"
    cli_cnf = out_dir / "client.cnf"

    ca_key = out_dir / "ca.key"
    ca_crt = out_dir / "ca.crt"
    server_key = out_dir / "server.key"
    server_csr = out_dir / "server.csr"
    server_crt = out_dir / "server.crt"
    client_key = out_dir / "client.key"
    client_csr = out_dir / "client.csr"
    client_crt = out_dir / "client.crt"

    ca_cnf.write_text(
        "\n".join(
            [
                "[req]",
                "prompt = no",
                "distinguished_name = dn",
                "x509_extensions = v3_ca",
                "",
                "[dn]",
                "O = PSYCHE AI Local Fortress",
                "CN = PSYCHE Local Root CA",
                "",
                "[v3_ca]",
                "subjectKeyIdentifier = hash",
                "authorityKeyIdentifier = keyid:always,issuer",
                "basicConstraints = critical, CA:true, pathlen:0",
                "keyUsage = critical, digitalSignature, cRLSign, keyCertSign",
            ]
        ),
        encoding="utf-8",
    )

    srv_cnf.write_text(
        "\n".join(
            [
                "[req]",
                "prompt = no",
                "distinguished_name = dn",
                "req_extensions = v3_server",
                "",
                "[dn]",
                "O = PSYCHE AI Windows Gateway",
                f"CN = {common_name}",
                "",
                "[v3_server]",
                "basicConstraints = CA:FALSE",
                "keyUsage = critical, digitalSignature, keyEncipherment",
                "extendedKeyUsage = serverAuth",
                "subjectAltName = @alt_names",
                "",
                "[alt_names]",
                f"DNS.1 = {common_name}",
                "DNS.2 = localhost",
                "IP.1 = 127.0.0.1",
            ]
        ),
        encoding="utf-8",
    )

    cli_cnf.write_text(
        "\n".join(
            [
                "[req]",
                "prompt = no",
                "distinguished_name = dn",
                "req_extensions = v3_client",
                "",
                "[dn]",
                "O = PSYCHE AI Android Companion",
                "CN = psyche-android-companion",
                "",
                "[v3_client]",
                "basicConstraints = CA:FALSE",
                "keyUsage = critical, digitalSignature",
                "extendedKeyUsage = clientAuth",
            ]
        ),
        encoding="utf-8",
    )

    days = str(validity_days)
    # 1. Root CA (ECDSA P-256)
    _run_openssl(["ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", str(ca_key)], out_dir)
    _run_openssl(
        [
            "req", "-new", "-x509", "-sha256", "-days", days,
            "-key", str(ca_key), "-config", str(ca_cnf), "-out", str(ca_crt),
        ],
        out_dir,
    )

    # 2. Windows Gateway Server Certificate
    _run_openssl(["ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", str(server_key)], out_dir)
    _run_openssl(
        ["req", "-new", "-key", str(server_key), "-config", str(srv_cnf), "-out", str(server_csr)],
        out_dir,
    )
    _run_openssl(
        [
            "x509", "-req", "-sha256", "-days", days,
            "-in", str(server_csr), "-CA", str(ca_crt), "-CAkey", str(ca_key),
            "-CAcreateserial", "-extensions", "v3_server", "-extfile", str(srv_cnf),
            "-out", str(server_crt),
        ],
        out_dir,
    )

    # 3. Android Companion Client Certificate
    _run_openssl(["ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", str(client_key)], out_dir)
    _run_openssl(
        ["req", "-new", "-key", str(client_key), "-config", str(cli_cnf), "-out", str(client_csr)],
        out_dir,
    )
    _run_openssl(
        [
            "x509", "-req", "-sha256", "-days", days,
            "-in", str(client_csr), "-CA", str(ca_crt), "-CAkey", str(ca_key),
            "-CAcreateserial", "-extensions", "v3_client", "-extfile", str(cli_cnf),
            "-out", str(client_crt),
        ],
        out_dir,
    )

    # Remove CSR / temporary config artifacts after signing
    for tmp in (server_csr, client_csr, ca_cnf, srv_cnf, cli_cnf):
        if tmp.exists():
            os.remove(tmp)

    return {
        "cert_dir": str(out_dir),
        "ca_cert_path": str(ca_crt),
        "ca_key_path": str(ca_key),
        "server_cert_path": str(server_crt),
        "server_key_path": str(server_key),
        "client_cert_path": str(client_crt),
        "client_key_path": str(client_key),
        "ca_cert_sha256": _cert_der_sha256(ca_crt, out_dir),
        "server_cert_sha256": _cert_der_sha256(server_crt, out_dir),
        "client_cert_sha256": _cert_der_sha256(client_crt, out_dir),
    }


def create_mtls_ssl_context(
    cert_bundle: dict[str, Any],
    *,
    require_client_cert: bool = True,
) -> ssl.SSLContext:
    """Creates a strict TLS 1.3 SSLContext enforcing mutual client X.509 authentication."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(
        certfile=cert_bundle["server_cert_path"],
        keyfile=cert_bundle["server_key_path"],
    )
    ctx.load_verify_locations(cafile=cert_bundle["ca_cert_path"])
    ctx.verify_mode = ssl.CERT_REQUIRED if require_client_cert else ssl.CERT_OPTIONAL
    return ctx
