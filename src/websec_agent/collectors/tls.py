from __future__ import annotations

import hashlib
import socket
import ssl
from dataclasses import dataclass

from ..core.errors import ToolError
from ..core.schemas import EvidenceKind
from .base import Collected


@dataclass
class TLSProbeResult:
    der: bytes
    version: str
    cipher: str
    subject: str = ""


def default_tls_probe(host: str, port: int, timeout: float = 10.0) -> TLSProbeResult:
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw_socket:
            with context.wrap_socket(raw_socket, server_hostname=host) as tls_socket:
                der = tls_socket.getpeercert(binary_form=True) or b""
                return TLSProbeResult(
                    der=der,
                    version=tls_socket.version() or "unknown",
                    cipher=(tls_socket.cipher() or ("unknown", "", 0))[0],
                )
    except (OSError, ssl.SSLError) as exc:
        raise ToolError(f"tls probe failed for {host}:{port}: {exc}") from exc


class TLSCollector:
    def __init__(self, probe=default_tls_probe) -> None:
        self._probe = probe

    def collect(self, host: str, port: int = 443) -> Collected:
        result = self._probe(host, port)
        fingerprint = hashlib.sha256(result.der).hexdigest()
        subject = f", subject={result.subject}" if result.subject else ""
        summary = (
            f"TLS {host}:{port} {result.version} cipher={result.cipher} "
            f"cert_sha256={fingerprint} der_bytes={len(result.der)}{subject}"
        )
        return Collected(
            kind=EvidenceKind.TLS_CERT,
            source_url=f"https://{host}:{port}",
            method="TLS",
            summary=summary,
            raw=result.der,
        )
