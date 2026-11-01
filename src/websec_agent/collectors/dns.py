from __future__ import annotations

import json
import socket

from ..core.errors import ToolError
from ..core.schemas import EvidenceKind
from .base import Collected


def default_dns_lookup(host: str, port: int = 443) -> list[str]:
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ToolError(f"dns lookup failed for {host}: {exc}") from exc
    addresses = {info[4][0] for info in infos}
    return sorted(addresses)


class DNSCollector:
    def __init__(self, resolver=default_dns_lookup) -> None:
        self._resolver = resolver

    def collect(self, host: str) -> Collected:
        addresses = self._resolver(host)
        raw = json.dumps({"host": host, "addresses": addresses}, indent=2).encode("utf-8")
        summary = f"DNS {host} -> {', '.join(addresses) if addresses else 'no records'}"
        return Collected(
            kind=EvidenceKind.DNS,
            source_url=f"dns://{host}",
            method="DNS",
            summary=summary,
            raw=raw,
        )
