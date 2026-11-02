from __future__ import annotations

import ipaddress
from urllib.parse import urlparse

from ..config import ScopePolicy
from ..core.errors import ScopeViolation


def _normalize_host(host: str) -> str:
    return host.strip().lower().rstrip(".")


def _is_private_or_local(host: str) -> bool:
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return host in {"localhost", "localhost.localdomain"} or host.endswith(".localhost")
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
    )


def _host_matches(pattern: str, host: str) -> bool:
    pattern = _normalize_host(pattern)
    if pattern == host:
        return True
    if pattern.startswith("*."):
        return host.endswith(pattern[1:]) and host != pattern[2:]
    return False


class ScopeGuard:
    """Enforces the authorized target set at the tool-execution boundary.

    The run target host is always authorized. Additional hosts come only from the
    policy file or an explicit user-approved --allow-host expansion. Nothing here
    depends on agent prompts.
    """

    def __init__(self, policy: ScopePolicy, target: str) -> None:
        parsed = urlparse(target)
        if not parsed.hostname:
            raise ScopeViolation(target, "target URL must include a host")
        self._policy = policy
        self._target = target
        self._target_host = _normalize_host(parsed.hostname)
        self._target_port = parsed.port or (443 if parsed.scheme == "https" else 80)

    @property
    def target(self) -> str:
        return self._target

    @property
    def target_host(self) -> str:
        return self._target_host

    @property
    def policy(self) -> ScopePolicy:
        return self._policy

    def snapshot(self) -> dict:
        return self._policy.snapshot(self._target)

    def expand(self, hosts: list[str]) -> None:
        """Explicit, user-approved scope expansion (CLI --allow-host)."""
        for host in hosts:
            normalized = _normalize_host(host)
            if normalized and normalized not in self._policy.allowed_hosts:
                self._policy.allowed_hosts.append(normalized)

    def check_host(self, host: str, port: int | None = None) -> str:
        host = _normalize_host(host)
        if not host:
            raise ScopeViolation(host, "empty host")

        if self._policy.unrestricted:
            # Operator-level policy: no host allowlist, no port list, no
            # private-address blocking. Anything the project points at - and
            # anything a redirect lands on - is reachable.
            return host

        if any(_host_matches(pattern, host) for pattern in self._policy.denied_hosts):
            raise ScopeViolation(host, "host is explicitly denied")

        authorized = host == self._target_host or any(
            _host_matches(pattern, host) for pattern in self._policy.allowed_hosts
        )
        if not authorized:
            raise ScopeViolation(
                host,
                "host is not in scope; add it to scope_policy.yaml or pass --allow-host "
                "after obtaining authorization",
            )

        if not self._policy.allow_private and _is_private_or_local(host):
            raise ScopeViolation(
                host, "private/loopback address blocked (set allow_private: true for local tests)"
            )

        if port is not None and self._policy.allowed_ports:
            if port not in self._policy.allowed_ports:
                raise ScopeViolation(host, f"port {port} is not in allowed_ports")
        return host

    def check_url(self, url: str) -> tuple[str, int, str]:
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"}:
            raise ScopeViolation(url, f"unsupported scheme: {parsed.scheme!r}")
        if not parsed.hostname:
            raise ScopeViolation(url, "URL missing host")
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        host = self.check_host(parsed.hostname, port)
        return host, port, parsed.scheme
