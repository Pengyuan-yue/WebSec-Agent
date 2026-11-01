from __future__ import annotations

import pytest

from websec_agent.config import ScopePolicy
from websec_agent.core.errors import ScopeViolation
from websec_agent.scope.guard import ScopeGuard


def test_target_and_wildcard_are_authorized():
    policy = ScopePolicy(allowed_hosts=["*.example.com"])
    guard = ScopeGuard(policy, "https://app.example.com")

    assert guard.check_host("app.example.com") == "app.example.com"
    assert guard.check_host("api.example.com") == "api.example.com"
    with pytest.raises(ScopeViolation):
        guard.check_host("example.com")  # wildcard does not include the apex
    with pytest.raises(ScopeViolation):
        guard.check_host("evil.com")


def test_denied_host_wins_over_allowlist():
    policy = ScopePolicy(allowed_hosts=["*.example.com"], denied_hosts=["admin.example.com"])
    guard = ScopeGuard(policy, "https://app.example.com")
    with pytest.raises(ScopeViolation, match="explicitly denied"):
        guard.check_host("admin.example.com")


def test_private_address_blocked_unless_enabled():
    policy = ScopePolicy(allowed_hosts=["127.0.0.1"])
    with pytest.raises(ScopeViolation, match="private/loopback"):
        ScopeGuard(policy, "http://127.0.0.1").check_host("127.0.0.1")

    policy.allow_private = True
    ScopeGuard(policy, "http://127.0.0.1").check_host("127.0.0.1")


def test_port_allowlist():
    policy = ScopePolicy(allowed_hosts=["example.com"], allowed_ports=[443])
    guard = ScopeGuard(policy, "https://example.com")
    guard.check_url("https://example.com/path")
    with pytest.raises(ScopeViolation, match="not in allowed_ports"):
        guard.check_url("http://example.com:8080/")


def test_expansion_requires_explicit_call():
    policy = ScopePolicy(allowed_hosts=[])
    guard = ScopeGuard(policy, "https://example.com")
    with pytest.raises(ScopeViolation):
        guard.check_host("staging.example.com")
    guard.expand(["staging.example.com"])
    guard.check_host("staging.example.com")


def test_unsupported_scheme_is_rejected():
    guard = ScopeGuard(ScopePolicy(allowed_hosts=["example.com"]), "https://example.com")
    with pytest.raises(ScopeViolation, match="unsupported scheme"):
        guard.check_url("ftp://example.com/file")
