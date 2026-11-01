from __future__ import annotations

import httpx
import pytest

from websec_agent.collectors.tls import TLSProbeResult
from websec_agent.config import ScopePolicy
from websec_agent.core.errors import ScopeViolation
from websec_agent.core.schemas import Role, Run, ToolName, ToolRequest
from websec_agent.scope.guard import ScopeGuard
from websec_agent.store.db import Database
from websec_agent.store.repos import Repositories
from websec_agent.tools.executor import ToolExecutor


def test_tool_executor_blocks_out_of_scope_request_before_network(tmp_path):
    db = Database(f"sqlite+pysqlite:///{tmp_path / 'scope.db'}")
    db.create_all()
    repos = Repositories.build(db)
    run = Run(target="https://example.com")
    repos.runs.create(run)

    called = {"network": False}

    def handler(request: httpx.Request) -> httpx.Response:
        called["network"] = True
        raise AssertionError("out-of-scope network call must not happen")

    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    executor = ToolExecutor(
        ScopeGuard(ScopePolicy(allowed_hosts=["example.com"]), "https://example.com"),
        repos.evidence,
        artifacts,
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
        tls_probe=lambda host, port: TLSProbeResult(b"", "TLSv1.2", "cipher"),
    )

    request = ToolRequest(
        tool=ToolName.HTTP_REQUEST,
        params={"url": "https://evil.example.org/steal", "method": "GET"},
    )
    with pytest.raises(ScopeViolation, match="not in scope"):
        executor.execute(request, run.id, "task-1")

    assert called["network"] is False
    assert repos.evidence.count_by_run(run.id) == 0
