from __future__ import annotations

import json

import httpx

from websec_agent.collectors.base import Collected
from websec_agent.config import ScopePolicy
from websec_agent.core.schemas import EvidenceKind, Run, ToolName, ToolRequest
from websec_agent.scope.guard import ScopeGuard
from websec_agent.store.db import Database
from websec_agent.store.repos import Repositories
from websec_agent.tools.executor import ToolExecutor


def _build(tmp_path, handler):
    db = Database(f"sqlite+pysqlite:///{tmp_path / 'tools.db'}")
    db.create_all()
    repos = Repositories.build(db)
    run = Run(target="http://demo.testfire.net/")
    repos.runs.create(run)
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    executor = ToolExecutor(
        ScopeGuard(ScopePolicy(allowed_hosts=["demo.testfire.net"]), "http://demo.testfire.net/"),
        repos.evidence,
        artifacts,
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    return repos, run, artifacts, executor


def test_http_collector_persists_set_cookie_and_replay_via_cookies_from(tmp_path):
    seen: dict[str, httpx.Request] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen[request.url.path] = request
        if request.url.path == "/doLogin":
            return httpx.Response(
                302,
                headers={"Location": "/bank/main.jsp", "Set-Cookie": "JSESSIONID=abc123; Path=/"},
            )
        assert "JSESSIONID=abc123" in request.headers.get("cookie", ""), "cookie must be replayed"
        return httpx.Response(200, text="account overview")

    repos, run, artifacts, executor = _build(tmp_path, handler)
    login = executor.execute(
        ToolRequest(
            tool=ToolName.HTTP_REQUEST,
            params={
                "url": "http://demo.testfire.net/doLogin",
                "method": "POST",
                "body": "uid=x&passw=y",
            },
        ),
        run.id,
        "task-1",
    )
    assert login.kind == EvidenceKind.HTTP_RESPONSE

    protected = executor.execute(
        ToolRequest(
            tool=ToolName.HTTP_REQUEST,
            params={
                "url": "http://demo.testfire.net/bank/main.jsp",
                "method": "GET",
                "cookies_from": login.id,
            },
        ),
        run.id,
        "task-2",
    )
    assert protected.summary.startswith("GET http://demo.testfire.net/bank/main.jsp -> 200")
    executor.close()


def test_evidence_diff_provides_differential_evidence(tmp_path):
    def handler(request: httpx.Request) -> httpx.Response:
        if b"payload" in request.url.query:
            return httpx.Response(200, text="uid=1001\nroot:x:0:0:root:/root:/bin/bash")
        return httpx.Response(200, text="uid=1001")

    repos, run, artifacts, executor = _build(tmp_path, handler)
    baseline = executor.execute(
        ToolRequest(
            tool=ToolName.HTTP_REQUEST,
            params={"url": "http://demo.testfire.net/status?query=ok"},
        ),
        run.id,
        "task-1",
    )
    payload = executor.execute(
        ToolRequest(
            tool=ToolName.HTTP_REQUEST,
            params={"url": "http://demo.testfire.net/status?query=payload"},
        ),
        run.id,
        "task-2",
    )

    diff = executor.execute(
        ToolRequest(
            tool=ToolName.EVIDENCE_DIFF,
            params={"evidence_a": baseline.id, "evidence_b": payload.id},
        ),
        run.id,
        "task-3",
    )
    assert diff.kind == EvidenceKind.EVIDENCE_DIFF
    assert sorted(diff.derived_from) == sorted([baseline.id, payload.id])
    assert "root:x:0:0:root" in diff.summary or "+1" in diff.summary
    stored = json.loads((artifacts / diff.raw_path).read_text())
    assert stored["identical"] is False
    assert "root:x:0:0:root:/root:/bin/bash" in stored["unified_diff"]
    executor.close()


def test_http_request_accepts_json_object_body(tmp_path):
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["content-type"] == "application/json"
        assert json.loads(request.read()) == {"username": "admin", "password": "admin"}
        return httpx.Response(200, text='{"token": "t"}')

    repos, run, artifacts, executor = _build(tmp_path, handler)
    evidence = executor.execute(
        ToolRequest(
            tool=ToolName.HTTP_REQUEST,
            params={
                "url": "http://demo.testfire.net/api/login",
                "method": "POST",
                "body": {"username": "admin", "password": "admin"},
            },
        ),
        run.id,
        "task-1",
    )
    stored = json.loads((artifacts / evidence.raw_path).read_text())
    assert stored["request"]["body"] == '{"username": "admin", "password": "admin"}'
    assert stored["request"]["headers"]["Content-Type"] == "application/json"
    assert "token" in stored["response"]["body"]
    executor.close()
