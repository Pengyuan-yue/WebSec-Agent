from __future__ import annotations

import json
import threading
from collections import Counter

import httpx

from websec_agent.agents.orchestrator import Orchestrator
from websec_agent.collectors.tls import TLSProbeResult
from websec_agent.config import RoleModelConfig, ScopePolicy
from websec_agent.core.schemas import Role, RunBudget, TaskKind, TaskStatus
from websec_agent.llm.gateway import LLMGateway
from websec_agent.llm.providers.fake import FakeGateway
from websec_agent.scope.guard import ScopeGuard
from websec_agent.store.db import Database
from websec_agent.store.repos import Repositories
from websec_agent.tools.executor import ToolExecutor

TARGET = "https://example.com"


def _http_handler(request: httpx.Request) -> httpx.Response:
    if request.url.path == "/robots.txt":
        return httpx.Response(404, content=b"not found")
    return httpx.Response(200, content=b"<html>home</html>")


class StaticRegistry:
    def __init__(self, gateways: dict[Role, LLMGateway]) -> None:
        self._gateways = gateways
        self._settings = RoleModelConfig(
            provider="fake", model="fake-model", max_output_tokens=2048
        )

    def resolve(self, role: Role):
        return self._settings, self._gateways[role]


def test_four_pentesters_run_in_parallel(tmp_path):
    """The four fixed Pentester lanes must overlap, without planner/reviewer/reporter calls."""
    barrier = threading.Barrier(4, timeout=15)
    count_lock = threading.Lock()
    overlaps = {"pentester": 0}

    def pentester(_request) -> str:
        barrier.wait(timeout=15)
        with count_lock:
            overlaps["pentester"] += 1
        return json.dumps(
            {"summary": "Nothing severe found.", "findings": [], "tool_requests": []}
        )

    registry = StaticRegistry({Role.PENTESTER: FakeGateway(pentester)})

    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    db = Database(f"sqlite+pysqlite:///{tmp_path / 'run.db'}")
    guard = ScopeGuard(ScopePolicy(allowed_hosts=["example.com"]), TARGET)
    repos = Repositories.build(db)
    db.create_all()
    executor = ToolExecutor(
        guard,
        repos.evidence,
        artifacts,
        http_client=httpx.Client(transport=httpx.MockTransport(_http_handler)),
        tls_probe=lambda host, port: TLSProbeResult(der=b"DER", version="TLSv1.3", cipher="C"),
        dns_lookup=lambda host, port=443: ["93.184.216.34"],
    )
    orchestrator = Orchestrator(
        db=db,
        target=TARGET,
        executor=executor,
        registry=registry,
        run_budget=RunBudget(max_tasks=40, max_replans=2, max_parallel=2),
        artifacts_root=artifacts,
    )
    run = orchestrator.run()
    executor.close()

    assert overlaps["pentester"] == 4
    assert run.budget["max_parallel"] == 4

    tasks = repos.tasks.list_by_run(run.id)
    failures = [(t.kind.value, t.error) for t in tasks if t.status != TaskStatus.DONE]
    assert not failures, failures

    pentester_tasks = [
        task for task in tasks
        if task.kind == TaskKind.ANALYZE and task.inputs.get("pentester_slot")
    ]
    assert len(pentester_tasks) == 4
    assert {task.inputs["pentester_label"] for task in pentester_tasks} == {
        "Pentester 1", "Pentester 2", "Pentester 3", "Pentester 4"
    }

    events = repos.events.list_by_run(run.id)
    parallel_events = [event for event in events if event.type == "dispatch_parallel"]
    assert any(set(event.payload.get("kinds", [])) == {"analyze"} for event in parallel_events)

    kinds = Counter(task.kind.value for task in tasks)
    assert kinds["analyze"] == 4
    assert kinds["report"] == 1
    assert kinds["plan"] == 0
    assert kinds["review"] == 0
