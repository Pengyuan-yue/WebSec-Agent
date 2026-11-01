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


def test_parallel_dispatch_overlaps_llm_calls(tmp_path):
    """Two independent analysis tasks must run their LLM turns concurrently."""
    barrier = threading.Barrier(2, timeout=15)
    overlaps = {"analyze": 0}

    def planner(_request) -> str:
        return json.dumps(
            {
                "rationale": "Two independent probes.",
                "tasks": [
                    {
                        "key": "probe-a",
                        "kind": "analyze",
                        "role": "pentester",
                        "objective": "Analyze area A.",
                        "inputs": {},
                        "depends_on": [],
                        "priority": 50,
                    },
                    {
                        "key": "probe-b",
                        "kind": "analyze",
                        "role": "pentester",
                        "objective": "Analyze area B.",
                        "inputs": {},
                        "depends_on": [],
                        "priority": 50,
                    },
                ],
            }
        )

    def pentester(_request) -> str:
        # Only the two plan-created analysis tasks should meet at the barrier;
        # the fallback/cycle-2 tasks (if any) would break the barrier count.
        try:
            barrier.wait(timeout=15)
            overlaps["analyze"] += 1
        except threading.BrokenBarrierError:
            pass
        return json.dumps(
            {"summary": "Nothing severe found.", "findings": [], "tool_requests": []}
        )

    def reporter(_request) -> str:
        return json.dumps({"summary_markdown": "Parallel fixture."})

    registry = StaticRegistry(
        {
            Role.PLANNER: FakeGateway(planner),
            Role.PENTESTER: FakeGateway(pentester),
            Role.REPORTER: FakeGateway(reporter),
        }
    )

    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    db = Database(f"sqlite+pysqlite:///{tmp_path / 'run.db'}")
    policy = ScopePolicy(allowed_hosts=["example.com"])
    guard = ScopeGuard(policy, TARGET)
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

    # The barrier was met: both analysis LLM turns were in flight simultaneously.
    assert overlaps["analyze"] == 2, "independent analysis tasks did not overlap"

    tasks = repos.tasks.list_by_run(run.id)
    failures = [(t.kind.value, t.error) for t in tasks if t.status != TaskStatus.DONE]
    assert not failures, failures

    events = repos.events.list_by_run(run.id)
    parallel_events = [e for e in events if e.type == "dispatch_parallel"]
    assert parallel_events, "no parallel dispatch happened"
    analysis_parallel = [
        e
        for e in parallel_events
        if set(e.payload.get("kinds", [])) == {"analyze"}
    ]
    assert analysis_parallel, "the two analysis tasks were not batched together"

    kinds = Counter(t.kind.value for t in tasks)
    assert kinds["analyze"] == 2
    assert kinds["report"] == 1
