from __future__ import annotations

import json
import threading

import httpx

from websec_agent.agents.orchestrator import Orchestrator
from websec_agent.collectors.tls import TLSProbeResult
from websec_agent.config import RoleModelConfig, ScopePolicy
from websec_agent.core.schemas import FindingStatus, Role, RunBudget
from websec_agent.llm.gateway import LLMGateway
from websec_agent.llm.providers.fake import FakeGateway, json_messages
from websec_agent.scope.guard import ScopeGuard
from websec_agent.store.db import Database
from websec_agent.store.repos import Repositories
from websec_agent.tools.executor import ToolExecutor

TARGET = "https://example.com"

FINDING = {
    "title": "Sensitive debug metadata exposed",
    "category": "configuration_exposure",
    "severity": "high",
    "confidence": 90,
    "description": "The baseline response exposes a debug-only environment header.",
    "impact": "The header discloses internal deployment metadata.",
    "reproduction": "Fetch the baseline page and inspect the response headers.",
    "remediation": "Remove debug-only headers from production responses.",
}


def _http_handler(request: httpx.Request) -> httpx.Response:
    if request.url.path == "/robots.txt":
        return httpx.Response(404, content=b"not found")
    return httpx.Response(
        200,
        content=b"<html>home</html>",
        headers={"X-Debug-Environment": "staging"},
    )


class StaticRegistry:
    def __init__(self, gateways: dict[Role, LLMGateway]) -> None:
        self._gateways = gateways
        self._settings = RoleModelConfig(
            provider="fake", model="fake-model", max_output_tokens=2048
        )

    def resolve(self, role: Role):
        return self._settings, self._gateways[role]


def _registry(pentester_capture=None):
    state = {"first_call": True}
    lock = threading.Lock()

    def pentester(request) -> str:
        context = json_messages(request)["context"]
        if pentester_capture is not None:
            with lock:
                pentester_capture.append(context)
        with lock:
            should_propose = state["first_call"]
            state["first_call"] = False
        if not should_propose:
            return json.dumps(
                {"summary": "No additional high-severity issue identified.", "findings": [], "tool_requests": []}
            )

        baseline = next(
            item for item in context["evidence"]
            if item["kind"] == "http_response" and item["source_url"] == TARGET
        )
        return json.dumps(
            {
                "summary": "A debug-only environment header is present in the baseline response.",
                "findings": [
                    {**FINDING, "evidence_ids": [baseline["id"]]}
                ],
                "tool_requests": [],
            }
        )

    return StaticRegistry({Role.PENTESTER: FakeGateway(pentester)})


def _run_once(tmp_path, registry, db_name) -> tuple[Repositories, object]:
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir(exist_ok=True)
    db = Database(f"sqlite+pysqlite:///{tmp_path / db_name}")
    guard = ScopeGuard(ScopePolicy(allowed_hosts=["example.com"]), TARGET)
    repos = Repositories.build(db)
    db.create_all()
    executor = ToolExecutor(
        guard,
        repos.evidence,
        artifacts,
        http_client=httpx.Client(transport=httpx.MockTransport(_http_handler)),
        tls_probe=lambda host, port: TLSProbeResult(
            der=b"DER", version="TLSv1.3", cipher="TLS_AES_256"
        ),
        dns_lookup=lambda host, port=443: ["93.184.216.34"],
    )
    orchestrator = Orchestrator(
        db=db,
        target=TARGET,
        executor=executor,
        registry=registry,
        run_budget=RunBudget(max_tasks=30, max_replans=2, max_parallel=4),
        artifacts_root=artifacts,
    )
    run = orchestrator.run()
    executor.close()
    return repos, run


def test_confirmed_finding_persists_and_injects_across_runs(tmp_path):
    repos1, run1 = _run_once(tmp_path, _registry(), "first.db")

    findings1 = repos1.findings.list_by_run(run1.id)
    assert len(findings1) == 1
    assert findings1[0].status == FindingStatus.CONFIRMED

    knowledge_path = tmp_path / "artifacts" / "knowledge.json"
    assert knowledge_path.exists()
    payload = json.loads(knowledge_path.read_text(encoding="utf-8"))
    entries = payload["targets"]["example.com"]
    assert len(entries) == 1
    entry = entries[0]
    assert entry["kind"] == "confirmed_finding"
    assert entry["title"] == FINDING["title"]
    assert entry["source_run_id"] == run1.id
    assert entry["evidence_hash"]
    assert entry["url"]

    # The four Pentesters receive target knowledge as shared run context.
    pentester_contexts: list[dict] = []
    _repos2, _run2 = _run_once(
        tmp_path,
        _registry(pentester_capture=pentester_contexts),
        "second.db",
    )
    assert pentester_contexts, "no Pentester received a context"
    knowledge = next(
        (context.get("cross_run_knowledge") for context in pentester_contexts
         if context.get("cross_run_knowledge")),
        None,
    )
    assert knowledge, "cross_run_knowledge missing from Pentester context"
    assert knowledge[0]["title"] == FINDING["title"]
    assert knowledge[0]["source_run_id"] == run1.id
    assert knowledge[0]["kind"] == "confirmed_finding"

    # Re-running the same confirmed content must not duplicate entries.
    _run_once(tmp_path, _registry(), "third.db")
    payload = json.loads(knowledge_path.read_text(encoding="utf-8"))
    assert len(payload["targets"]["example.com"]) == 1
