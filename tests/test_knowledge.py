from __future__ import annotations

import json

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
    "title": "Authentication bypass via SQL injection on login",
    "category": "injection",
    "severity": "critical",
    "confidence": 90,
    "description": "Injected credentials bypass authentication.",
    "impact": "Full account takeover.",
    "reproduction": "POST /doLogin with uid=' or '1'='1 logs in as admin.",
    "remediation": "Parameterize login queries.",
}


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


def _registry(planner_capture=None):
    def planner(request) -> str:
        if planner_capture is not None:
            planner_capture.append(json_messages(request)["context"])
        return json.dumps(
            {
                "rationale": "Analyze login.",
                "tasks": [
                    {
                        "key": "login",
                        "kind": "analyze",
                        "role": "pentester",
                        "objective": "Assess the login flow.",
                        "inputs": {},
                        "depends_on": [],
                        "priority": 50,
                    }
                ],
            }
        )

    def pentester(request) -> str:
        context = json_messages(request)["context"]
        return json.dumps(
            {
                "summary": "Proposing injection.",
                "findings": [{**FINDING, "evidence_ids": [context["evidence"][0]["id"]]}],
                "tool_requests": [],
            }
        )

    def reviewer(request) -> str:
        context = json_messages(request)["context"]
        finding = context["findings"][0]
        return json.dumps(
            {
                "verdicts": [
                    {
                        "finding_id": finding["id"],
                        "verdict": "confirm",
                        "rationale": "Evidence supports the bypass.",
                        "cited_evidence_ids": finding["evidence_ids"],
                        "missing_evidence": [],
                    }
                ],
                "notes": "",
            }
        )

    def reporter(_request) -> str:
        return json.dumps({"summary_markdown": "Knowledge fixture."})

    return StaticRegistry(
        {
            Role.PLANNER: FakeGateway(planner),
            Role.PENTESTER: FakeGateway(pentester),
            Role.REVIEWER: FakeGateway(reviewer),
            Role.REPORTER: FakeGateway(reporter),
        }
    )


def _run_once(tmp_path, registry, db_name) -> Repositories:
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir(exist_ok=True)
    db = Database(f"sqlite+pysqlite:///{tmp_path / db_name}")
    policy = ScopePolicy(allowed_hosts=["example.com"])
    guard = ScopeGuard(policy, TARGET)
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
        run_budget=RunBudget(max_tasks=30, max_replans=2, max_parallel=2),
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
    assert entry["kind"] == "injection_point"
    assert entry["title"] == FINDING["title"]
    assert entry["source_run_id"] == run1.id
    assert entry["evidence_hash"]
    assert entry["url"]

    # Second run: the planner must receive the prior knowledge in context.
    planner_contexts: list[dict] = []
    repos2, run2 = _run_once(tmp_path, _registry(planner_capture=planner_contexts), "second.db")
    assert planner_contexts, "planner was never invoked"
    knowledge = planner_contexts[0].get("cross_run_knowledge")
    assert knowledge, "cross_run_knowledge missing from planner context"
    assert knowledge[0]["title"] == FINDING["title"]
    assert knowledge[0]["source_run_id"] == run1.id
    assert knowledge[0]["kind"] == "injection_point"

    # Re-running the same confirmed content must not duplicate entries.
    _run_once(tmp_path, _registry(), "third.db")
    payload = json.loads(knowledge_path.read_text(encoding="utf-8"))
    assert len(payload["targets"]["example.com"]) == 1
