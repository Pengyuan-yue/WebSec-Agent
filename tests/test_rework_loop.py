from __future__ import annotations

import json
from collections import Counter

import httpx

from websec_agent.agents.orchestrator import Orchestrator
from websec_agent.collectors.tls import TLSProbeResult
from websec_agent.config import RoleModelConfig, ScopePolicy
from websec_agent.core.schemas import FindingStatus, Role, RunBudget, TaskKind
from websec_agent.llm.gateway import LLMGateway
from websec_agent.llm.providers.fake import FakeGateway, json_messages
from websec_agent.scope.guard import ScopeGuard
from websec_agent.store.db import Database
from websec_agent.store.repos import Repositories
from websec_agent.tools.executor import ToolExecutor

TARGET = "https://example.com"

FINDING = {
    "title": "Exposed session token in baseline response",
    "category": "sensitive_data_exposure",
    "severity": "high",
    "confidence": 75,
    "description": "The baseline response leaks a session token.",
    "impact": "Session hijacking.",
    "reproduction": "Fetch the page and inspect the response.",
    "remediation": "Remove the token from responses.",
}


def _proposed(evidence_id: str) -> dict:
    return {**FINDING, "evidence_ids": [evidence_id]}


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


def _make_orchestrator(tmp_path, registry):
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir(exist_ok=True)
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
        tls_probe=lambda host, port: TLSProbeResult(
            der=b"DER-CERT-BYTES", version="TLSv1.3", cipher="TLS_AES_256_GCM_SHA384"
        ),
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
    return orchestrator, repos, artifacts, executor


def _planner(_request) -> str:
    return json.dumps(
        {
            "rationale": "Analyze baseline for high severity exposure.",
            "tasks": [
                {
                    "key": "analyze-baseline",
                    "kind": "analyze",
                    "role": "pentester",
                    "objective": "Assess baseline responses for sensitive data exposure.",
                    "inputs": {},
                    "depends_on": [],
                    "priority": 50,
                }
            ],
        }
    )


def _reporter(_request) -> str:
    return json.dumps({"summary_markdown": "Rework loop fixture summary."})


def _resubmit(request) -> dict | None:
    context = json_messages(request)["context"]
    finding = context["findings"][0]
    return {
        **FINDING,
        "evidence_ids": [finding["evidence_ids"][0]],
    }


def test_needs_evidence_rework_then_confirm(tmp_path):
    state = {"pentester_calls": 0, "reviewer_calls": 0}

    def pentester(request) -> str:
        state["pentester_calls"] += 1
        context = json_messages(request)["context"]
        if state["pentester_calls"] == 1:
            return json.dumps(
                {
                    "summary": "Proposing exposure.",
                    "findings": [_proposed(context["evidence"][0]["id"])],
                    "tool_requests": [],
                }
            )
        if state["pentester_calls"] == 2:
            # Rework turn: resubmit the SAME finding (same title/category).
            return json.dumps(
                {
                    "summary": "Recollected decisive evidence and resubmitting.",
                    "findings": [_resubmit(request)],
                    "tool_requests": [],
                }
            )
        return json.dumps({"summary": "Nothing more.", "findings": [], "tool_requests": []})

    def reviewer(request) -> str:
        state["reviewer_calls"] += 1
        context = json_messages(request)["context"]
        finding = context["findings"][0]
        if state["reviewer_calls"] == 1:
            return json.dumps(
                {
                    "verdicts": [
                        {
                            "finding_id": finding["id"],
                            "verdict": "needs_evidence",
                            "rationale": "No differential evidence the token is accepted elsewhere.",
                            "cited_evidence_ids": [],
                            "missing_evidence": ["a replay request showing the token is valid"],
                        }
                    ],
                    "notes": "",
                }
            )
        return json.dumps(
            {
                "verdicts": [
                    {
                        "finding_id": finding["id"],
                        "verdict": "confirm",
                        "rationale": "Resubmitted evidence is decisive.",
                        "cited_evidence_ids": finding["evidence_ids"],
                        "missing_evidence": [],
                    }
                ],
                "notes": "",
            }
        )

    registry = StaticRegistry(
        {
            Role.PLANNER: FakeGateway(_planner),
            Role.PENTESTER: FakeGateway(pentester),
            Role.REVIEWER: FakeGateway(reviewer),
            Role.REPORTER: FakeGateway(_reporter),
        }
    )
    orchestrator, repos, artifacts, executor = _make_orchestrator(tmp_path, registry)
    run = orchestrator.run()
    executor.close()

    tasks = repos.tasks.list_by_run(run.id)
    kinds = Counter(task.kind.value for task in tasks)
    assert kinds["review"] == 2
    assert kinds["validate"] == 1  # the rework task

    rework_tasks = [t for t in tasks if t.kind == TaskKind.VALIDATE]
    assert rework_tasks[0].inputs.get("rework_finding_id")
    assert "replay request" in rework_tasks[0].objective

    findings = repos.findings.list_by_run(run.id)
    assert len(findings) == 1
    assert findings[0].status == FindingStatus.CONFIRMED

    events = repos.events.list_by_run(run.id)
    event_types = [e.type for e in events]
    assert "rework_created" in event_types
    assert "finding_reworked" in event_types
    reworked = next(e for e in events if e.type == "finding_reworked")
    assert reworked.payload["finding_id"] == findings[0].id
    assert state["pentester_calls"] == 2
    assert state["reviewer_calls"] == 2


def test_rework_loop_is_bounded(tmp_path):
    state = {"pentester_calls": 0}

    def pentester(request) -> str:
        state["pentester_calls"] += 1
        context = json_messages(request)["context"]
        if state["pentester_calls"] == 1:
            return json.dumps(
                {
                    "summary": "Proposing exposure.",
                    "findings": [_proposed(context["evidence"][0]["id"])],
                    "tool_requests": [],
                }
            )
        # Rework turns keep resubmitting the same finding with the same evidence.
        return json.dumps(
            {
                "summary": "Resubmitting with available evidence.",
                "findings": [_resubmit(request)],
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
                        "verdict": "needs_evidence",
                        "rationale": "Still not decisive.",
                        "cited_evidence_ids": [],
                        "missing_evidence": ["impossible proof"],
                    }
                ],
                "notes": "",
            }
        )

    registry = StaticRegistry(
        {
            Role.PLANNER: FakeGateway(_planner),
            Role.PENTESTER: FakeGateway(pentester),
            Role.REVIEWER: FakeGateway(reviewer),
            Role.REPORTER: FakeGateway(_reporter),
        }
    )
    orchestrator, repos, artifacts, executor = _make_orchestrator(tmp_path, registry)
    run = orchestrator.run()
    executor.close()

    tasks = repos.tasks.list_by_run(run.id)
    kinds = Counter(task.kind.value for task in tasks)
    # three reviews, but only two rework tasks
    assert kinds["review"] == 3
    assert kinds["validate"] == 2

    events = repos.events.list_by_run(run.id)
    event_types = [e.type for e in events]
    assert event_types.count("rework_created") == 2
    assert "rework_limit_reached" in event_types

    findings = repos.findings.list_by_run(run.id)
    assert len(findings) == 1
    assert findings[0].status == FindingStatus.UNCERTAIN
    # the run still terminates with a report
    assert kinds["report"] == 1
    assert state["pentester_calls"] == 3
