from __future__ import annotations

import json
import threading
from collections import Counter

import httpx

from websec_agent.agents.orchestrator import Orchestrator
from websec_agent.collectors.tls import TLSProbeResult
from websec_agent.config import RoleModelConfig, ScopePolicy
from websec_agent.core.schemas import FindingStatus, Role, RunBudget, TaskKind, TaskStatus
from websec_agent.llm.gateway import LLMGateway
from websec_agent.llm.providers.fake import FakeGateway, json_messages
from websec_agent.scope.guard import ScopeGuard
from websec_agent.store.db import Database
from websec_agent.store.repos import Repositories
from websec_agent.tools.executor import ToolExecutor

TARGET = "https://example.com"


class StaticRegistry:
    def __init__(self, gateways: dict[Role, LLMGateway]) -> None:
        self._gateways = gateways
        self._settings = RoleModelConfig(
            provider="fake", model="fake-model", max_output_tokens=2048
        )

    def resolve(self, role: Role):
        return self._settings, self._gateways[role]


def _http_handler(request: httpx.Request) -> httpx.Response:
    if request.url.path == "/robots.txt":
        return httpx.Response(404, content=b"not found")
    return httpx.Response(
        200,
        content=b"<html><title>home</title></html>",
        headers={"content-type": "text/html"},
    )


def _gateways() -> tuple[StaticRegistry, dict]:
    state = {"pentester_calls": 0}
    lock = threading.Lock()

    def pentester(request) -> str:
        with lock:
            state["pentester_calls"] += 1
            call_number = state["pentester_calls"]
        context = json_messages(request)["context"]
        if call_number != 1:
            return json.dumps(
                {"summary": "No additional high-severity issues identified.", "findings": [], "tool_requests": []}
            )

        baseline = next(
            item for item in context["evidence"]
            if item["kind"] == "http_response" and item["source_url"] == TARGET
        )
        return json.dumps(
            {
                "summary": "Baseline response is missing important browser security headers.",
                "findings": [
                    {
                        "title": "Missing security response headers",
                        "category": "misconfiguration",
                        "severity": "high",
                        "confidence": 82,
                        "description": "The baseline response lacks CSP and X-Frame-Options.",
                        "impact": "The omission weakens browser-side protection against content injection and framing attacks.",
                        "evidence_ids": [baseline["id"]],
                        "reproduction": "Fetch the baseline page and inspect its response headers.",
                        "remediation": "Configure an appropriate Content-Security-Policy and X-Frame-Options policy.",
                    }
                ],
                "tool_requests": [],
                "notes": "",
            }
        )

    return StaticRegistry({Role.PENTESTER: FakeGateway(pentester)}), state


def test_end_to_end_run_with_four_pentesters_and_deterministic_report(tmp_path):
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
        tls_probe=lambda host, port: TLSProbeResult(
            der=b"DER-CERT-BYTES", version="TLSv1.3", cipher="TLS_AES_256_GCM_SHA384"
        ),
        dns_lookup=lambda host, port=443: ["93.184.216.34"],
    )
    registry, state = _gateways()

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

    tasks = repos.tasks.list_by_run(run.id)
    failures = [(task.kind.value, task.status.value, task.error) for task in tasks if task.status != TaskStatus.DONE]
    assert not failures, failures

    kinds = Counter(task.kind.value for task in tasks)
    assert kinds["recon"] == 4
    assert kinds["analyze"] == 4
    assert kinds["plan"] == 0
    assert kinds["review"] == 0
    assert kinds["audit"] == 1
    assert kinds["report"] == 1

    pentester_tasks = [
        task for task in tasks
        if task.kind == TaskKind.ANALYZE and task.inputs.get("pentester_slot")
    ]
    assert len(pentester_tasks) == 4
    assert {task.inputs["pentester_label"] for task in pentester_tasks} == {
        "Pentester 1", "Pentester 2", "Pentester 3", "Pentester 4"
    }

    evidence = repos.evidence.list_by_run(run.id)
    assert len(evidence) == 4
    assert all(item.in_scope for item in evidence)

    findings = repos.findings.list_by_run(run.id)
    assert len(findings) == 1
    assert findings[0].status == FindingStatus.CONFIRMED

    assert repos.reviews.list_by_run(run.id) == []
    audits = repos.audits.list_by_run(run.id)
    assert audits and all(check.passed for check in audits)

    report_task = next(task for task in tasks if task.kind == TaskKind.REPORT)
    report_dir = artifacts / "runs" / run.id
    assert report_dir.exists()
    assert (report_dir / "report.md").exists()
    assert (report_dir / "findings.json").exists()
    assert (report_dir / "run.json").exists()
    assert report_task.result["findings"] == 1
    assert report_task.result["summary_generated"] is True
    assert report_task.result["generator"] == "deterministic"

    markdown = (report_dir / "report.md").read_text(encoding="utf-8")
    assert "Missing security response headers" in markdown
    assert "**Status**: completed" in markdown
    assert "已确认 1 项" in markdown

    run_payload = json.loads((report_dir / "run.json").read_text(encoding="utf-8"))
    assert run_payload["run"]["status"] == "completed"
    assert run_payload["stats"]["tasks"].get("done") == len(tasks)

    assert run.budget["max_parallel"] == 4
    assert run.status.value == "completed"
    assert run.stats["findings"]["confirmed"] == 1
    assert state["pentester_calls"] == 4
