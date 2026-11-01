from __future__ import annotations

import json
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
    path = request.url.path
    if path == "/.env":
        return httpx.Response(
            200, content=b"SECRET=1", headers={"content-type": "text/plain"}
        )
    if path == "/robots.txt":
        return httpx.Response(404, content=b"not found")
    return httpx.Response(200, content=b"<html><title>home</title></html>")


def _gateways() -> tuple[StaticRegistry, dict]:
    state = {"pentester_calls": 0}

    def planner(_request) -> str:
        return json.dumps(
            {
                "rationale": "Inspect baseline configuration and hunt exposed secrets.",
                "tasks": [
                    {
                        "key": "config",
                        "kind": "analyze",
                        "role": "pentester",
                        "objective": "Assess security headers and exposed files.",
                        "inputs": {"focus": "headers"},
                        "depends_on": [],
                        "priority": 50,
                    }
                ],
            }
        )

    def pentester(request) -> str:
        state["pentester_calls"] += 1
        context = json_messages(request)["context"]
        if state["pentester_calls"] > 1:
            return json.dumps(
                {"summary": "No additional issues after new evidence.", "findings": [], "tool_requests": []}
            )
        evidence = context["evidence"][0]
        return json.dumps(
            {
                "summary": "Missing security headers and an exposed env file.",
                "findings": [
                    {
                        "title": "Missing security headers",
                        "category": "misconfiguration",
                        "severity": "high",
                        "confidence": 82,
                        "description": "The baseline response lacks CSP, HSTS and X-Frame-Options.",
                        "impact": "Increases impact of clickjacking and content injection.",
                        "evidence_ids": [evidence["id"]],
                        "reproduction": "curl -I https://example.com and inspect response headers.",
                        "remediation": "Add CSP, HSTS, X-Frame-Options and X-Content-Type-Options.",
                    }
                ],
                "tool_requests": [
                    {
                        "tool": "http_request",
                        "params": {"url": "https://example.com/.env", "method": "GET"},
                        "reason": "Check for exposed environment files",
                    }
                ],
                "notes": "",
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
                        "rationale": "Baseline evidence shows the response headers directly.",
                        "cited_evidence_ids": finding["evidence_ids"],
                        "missing_evidence": [],
                    }
                ],
                "notes": "",
            }
        )

    def reporter(_request) -> str:
        return json.dumps(
            {
                "summary_markdown": (
                    "One high-severity misconfiguration was confirmed after review and "
                    "evidence audit. An exposed .env probe returned HTTP 200 in this fixture."
                )
            }
        )

    registry = StaticRegistry(
        {
            Role.PLANNER: FakeGateway(planner),
            Role.PENTESTER: FakeGateway(pentester),
            Role.REVIEWER: FakeGateway(reviewer),
            Role.REPORTER: FakeGateway(reporter),
        }
    )
    return registry, state


def test_end_to_end_run_with_fake_gateway(tmp_path):
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
    assert all(task.status == TaskStatus.DONE for task in tasks), [
        (task.kind.value, task.status.value, task.error) for task in tasks
    ]
    kinds = Counter(task.kind.value for task in tasks)
    assert kinds["plan"] == 2  # seeded plan plus the evidence-growth expansion cycle
    assert kinds["recon"] == 5  # four baseline collectors plus the requested .env fetch
    assert kinds["analyze"] == 3  # initial analysis, bounded follow-up, and cycle-2 analysis
    assert kinds["review"] == 1
    assert kinds["audit"] == 1
    assert kinds["report"] == 1

    events = repos.events.list_by_run(run.id)
    cycle_events = [e for e in events if e.type == "plan_cycle_created"]
    assert len(cycle_events) == 1
    assert cycle_events[0].payload["evidence_before"] == 4
    assert cycle_events[0].payload["evidence_now"] == 5

    evidence = repos.evidence.list_by_run(run.id)
    assert len(evidence) == 5
    assert all(item.in_scope for item in evidence)

    findings = repos.findings.list_by_run(run.id)
    assert len(findings) == 1
    assert findings[0].status == FindingStatus.CONFIRMED

    reviews = repos.reviews.list_by_run(run.id)
    assert len(reviews) == 1
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

    markdown = (report_dir / "report.md").read_text(encoding="utf-8")
    assert "Missing security headers" in markdown
    assert "**Status**: completed" in markdown
    assert "One high-severity misconfiguration" in markdown

    run_payload = json.loads((report_dir / "run.json").read_text(encoding="utf-8"))
    assert run_payload["run"]["status"] == "completed"
    assert run_payload["stats"]["tasks"].get("done") == len(tasks)

    assert run.status.value == "completed"
    assert run.stats["findings"]["confirmed"] == 1
    assert state["pentester_calls"] == 3
