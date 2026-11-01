from __future__ import annotations

import json
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from ..core.budget import BudgetGuard, BudgetSnapshot
from ..core.errors import ConfigError, ConcurrentModification, ProtocolError, ScopeViolation, WebSecError
from ..core.schemas import (
    AuditOutput,
    Budget,
    EventRecord,
    EvidenceKind,
    EvidenceSummary,
    Finding,
    FindingStatus,
    FindingSummary,
    ProposedFinding,
    Role,
    Run,
    RunBudget,
    RunStatus,
    Severity,
    SupervisorOutput,
    Task,
    TaskKind,
    TaskStatus,
    ToolRequest,
    ToolName,
    utcnow,
)
from ..core.state import is_terminal, validate_transition
from ..collectors.base import Collected
from ..llm.gateway import LLMCaller
from ..llm.registry import GatewayRegistry
from ..report.builder import build_report, compute_stats
from ..store.db import Database
from ..store.knowledge import KnowledgeStore
from ..store.repos import Repositories
from ..tools.oast import OastChannel
from .auditor import EvidenceAuditor
from .context import compress_evidence, compress_list
from .pentester import PentesterAgent
from .supervisor import SupervisorAgent

ANALYSIS_KINDS = {TaskKind.ANALYZE, TaskKind.EXPLOIT, TaskKind.VALIDATE}
ACTIVE_STATUSES = {TaskStatus.PENDING, TaskStatus.READY, TaskStatus.RUNNING}
MAX_CONTEXT_EVIDENCE = 200
MAX_EXCERPT_CHARS = 200_000
MAX_CONTEXT_TASKS = 20
MAX_TOOL_REQUESTS_PER_TURN = 3
MAX_PROBES_PER_ENDPOINT = 3
# Kinds safe to dispatch concurrently: their handlers are LLM-bound (pure
# network I/O) or subprocess-bound; all DB access is serialized by the
# Database session lock. AUDIT and REPORT stay exclusive.
PARALLEL_KINDS = {
    TaskKind.RECON,
    TaskKind.ANALYZE,
    TaskKind.EXPLOIT,
    TaskKind.VALIDATE,
}
CONTEXT_CHARS_PER_TOKEN = 3.5
CONTEXT_BUDGET_RATIO = 0.95
CONTEXT_SAFETY_TOKENS = 4096
MIN_CONTEXT_BUDGET_CHARS = 40_000
MAX_SUPERVISOR_CALLS_PER_RUN = 8


class Orchestrator:
    """Single writer for task state. Agents only propose; the harness persists."""

    def __init__(
        self,
        db: Database,
        target: str,
        executor,
        registry: GatewayRegistry,
        run_budget: RunBudget,
        artifacts_root: str | Path,
        use_memory: bool = True,
    ) -> None:
        self._db = db
        self._target = target
        self._executor = executor
        self._registry = registry
        # Four Pentester workers are a fixed part of this orchestration model.
        self._run_budget = run_budget.model_copy(update={"max_parallel": 4})
        self._artifacts_root = Path(artifacts_root)
        self._repos = Repositories.build(db)
        self._guard = executor.guard
        self._auditor = EvidenceAuditor(self._repos.evidence, artifacts_root)
        self._budget: BudgetGuard | None = None
        self._seen_tool_requests: dict[str, set[str]] = {}
        self._probe_counts: dict[str, dict[tuple[str, str], int]] = {}
        self._persist_lock = threading.RLock()
        self._supervisor_lock = threading.RLock()
        self._supervisor_directives: dict[int, dict[str, Any]] = {}
        self._supervisor_calls: dict[str, int] = {}
        self._supervisor_disabled = False
        self._supervisor_budget_reported = False

        parsed = urlparse(target)
        self._target_host = parsed.hostname or ""
        self._target_scheme = parsed.scheme or "https"
        self._target_port = parsed.port or (443 if self._target_scheme == "https" else 80)

        self._use_memory = use_memory
        self._knowledge = KnowledgeStore(self._artifacts_root / "knowledge.json")
        self._knowledge_loaded = (
            self._knowledge.entries_for(self._target_host) if use_memory else []
        )
        self._oast = OastChannel(
            binary=self._artifacts_root.parent / "tools" / "bin" / "interactsh-client",
            log_path=self._artifacts_root / "oast" / "channel.log",
        )
        self._oast_started = False

    # ------------------------------------------------------------------ run

    def run(self) -> Run:
        self._db.create_all()
        run = Run(
            target=self._target,
            scope_snapshot=self._guard.snapshot(),
            budget=self._run_budget.model_dump(),
        )
        self._repos.runs.create(run)
        self._event(run.id, "run_started", {"target": self._target})
        self._budget = BudgetGuard(self._run_budget, lambda: self._budget_snapshot(run.id))

        self._seed_initial_tasks(run.id)
        self._start_oast(run.id)

        pool = ThreadPoolExecutor(
            max_workers=4, thread_name_prefix="websec-dispatch"
        )
        try:
            while True:
                self._refresh_dependencies(run.id)
                self._schedule_followups(run.id)
                self._refresh_dependencies(run.id)

                ready = self._repos.tasks.list_by_status(run.id, TaskStatus.READY)
                if not ready:
                    if self._ensure_report_task(run.id):
                        continue
                    break

                if self._supervisor_calls.get(run.id, 0) == 0 and any(
                    task.inputs.get("pentester_slot") for task in ready
                ):
                    self._maybe_supervise(run.id, "initial_assignment")
                    ready = self._repos.tasks.list_by_status(run.id, TaskStatus.READY)

                if ready[0].kind != TaskKind.REPORT:
                    reason = self._budget.exhaustion_reason()
                    if reason:
                        for candidate in ready:
                            if candidate.kind != TaskKind.REPORT:
                                self._skip(candidate, reason)
                        continue

                batch = [
                    task
                    for task in ready
                    if task.kind in PARALLEL_KINDS
                ][:4]
                if len(batch) <= 1:
                    candidate = ready[0]
                    self._dispatch(candidate)
                    if candidate.kind in ANALYSIS_KINDS and candidate.inputs.get("pentester_slot"):
                        self._maybe_supervise(
                            run.id,
                            f"worker_checkpoint:{candidate.inputs.get('pentester_slot')}",
                        )
                    continue
                self._event(
                    run.id,
                    "dispatch_parallel",
                    {
                        "task_ids": [task.id for task in batch],
                        "kinds": [t.kind.value for t in batch],
                        "agents": [
                            t.inputs.get("pentester_label")
                            for t in batch
                            if t.inputs.get("pentester_label")
                        ],
                    },
                )
                future_tasks = {pool.submit(self._dispatch, task): task for task in batch}
                for future in as_completed(future_tasks):
                    future.result()
                    completed_task = future_tasks[future]
                    if (
                        completed_task.kind in ANALYSIS_KINDS
                        and completed_task.inputs.get("pentester_slot")
                    ):
                        self._maybe_supervise(
                            run.id,
                            f"worker_checkpoint:{completed_task.inputs.get('pentester_slot')}",
                        )
        finally:
            pool.shutdown(wait=True)

        self._finalize_oast(run.id)
        return self._finalize(run.id)

    # ------------------------------------------------------------------- oast

    def _start_oast(self, run_id: str) -> None:
        if not self._oast.available:
            self._event(run_id, "oast_unavailable", {"reason": "interactsh-client not installed"})
            return
        try:
            if self._oast.start():
                self._oast_started = True
                self._event(
                    run_id,
                    "oast_started",
                    {"callback_url": self._oast.url, "server": "default oast cluster"},
                )
            else:
                self._event(run_id, "oast_unavailable", {"reason": "registration failed or timed out"})
        except Exception as exc:  # noqa: BLE001 - OAST is an optional channel
            self._event(run_id, "oast_unavailable", {"reason": f"{type(exc).__name__}: {exc}"[:200]})

    def _flush_oast(self, run_id: str) -> list[str]:
        """Persist pending OAST interactions as citable evidence."""
        if not self._oast_started:
            return []
        evidence_ids: list[str] = []
        try:
            with self._persist_lock:
                for interaction in self._oast.new_interactions():
                    evidence = self._persist_oast_interaction(run_id, interaction)
                    if evidence is not None:
                        evidence_ids.append(evidence.id)
        except Exception as exc:  # noqa: BLE001 - a bad interaction must not kill the run
            self._event(run_id, "oast_flush_failed", {"error": f"{type(exc).__name__}: {exc}"[:200]})
        return evidence_ids

    def _persist_oast_interaction(self, run_id: str, interaction: dict[str, Any]):
        protocol = str(interaction.get("protocol", "unknown"))
        unique_id = str(interaction.get("unique-id", ""))
        summary = (
            f"OAST {protocol} callback for {unique_id} from "
            f"{interaction.get('remote-address', '?')} at {interaction.get('timestamp', '?')}"
        )
        raw = json.dumps(interaction, ensure_ascii=False, indent=2).encode("utf-8")
        collected = Collected(
            kind=EvidenceKind.OAST_CALLBACK,
            source_url=f"{unique_id or 'oast'}.oast.callback",
            method=f"OAST_{protocol.upper()}",
            summary=summary,
            raw=raw,
            derived_from=[],
        )
        evidence = self._executor.persist_collected(collected, run_id)
        self._event(
            run_id,
            "oast_interaction",
            {
                "evidence_id": evidence.id,
                "protocol": protocol,
                "unique_id": unique_id,
                "remote_address": str(interaction.get("remote-address", "")),
            },
        )
        return evidence

    def _finalize_oast(self, run_id: str) -> None:
        evidence_ids = self._flush_oast(run_id)
        try:
            total = self._oast.stop()
        except Exception:  # noqa: BLE001
            total = 0
        if self._oast_started:
            self._event(
                run_id,
                "oast_stopped",
                {"total_interactions": total, "final_evidence_ids": evidence_ids},
            )

    # --------------------------------------------------------------- seeding


    def _seed_initial_tasks(self, run_id: str) -> None:
        url = self._target
        origin = f"{self._target_scheme}://{urlparse(url).netloc}"

        recon_specs: list[tuple[str, ToolRequest]] = [
            (
                "Baseline HTTP fetch of the target",
                ToolRequest(
                    tool=ToolName.HTTP_REQUEST,
                    params={"url": url, "method": "GET"},
                    reason="baseline",
                ),
            ),
        ]

        if self._target_scheme == "https":
            recon_specs.append(
                (
                    f"TLS certificate probe of {self._target_host}:{self._target_port}",
                    ToolRequest(
                        tool=ToolName.TLS_PROBE,
                        params={"host": self._target_host, "port": self._target_port},
                        reason="baseline",
                    ),
                )
            )

        recon_specs.extend(
            [
                (
                    "Fetch robots.txt",
                    ToolRequest(
                        tool=ToolName.ROBOTS,
                        params={"url": f"{origin}/robots.txt"},
                        reason="baseline",
                    ),
                ),
                (
                    "Resolve target DNS records",
                    ToolRequest(
                        tool=ToolName.DNS_LOOKUP,
                        params={"host": self._target_host},
                        reason="baseline",
                    ),
                ),
            ]
        )

        recon_ids: list[str] = []
        for objective, request in recon_specs:
            task = self._create_task(
                run_id,
                kind=TaskKind.RECON,
                role=Role.PENTESTER,
                objective=objective,
                inputs={"request": request.model_dump(mode="json"), "baseline": True},
                depends_on=[],
                priority=80,
                status=TaskStatus.READY,
            )
            recon_ids.append(task.id)

        # Baseline recon finishes first. The Supervisor assigns the initial
        # objectives before any Pentester starts; workers do not self-select lanes.
        pentester_lanes = [
            ("Pentester 1", "Await Supervisor assignment for worker slot 1."),
            ("Pentester 2", "Await Supervisor assignment for worker slot 2."),
            ("Pentester 3", "Await Supervisor assignment for worker slot 3."),
            ("Pentester 4", "Await Supervisor assignment for worker slot 4."),
        ]
        for slot, (label, objective) in enumerate(pentester_lanes, start=1):
            self._create_task(
                run_id,
                kind=TaskKind.ANALYZE,
                role=Role.PENTESTER,
                objective=objective,
                inputs={"pentester_slot": slot, "pentester_label": label},
                depends_on=recon_ids,
                priority=70,
                status=TaskStatus.PENDING,
            )

    def _create_task(
        self,
        run_id: str,
        *,
        kind: TaskKind,
        role: Role,
        objective: str,
        inputs: dict[str, Any],
        depends_on: list[str],
        priority: int,
        status: TaskStatus = TaskStatus.PENDING,
        parent_id: str | None = None,
        budget: Budget | None = None,
    ) -> Task:
        task = Task(
            run_id=run_id,
            parent_id=parent_id,
            kind=kind,
            role=role,
            objective=objective,
            inputs=inputs,
            depends_on=depends_on,
            status=status,
            priority=priority,
            budget=budget or Budget(),
        )
        self._repos.tasks.create(task)
        self._event(
            run_id,
            "task_created",
            {
                "task_id": task.id,
                "kind": kind.value,
                "role": role.value,
                "status": status.value,
                "agent": inputs.get("pentester_label"),
            },
            task_id=task.id,
        )
        return task

    def _update_task(self, task: Task, new_status: TaskStatus, error: str | None = None) -> None:
        validate_transition(task.status, new_status)
        task.status = new_status
        if error is not None:
            task.error = error
        self._repos.tasks.update(task)
        self._event(
            task.run_id,
            f"task_{new_status.value}",
            {"task_id": task.id, "error": task.error},
            task_id=task.id,
        )

    def _skip(self, task: Task, reason: str) -> None:
        task.error = reason
        self._update_task(task, TaskStatus.SKIPPED, reason)

    def _refresh_dependencies(self, run_id: str) -> None:
        tasks = self._repos.tasks.list_by_run(run_id)
        by_id = {task.id: task for task in tasks}
        for task in tasks:
            if task.status != TaskStatus.PENDING:
                continue
            missing = [dep for dep in task.depends_on if dep not in by_id]
            if missing:
                self._skip(task, f"missing dependency tasks: {', '.join(missing)}")
                continue
            if all(is_terminal(by_id[dep].status) for dep in task.depends_on):
                self._update_task(task, TaskStatus.READY)

    # ------------------------------------------------------------- scheduling

    def _maybe_supervise(self, run_id: str, checkpoint: str) -> None:
        """Run a bounded Supervisor checkpoint and update only unstarted lane work."""
        if self._supervisor_disabled:
            return
        calls = self._supervisor_calls.get(run_id, 0)
        if calls >= MAX_SUPERVISOR_CALLS_PER_RUN:
            if not self._supervisor_budget_reported:
                self._supervisor_budget_reported = True
                self._event(
                    run_id,
                    "supervisor_budget_exhausted",
                    {"limit": MAX_SUPERVISOR_CALLS_PER_RUN},
                )
            return

        tasks = self._repos.tasks.list_by_run(run_id)
        lane_tasks = [
            task for task in tasks
            if task.kind in ANALYSIS_KINDS and task.inputs.get("pentester_slot") in {1, 2, 3, 4}
        ]
        if not lane_tasks or not any(
            task.status in {TaskStatus.PENDING, TaskStatus.READY, TaskStatus.RUNNING}
            for task in lane_tasks
        ):
            return

        try:
            self._registry.resolve(Role.SUPERVISOR)
        except Exception as exc:  # noqa: BLE001 - deterministic lane split remains available
            self._supervisor_disabled = True
            self._event(
                run_id,
                "supervisor_unavailable",
                {"reason": f"{type(exc).__name__}: {exc}"[:240]},
            )
            return

        if self._budget is not None and self._budget.exhaustion_reason():
            return

        self._supervisor_calls[run_id] = calls + 1
        supervisor_task = Task(
            run_id=run_id,
            kind=TaskKind.SUPERVISE,
            role=Role.SUPERVISOR,
            objective="Coordinate the four Pentester lanes using the latest checkpoint state.",
            inputs={"checkpoint": checkpoint, "checkpoint_number": calls + 1},
            status=TaskStatus.RUNNING,
        )
        try:
            output = self._call_agent(
                SupervisorAgent(),
                supervisor_task,
                self._supervisor_context(run_id, checkpoint),
            )
            if not isinstance(output, SupervisorOutput):
                output = SupervisorOutput.model_validate(output)
            supervisor_task.status = TaskStatus.DONE
            supervisor_task.attempts = 1
            supervisor_task.result = output.model_dump(mode="json")
            self._repos.tasks.create(supervisor_task)
            self._apply_supervisor_output(run_id, output)
            self._event(
                run_id,
                "supervisor_completed",
                {
                    "supervisor_task_id": supervisor_task.id,
                    "checkpoint": checkpoint,
                    "summary": output.summary,
                    "assignments": len(output.assignments),
                    "overlap_warnings": output.overlap_warnings,
                },
                task_id=supervisor_task.id,
            )
        except Exception as exc:  # noqa: BLE001 - fall back to the four deterministic lanes
            self._supervisor_disabled = True
            self._event(
                run_id,
                "supervisor_failed",
                {
                    "supervisor_task_id": supervisor_task.id,
                    "checkpoint": checkpoint,
                    "reason": f"{type(exc).__name__}: {exc}"[:400],
                    "fallback": "keep_existing_four_lane_assignments",
                },
                task_id=supervisor_task.id,
            )

    def _supervisor_context(self, run_id: str, checkpoint: str) -> dict[str, Any]:
        tasks = self._repos.tasks.list_by_run(run_id)
        findings = self._repos.findings.list_by_run(run_id)
        evidence = self._repos.evidence.list_by_run(run_id)
        return {
            "target": self._target,
            "authorized_scope": self._guard.snapshot(),
            "checkpoint": checkpoint,
            "lanes": self._worker_roster_context(tasks, None),
            "findings": [
                {
                    "title": item.title,
                    "category": item.category,
                    "severity": item.severity.value,
                    "status": item.status.value,
                    "task_id": item.task_id,
                }
                for item in findings[-40:]
            ],
            "evidence_inventory": [
                {
                    "kind": item.kind.value,
                    "source_url": item.source_url,
                    "method": item.method,
                    "summary": item.summary[:240],
                }
                for item in evidence[-60:]
            ],
            "constraints": {
                "worker_slots": 4,
                "max_parallel": 4,
                "running_tasks_are_immutable": True,
                "supervisor_may_only_guide_unstarted_work": True,
            },
        }

    def _apply_supervisor_output(self, run_id: str, output: SupervisorOutput) -> None:
        tasks = self._repos.tasks.list_by_run(run_id)
        seen_slots: set[int] = set()
        focus_owners: dict[str, int] = {}
        for directive in output.assignments:
            if directive.slot in seen_slots:
                continue
            seen_slots.add(directive.slot)
            payload = directive.model_dump(mode="json")
            unique_focus: list[str] = []
            for item in payload.get("focus", []):
                normalized = " ".join(str(item).casefold().split())
                if not normalized or normalized in focus_owners:
                    continue
                focus_owners[normalized] = directive.slot
                unique_focus.append(str(item))
            payload["focus"] = unique_focus
            with self._supervisor_lock:
                self._supervisor_directives[directive.slot] = payload

            updated = 0
            for candidate in tasks:
                if candidate.inputs.get("pentester_slot") != directive.slot:
                    continue
                if candidate.status not in {TaskStatus.PENDING, TaskStatus.READY}:
                    continue
                latest = self._repos.tasks.get(candidate.id)
                if latest is None or latest.status not in {TaskStatus.PENDING, TaskStatus.READY}:
                    continue
                if latest.inputs.get("supervisor_directive") == payload:
                    continue
                latest.inputs = {**latest.inputs, "supervisor_directive": payload}
                latest.objective = directive.objective
                try:
                    self._repos.tasks.update(latest)
                    updated += 1
                except ConcurrentModification:
                    # A worker claimed the task concurrently; never overwrite in-progress work.
                    continue
            self._event(
                run_id,
                "supervisor_assignment_applied",
                {
                    "slot": directive.slot,
                    "focus": payload["focus"],
                    "avoid": payload["avoid"],
                    "guidance": payload["guidance"],
                    "updated_unstarted_tasks": updated,
                },
            )

    def _worker_roster_context(
        self, tasks: list[Task], current_slot: int | None
    ) -> list[dict[str, Any]]:
        roster: list[dict[str, Any]] = []
        for slot in range(1, 5):
            lane = [
                task for task in tasks
                if task.kind in ANALYSIS_KINDS and task.inputs.get("pentester_slot") == slot
            ]
            if not lane:
                continue
            lane.sort(key=lambda item: (item.created_at, item.id))
            latest = lane[-1]
            summaries = [
                str(item.result.get("summary", ""))[:400]
                for item in lane
                if item.status == TaskStatus.DONE
                and isinstance(item.result, dict)
                and item.result.get("summary")
            ][-3:]
            with self._supervisor_lock:
                directive = dict(self._supervisor_directives.get(slot, {}))
            roster.append(
                {
                    "slot": slot,
                    "label": latest.inputs.get("pentester_label", f"Pentester {slot}"),
                    "status": latest.status.value,
                    "current_objective": latest.objective,
                    "active": any(item.status == TaskStatus.RUNNING for item in lane),
                    "unstarted_task_ids": [
                        item.id for item in lane
                        if item.status in {TaskStatus.PENDING, TaskStatus.READY}
                    ],
                    "completed_summaries": summaries,
                    "supervisor_directive": directive,
                    "is_current_worker": slot == current_slot,
                }
            )
        return roster

    def _schedule_followups(self, run_id: str) -> None:
        """Schedule one deterministic evidence-integrity audit after Pentester work settles."""
        tasks = self._repos.tasks.list_by_run(run_id)
        findings = self._repos.findings.list_by_run(run_id)
        audited_ids = self._repos.audits.audited_finding_ids(run_id)

        active_work = any(
            task.kind in (ANALYSIS_KINDS | {TaskKind.RECON})
            and task.status in ACTIVE_STATUSES
            for task in tasks
        )
        active_audit = any(
            task.kind == TaskKind.AUDIT and task.status in ACTIVE_STATUSES for task in tasks
        )
        if active_work or active_audit:
            return

        attempted_ids = {
            finding_id
            for task in tasks
            if task.kind == TaskKind.AUDIT
            for finding_id in (task.inputs.get("finding_ids") or [])
        }
        unaudited = [
            finding
            for finding in findings
            if finding.status in {FindingStatus.CONFIRMED, FindingStatus.UNCERTAIN}
            and finding.id not in audited_ids
            and finding.id not in attempted_ids
        ]
        if not unaudited:
            return

        work_ids = [
            task.id
            for task in tasks
            if task.kind in (ANALYSIS_KINDS | {TaskKind.RECON})
            and task.status != TaskStatus.SKIPPED
        ]
        self._create_task(
            run_id,
            kind=TaskKind.AUDIT,
            role=Role.SYSTEM,
            objective="Programmatically audit evidence hashes, scope flags and finding completeness.",
            inputs={"finding_ids": [finding.id for finding in unaudited]},
            depends_on=work_ids,
            priority=58,
        )


    def _ensure_report_task(self, run_id: str) -> bool:
        tasks = self._repos.tasks.list_by_run(run_id)
        if any(task.kind == TaskKind.REPORT for task in tasks):
            return False
        self._create_task(
            run_id,
            kind=TaskKind.REPORT,
            role=Role.SYSTEM,
            objective="Generate the report deterministically from persisted evidence and findings.",
            inputs={},
            depends_on=[task.id for task in tasks],
            priority=5,
        )
        return True


    def _dispatch(self, task: Task) -> None:
        task.attempts += 1
        self._update_task(task, TaskStatus.RUNNING)
        try:
            if task.kind == TaskKind.RECON:
                result = self._handle_recon(task)
            elif task.kind in ANALYSIS_KINDS:
                result = self._handle_pentest(task)
            elif task.kind == TaskKind.AUDIT:
                result = self._handle_audit(task)
            elif task.kind == TaskKind.REPORT:
                result = self._handle_report(task)
            else:
                raise ProtocolError(f"unsupported task kind: {task.kind}")

            task.result = result
            self._update_task(task, TaskStatus.DONE)
        except ScopeViolation as exc:
            self._fail(task, f"{exc}", event_type="scope_violation")
        except (WebSecError, ConfigError) as exc:
            self._fail(task, str(exc))
        except Exception as exc:  # noqa: BLE001 - a single task must not kill the run
            self._fail(task, f"{type(exc).__name__}: {exc}")

    def _fail(self, task: Task, message: str, event_type: str = "task_failed") -> None:
        task.error = message[:2000]
        self._update_task(task, TaskStatus.FAILED, task.error)
        if event_type != "task_failed":
            self._event(
                task.run_id,
                event_type,
                {"task_id": task.id, "error": task.error},
                task_id=task.id,
            )

    # ---------------------------------------------------------------- handlers

    def _handle_recon(self, task: Task) -> dict[str, Any]:
        raw_request = task.inputs.get("request")
        if not isinstance(raw_request, dict):
            raise ProtocolError("recon task requires inputs.request")
        request = ToolRequest.model_validate(raw_request)
        evidence = self._executor.execute(request, task.run_id, task.id)
        self._event(
            task.run_id,
            "evidence_collected",
            {
                "evidence_id": evidence.id,
                "kind": evidence.kind.value,
                "source_url": evidence.source_url,
                "summary": evidence.summary,
            },
            task_id=task.id,
        )
        return {
            "evidence_id": evidence.id,
            "kind": evidence.kind.value,
            "source_url": evidence.source_url,
            "summary": evidence.summary,
        }

    def _handle_pentest(self, task: Task) -> dict[str, Any]:
        context = self._context(task)
        directive = context.get("supervisor_guidance")
        agent_task = task
        if isinstance(directive, dict) and directive:
            guidance_lines = [
                "Supervisor guidance for this checkpoint (coordination only):",
                f"Focus: {', '.join(directive.get('focus') or [])}",
                f"Avoid duplicating: {', '.join(directive.get('avoid') or [])}",
                f"Guidance: {directive.get('guidance', '')}",
            ]
        output = self._call_agent(PentesterAgent(), task, context)

        with self._persist_lock:
            rework_finding_id = task.inputs.get("rework_finding_id")
            rework_finding: Finding | None = None
            if isinstance(rework_finding_id, str) and rework_finding_id:
                rework_finding = self._repos.findings.get(task.run_id, rework_finding_id)
            rework_key = (
                (rework_finding.title.strip().lower(), rework_finding.category.strip().lower())
                if rework_finding is not None
                else None
            )

            existing = self._repos.findings.list_by_run(task.run_id)
            duplicate_keys = {
                (finding.title.strip().lower(), finding.category.strip().lower())
                for finding in existing
                if (finding.title.strip().lower(), finding.category.strip().lower()) != rework_key
            }
            created_findings: list[Finding] = []
            reworked_findings: list[Finding] = []

            for proposed in output.findings:
                if proposed.severity not in {Severity.CRITICAL, Severity.HIGH}:
                    self._event(
                        task.run_id,
                        "finding_dropped",
                        {
                            "reason": "severity out of scope (high/critical only)",
                            "severity": proposed.severity.value,
                            "title": proposed.title,
                        },
                        task_id=task.id,
                    )
                    continue
                evidence_ids = list(dict.fromkeys(proposed.evidence_ids))
                evidence = self._repos.evidence.list_by_ids(task.run_id, evidence_ids)
                valid_ids = {item.id for item in evidence if item.in_scope}
                missing = [eid for eid in evidence_ids if eid not in valid_ids]
                if missing:
                    self._event(
                        task.run_id,
                        "finding_dropped",
                        {"reason": "unverified evidence ids", "missing": missing, "title": proposed.title},
                        task_id=task.id,
                    )
                    continue

                key = (proposed.title.strip().lower(), proposed.category.strip().lower())
                if rework_key is not None and key == rework_key:
                    reworked = self._resubmit_rework_finding(task, rework_finding, proposed, evidence_ids)
                    if reworked is not None:
                        reworked_findings.append(reworked)
                    continue
                if key in duplicate_keys:
                    self._event(
                        task.run_id,
                        "finding_dropped",
                        {"reason": "duplicate", "title": proposed.title},
                        task_id=task.id,
                    )
                    continue

                finding = self._persist_finding(task, proposed, evidence_ids)
                duplicate_keys.add(key)
                created_findings.append(finding)

            child_ids, followup_id = self._create_tool_children(task, output.tool_requests)

            return {
                "summary": output.summary,
                "notes": output.notes,
                "finding_ids": [finding.id for finding in created_findings],
                "reworked_finding_ids": [finding.id for finding in reworked_findings],
                "tool_task_ids": child_ids,
                "followup_task_id": followup_id,
            }

    def _persist_finding(
        self, task: Task, proposed: ProposedFinding, evidence_ids: list[str]
    ) -> Finding:
        finding = Finding(
            run_id=task.run_id,
            task_id=task.id,
            title=proposed.title,
            category=proposed.category,
            severity=proposed.severity,
            confidence=proposed.confidence,
            description=proposed.description,
            impact=proposed.impact,
            evidence_ids=evidence_ids,
            reproduction=proposed.reproduction,
            remediation=proposed.remediation,
            status=FindingStatus.CONFIRMED,
            created_by=Role.PENTESTER,
        )
        self._repos.findings.create(finding)
        self._event(
            task.run_id,
            "finding_created",
            {
                "finding_id": finding.id,
                "title": finding.title,
                "severity": finding.severity.value,
                "status": finding.status.value,
            },
            task_id=task.id,
        )
        return finding

    def _resubmit_rework_finding(
        self, task: Task, finding: Finding, proposed: ProposedFinding, evidence_ids: list[str]
    ) -> Finding | None:
        """Rework resubmission: merge new evidence into the original finding."""
        if not evidence_ids:
            self._event(
                task.run_id,
                "finding_rework_rejected",
                {"finding_id": finding.id, "reason": "no in-scope evidence ids"},
                task_id=task.id,
            )
            return None
        merged = list(dict.fromkeys([*finding.evidence_ids, *evidence_ids]))
        updated = finding.model_copy(
            update={
                "confidence": proposed.confidence,
                "description": proposed.description,
                "impact": proposed.impact,
                "evidence_ids": merged,
                "reproduction": proposed.reproduction,
                "remediation": proposed.remediation,
                "status": FindingStatus.PROPOSED,
                "updated_at": utcnow(),
            }
        )
        self._repos.findings.update(updated)
        self._event(
            task.run_id,
            "finding_reworked",
            {
                "finding_id": updated.id,
                "added_evidence_ids": [eid for eid in evidence_ids if eid not in finding.evidence_ids],
                "evidence_count": len(merged),
                "status": updated.status.value,
            },
            task_id=task.id,
        )
        return updated

    def _create_tool_children(
        self, task: Task, requests: list[ToolRequest]
    ) -> tuple[list[str], str | None]:
        if not requests:
            return [], None
        assert self._budget is not None

        allowed = requests[:MAX_TOOL_REQUESTS_PER_TURN]
        if len(allowed) < len(requests):
            self._event(
                task.run_id,
                "tool_requests_truncated",
                {"requested": len(requests), "allowed": len(allowed)},
                task_id=task.id,
            )

        seen_keys = self._seen_tool_requests.setdefault(task.run_id, set())
        probe_counts = self._probe_counts.setdefault(task.run_id, {})
        child_ids: list[str] = []
        deduplicated = 0
        withheld = 0
        for request in allowed:
            exact_key = json.dumps(
                {"tool": request.tool.value, "params": request.params},
                sort_keys=True,
                ensure_ascii=False,
            )
            if exact_key in seen_keys:
                deduplicated += 1
                continue
            seen_keys.add(exact_key)
            if request.tool.value == "http_request":
                endpoint = (
                    request.params.get("method", "GET"),
                    request.params.get("url", ""),
                )
                probe_counts[endpoint] = probe_counts.get(endpoint, 0) + 1
                if probe_counts[endpoint] > MAX_PROBES_PER_ENDPOINT:
                    withheld += 1
                    continue
            child = self._create_task(
                task.run_id,
                kind=TaskKind.RECON,
                role=Role.PENTESTER,
                objective=f"Collect evidence via {request.tool.value}: {request.reason or request.params}",
                inputs={"request": request.model_dump(mode="json"), "parent_analysis": task.id},
                depends_on=[task.id],
                priority=max(0, task.priority - 10),
                parent_id=task.id,
                budget=task.budget,
            )
            child_ids.append(child.id)
        if deduplicated:
            self._event(
                task.run_id,
                "tool_requests_deduplicated",
                {"duplicates": deduplicated},
                task_id=task.id,
            )
        if withheld:
            self._event(
                task.run_id,
                "probe_limit_reached",
                {"withheld": withheld},
                task_id=task.id,
            )

        # No newly scheduled collection means no new evidence can arrive; do not
        # spin a follow-up Pentester task on requests already deduplicated.
        if not child_ids:
            return child_ids, None

        if self._budget.replan_limit_reached(self._repos.tasks.replan_count(task.run_id)):
            self._event(
                task.run_id,
                "replan_limit_reached",
                {"limit": self._run_budget.max_replans},
                task_id=task.id,
            )
            return child_ids, None

        followup_kind = task.kind if task.kind in ANALYSIS_KINDS else TaskKind.ANALYZE
        conclude_note = ""
        if withheld:
            conclude_note = (
                " NOTE: the harness withheld further probes for endpoints already tested"
                " multiple times with equivalent responses. CONCLUDE NOW: submit a finding"
                " citing the existing evidence, or state precisely what decisive signal is missing."
            )
        followup_inputs = {"followup": True, "origin_task": task.id, "origin_objective": task.objective}
        for key in ("pentester_slot", "pentester_label"):
            if key in task.inputs:
                followup_inputs[key] = task.inputs[key]
        slot = task.inputs.get("pentester_slot")
        directive = task.inputs.get("supervisor_directive")
        if not isinstance(directive, dict) and isinstance(slot, int):
            with self._supervisor_lock:
                directive = self._supervisor_directives.get(slot)
        if isinstance(directive, dict):
            followup_inputs["supervisor_directive"] = dict(directive)
        if isinstance(task.inputs.get("rework_finding_id"), str):
            followup_inputs["rework_finding_id"] = task.inputs["rework_finding_id"]
            followup_inputs["missing_evidence"] = task.inputs.get("missing_evidence", [])
        followup = self._create_task(
            task.run_id,
            kind=followup_kind,
            role=Role.PENTESTER,
            objective=f"Re-analyze with newly collected evidence: {task.objective}{conclude_note}",
            inputs=followup_inputs,
            depends_on=child_ids,
            priority=max(0, task.priority - 15),
            parent_id=task.id,
            budget=task.budget,
        )
        self._event(
            task.run_id,
            "replan_created",
            {"followup_task": followup.id, "origin_task": task.id},
            task_id=task.id,
        )
        return child_ids, followup.id

    def _handle_audit(self, task: Task) -> dict[str, Any]:
        target_ids = list(task.inputs.get("finding_ids") or [])
        findings = [
            finding
            for finding in (self._repos.findings.get(task.run_id, fid) for fid in target_ids)
            if finding is not None
        ]
        checks, failed_ids = self._auditor.audit(task.run_id, task.id, findings)
        if checks:
            self._repos.audits.create_many(checks)

        for finding_id in failed_ids:
            finding = self._repos.findings.get(task.run_id, finding_id)
            if finding is None:
                continue
            if finding.status == FindingStatus.CONFIRMED:
                self._repos.findings.set_status(task.run_id, finding_id, FindingStatus.UNCERTAIN)
                self._event(
                    task.run_id,
                    "finding_status_changed",
                    {"finding_id": finding_id, "status": "uncertain", "source": "audit"},
                    task_id=task.id,
                )

        output = AuditOutput(
            checks=checks,
            summary=(
                f"audited {len(findings)} finding(s): "
                f"{sum(1 for check in checks if not check.passed)} failed check(s)"
            ),
        )
        return output.model_dump(mode="json")


    def _handle_report(self, task: Task) -> dict[str, Any]:
        run = self._repos.runs.get(task.run_id)
        if run is None:
            raise ProtocolError("run disappeared")

        findings = self._repos.findings.list_by_run(task.run_id)
        reviews = self._repos.reviews.list_by_run(task.run_id)
        audits = self._repos.audits.list_by_run(task.run_id)
        evidence = self._repos.evidence.list_by_run(task.run_id)
        calls = self._repos.llm_calls.list_by_run(task.run_id)
        tasks = self._repos.tasks.list_by_run(task.run_id)
        events = self._repos.events.list_by_run(task.run_id)

        confirmed = sum(1 for finding in findings if finding.status == FindingStatus.CONFIRMED)
        uncertain = sum(1 for finding in findings if finding.status == FindingStatus.UNCERTAIN)
        rejected = sum(
            1
            for finding in findings
            if finding.status in {FindingStatus.REJECTED, FindingStatus.DUPLICATE}
        )
        failed = sum(1 for item in tasks if item.status == TaskStatus.FAILED)
        skipped = sum(1 for item in tasks if item.status == TaskStatus.SKIPPED)
        summary = (
            f"本次对目标 {self._target} 的安全评估共形成 {len(findings)} 项发现："
            f"已确认 {confirmed} 项，待核实 {uncertain} 项，已排除 {rejected} 项。"
        )
        if failed or skipped:
            summary += (
                f" 执行过程中有 {failed} 个任务失败、{skipped} 个任务因预算或依赖原因跳过，"
                "分析完整性需结合任务记录判断。"
            )
        else:
            summary += " 所有调度任务均已完成。"

        final_tasks = [
            item.model_copy(update={"status": TaskStatus.DONE}) if item.id == task.id else item
            for item in tasks
        ]
        final_status = self._projected_status(final_tasks)
        stats = compute_stats(final_tasks, evidence, findings, calls)
        projected_run = run.model_copy(
            update={
                "status": final_status,
                "stats": stats,
                "finished_at": utcnow(),
            }
        )
        report_dir = build_report(
            self._artifacts_root,
            projected_run,
            final_tasks,
            evidence,
            findings,
            reviews,
            audits,
            calls,
            events,
            summary,
        )
        self._event(
            task.run_id,
            "report_written",
            {
                "report_dir": str(report_dir),
                "summary_generated": True,
                "generator": "deterministic",
            },
            task_id=task.id,
        )
        return {
            "report_dir": str(report_dir),
            "summary_generated": True,
            "generator": "deterministic",
            "findings": len(findings),
            "evidence": len(evidence),
        }

    def _call_agent(self, agent, task: Task, context: dict[str, Any]):
        assert self._budget is not None
        settings, gateway = self._registry.resolve(task.role)
        caller = LLMCaller(
            run_id=task.run_id,
            task_id=task.id,
            role=task.role,
            settings=settings,
            gateway=gateway,
            llm_calls=self._repos.llm_calls,
            messages=self._repos.messages,
        )
        cap = self._budget.output_token_cap(settings.max_output_tokens, task.budget)
        return agent.run(caller, task, context, cap)

    def _context(
        self, task: Task, findings_override: list[Finding] | None = None
    ) -> dict[str, Any]:
        self._flush_oast(task.run_id)
        evidence = self._repos.evidence.list_by_run(task.run_id)
        selected, excerpts, evidence_stats = compress_evidence(
            evidence,
            self._body_excerpt,
            max_items=MAX_CONTEXT_EVIDENCE,
            max_total_excerpt_chars=self._context_char_budget(task),
        )
        findings = (
            findings_override
            if findings_override is not None
            else self._repos.findings.list_by_run(task.run_id)
        )
        tasks = self._repos.tasks.list_by_run(task.run_id)
        failed_tasks, failed_omitted = compress_list(
            [
                {"kind": item.kind.value, "objective": item.objective, "error": item.error}
                for item in tasks
                if item.status == TaskStatus.FAILED
            ],
            MAX_CONTEXT_TASKS,
        )
        skipped_tasks, skipped_omitted = compress_list(
            [
                {"kind": item.kind.value, "objective": item.objective, "error": item.error}
                for item in tasks
                if item.status == TaskStatus.SKIPPED
            ],
            MAX_CONTEXT_TASKS,
        )
        return {
            "target": self._target,
            "run_id": task.run_id,
            "scope": self._guard.snapshot(),
            "evidence": [
                EvidenceSummary(
                    id=item.id,
                    kind=item.kind,
                    source_url=item.source_url,
                    method=item.method,
                    summary=item.summary,
                    in_scope=item.in_scope,
                    content_hash=item.content_hash,
                    body_excerpt=excerpts.get(item.id, ""),
                ).model_dump(mode="json")
                for item in selected
            ],
            "findings": [
                self._finding_summary(finding).model_dump(mode="json")
                for finding in findings
            ],
            "failed_tasks": failed_tasks,
            "skipped_tasks": skipped_tasks,
            "context_compression": {
                "budget_chars": evidence_stats.budget_chars,
                "budget_pressure": evidence_stats.truncated > 0
                or (evidence_stats.omitted - evidence_stats.deduplicated) > 0,
                "evidence_available": evidence_stats.available,
                "evidence_included": evidence_stats.included,
                "evidence_omitted": evidence_stats.omitted,
                "evidence_deduplicated": evidence_stats.deduplicated,
                "excerpts_truncated": evidence_stats.truncated,
                "excerpt_chars": evidence_stats.excerpt_chars,
                "failed_tasks_omitted": failed_omitted,
                "skipped_tasks_omitted": skipped_omitted,
            },
            "max_replans": self._run_budget.max_replans,
            "external_tools": self._external_tools_context(),
            "cross_run_knowledge": self._knowledge_context(),
            "supervisor_guidance": (
                task.inputs.get("supervisor_directive")
                if isinstance(task.inputs.get("supervisor_directive"), dict)
                else self._current_supervisor_directive(task.inputs.get("pentester_slot"))
            ),
            "worker_roster": self._worker_roster_context(
                tasks,
                task.inputs.get("pentester_slot") if isinstance(task.inputs.get("pentester_slot"), int) else None,
            ),
            "oast_callback_url": self._oast.url if self._oast_started else None,
        }

    def _current_supervisor_directive(self, slot: Any) -> dict[str, Any]:
        if not isinstance(slot, int):
            return {}
        with self._supervisor_lock:
            return dict(self._supervisor_directives.get(slot, {}))

    def _knowledge_context(self) -> list[dict[str, str]]:
        entries = []
        for entry in self._knowledge_loaded[-20:]:
            if not isinstance(entry, dict):
                continue
            entries.append(
                {
                    "kind": str(entry.get("kind", "finding")),
                    "title": str(entry.get("title", ""))[:200],
                    "detail": str(entry.get("detail", ""))[:400],
                    "url": str(entry.get("url", "")),
                    "source_run_id": str(entry.get("source_run_id", "")),
                }
            )
        return entries

    def _external_tools_context(self) -> list[dict[str, str]]:
        tools = getattr(self._executor, "_tools", None)
        if tools is None:
            return []
        entries = []
        for name, spec in tools.tools.items():
            if not spec.installed():
                continue
            entries.append(
                {"tool": name, "description": spec.description, "path": spec.path}
            )
        return entries

    def _context_char_budget(self, task: Task) -> int:
        settings, _ = self._registry.resolve(task.role)
        usable_tokens = max(
            1,
            settings.context_window_tokens
            - settings.max_output_tokens
            - CONTEXT_SAFETY_TOKENS,
        )
        return max(
            MIN_CONTEXT_BUDGET_CHARS,
            int(usable_tokens * CONTEXT_CHARS_PER_TOKEN * CONTEXT_BUDGET_RATIO),
        )

    def _body_excerpt(self, evidence) -> str:
        if evidence.kind == EvidenceKind.EVIDENCE_DIFF:
            try:
                payload = json.loads(
                    (self._artifacts_root / evidence.raw_path).read_text(encoding="utf-8")
                )
            except (OSError, ValueError):
                return ""
            diff = payload.get("unified_diff")
            if not isinstance(diff, str) or not diff.strip():
                return payload.get("summary", "")
            return f"[unified diff]\n{diff[:MAX_EXCERPT_CHARS]}"
        if evidence.kind == EvidenceKind.BROWSER_SESSION:
            try:
                payload = json.loads(
                    (self._artifacts_root / evidence.raw_path).read_text(encoding="utf-8")
                )
            except (OSError, ValueError):
                return ""
            result = payload.get("result") or {}
            lines = [
                f"final_url: {result.get('final_url', '')}",
                f"status: {result.get('status')}",
                f"title: {result.get('title', '')}",
                f"screenshot_b64_chars: {len(result.get('screenshot_b64', '') or '')}",
            ]
            dom = str(result.get("dom_text", ""))[:MAX_EXCERPT_CHARS]
            return "\n".join(lines) + f"\n[rendered dom text]\n{dom}"
        if evidence.kind == EvidenceKind.OAST_CALLBACK:
            try:
                payload = json.loads(
                    (self._artifacts_root / evidence.raw_path).read_text(encoding="utf-8")
                )
            except (OSError, ValueError):
                return ""
            request = str(payload.get("raw-request", ""))[:4000]
            response = str(payload.get("raw-response", ""))[:4000]
            return (
                f"[oast {payload.get('protocol', '?')} interaction]\n"
                f"remote-address: {payload.get('remote-address', '?')}\n"
                f"timestamp: {payload.get('timestamp', '?')}\n"
                f"[raw request]\n{request}\n[raw response]\n{response}"
            )
        if evidence.kind not in {EvidenceKind.HTTP_RESPONSE, EvidenceKind.ROBOTS}:
            return ""
        try:
            payload = json.loads(
                (self._artifacts_root / evidence.raw_path).read_text(encoding="utf-8")
            )
        except (OSError, ValueError):
            return ""
        response = payload.get("response") or {}
        headers = response.get("headers") or {}
        signal_lines = []
        request_info = payload.get("request") or {}
        if request_info.get("method") or request_info.get("url"):
            req_line = f"request: {request_info.get('method', '')} {request_info.get('url', '')}".strip()
            req_body = request_info.get("body")
            if isinstance(req_body, str) and req_body:
                req_line += f"\n[request body]\n{req_body[:300]}"
            signal_lines.append(req_line)
        location = headers.get("location")
        if location:
            signal_lines.append(f"location: {location}")
        set_cookie = headers.get("set-cookie")
        if set_cookie:
            signal_lines.append(f"set-cookie: {set_cookie}")
        if headers.get("www-authenticate"):
            signal_lines.append(f"www-authenticate: {headers['www-authenticate']}")
        body = response.get("body")
        body = body.strip() if isinstance(body, str) else ""
        if len(body) > MAX_EXCERPT_CHARS:
            body = body[:MAX_EXCERPT_CHARS] + "\n...[truncated]"
        header_block = "\n".join(signal_lines)
        if not header_block:
            return body
        return f"[response headers]\n{header_block}\n[body]\n{body}" if body else f"[response headers, empty body]\n{header_block}"

    def _finding_summary(self, finding: Finding) -> FindingSummary:
        return FindingSummary(
            id=finding.id,
            title=finding.title,
            category=finding.category,
            severity=finding.severity,
            confidence=finding.confidence,
            status=finding.status,
            evidence_ids=finding.evidence_ids,
            description=finding.description,
            impact=finding.impact,
            reproduction=finding.reproduction,
            remediation=finding.remediation,
        )

    def _budget_snapshot(self, run_id: str) -> BudgetSnapshot:
        tokens, cost = self._repos.llm_calls.usage(run_id)
        return BudgetSnapshot(
            tasks=self._repos.tasks.count_by_run(run_id),
            tokens=tokens,
            cost_usd=cost,
            replans=self._repos.tasks.replan_count(run_id),
        )

    def _projected_status(self, tasks: list[Task]) -> RunStatus:
        if any(task.status in {TaskStatus.FAILED, TaskStatus.SKIPPED} for task in tasks):
            return RunStatus.COMPLETED_WITH_ERRORS
        if any(task.kind == TaskKind.REPORT and task.status == TaskStatus.FAILED for task in tasks):
            return RunStatus.FAILED
        return RunStatus.COMPLETED

    def _finalize(self, run_id: str) -> Run:
        run = self._repos.runs.get(run_id)
        if run is None:
            raise RuntimeError(f"run not found: {run_id}")
        tasks = self._repos.tasks.list_by_run(run_id)
        evidence = self._repos.evidence.list_by_run(run_id)
        findings = self._repos.findings.list_by_run(run_id)
        calls = self._repos.llm_calls.list_by_run(run_id)

        added = self._record_knowledge(run_id, findings)

        run.status = self._projected_status(tasks)
        run.stats = compute_stats(tasks, evidence, findings, calls)
        run.finished_at = utcnow()
        self._repos.runs.update(run)
        self._event(
            run_id,
            "run_finished",
            {"status": run.status.value, "stats": run.stats, "knowledge_added": added},
        )
        return run

    def _record_knowledge(self, run_id: str, findings: list[Finding]) -> int:
        """Persist confirmed credentials/paths/injection points for future runs."""
        if not self._use_memory:
            return 0
        confirmed = [f for f in findings if f.status == FindingStatus.CONFIRMED]
        if not confirmed:
            return 0
        entries: list[dict[str, Any]] = []
        for finding in confirmed:
            evidence = None
            if finding.evidence_ids:
                evidence = self._repos.evidence.get(finding.evidence_ids[0])
            text = f"{finding.category} {finding.title}".lower()
            if "injection" in text:
                kind = "injection_point"
            elif any(word in text for word in ("credential", "auth", "login", "session", "password")):
                kind = "credential"
            elif any(word in text for word in ("path", "directory", "endpoint", "exposure", "file")):
                kind = "path"
            else:
                kind = "confirmed_finding"
            entries.append(
                {
                    "kind": kind,
                    "title": finding.title,
                    "detail": finding.reproduction[:500],
                    "url": evidence.source_url if evidence else "",
                    "source_run_id": run_id,
                    "evidence_hash": evidence.content_hash if evidence else "",
                }
            )
        try:
            return self._knowledge.record(self._target_host, entries)
        except OSError as exc:
            self._event(run_id, "knowledge_write_failed", {"error": str(exc)[:200]})
            return 0

    def _event(
        self, run_id: str, event_type: str, payload: dict[str, Any], task_id: str | None = None
    ) -> None:
        self._repos.events.append(
            EventRecord(run_id=run_id, task_id=task_id, type=event_type, payload=payload)
        )
