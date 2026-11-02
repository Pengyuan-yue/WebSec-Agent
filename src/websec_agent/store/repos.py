from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from uuid import uuid4

from sqlalchemy import func, select

from ..core.errors import ConcurrentModification
from ..core.schemas import (
    AuditCheckRecord,
    Budget,
    Evidence,
    EventRecord,
    Finding,
    FindingStatus,
    LLMCallRecord,
    MemoryRecord,
    MessageRecord,
    ReviewRecord,
    Role,
    Run,
    RunStatus,
    Task,
    TaskKind,
    TaskStatus,
    utcnow,
)
from .db import Database
from .models import (
    AuditCheckRow,
    EvidenceRow,
    EventRow,
    FindingRow,
    LLMCallRow,
    MemoryRow,
    MessageRow,
    ProjectRow,
    ReviewRow,
    RunProjectRow,
    RunRow,
    TaskRow,
)


def _run_from_row(row: RunRow) -> Run:
    return Run(
        id=row.id,
        target=row.target,
        status=RunStatus(row.status),
        scope_snapshot=row.scope_snapshot or {},
        budget=row.budget or {},
        stats=row.stats or {},
        started_at=row.started_at,
        finished_at=row.finished_at,
    )


def _task_from_row(row: TaskRow) -> Task:
    return Task(
        id=row.id,
        run_id=row.run_id,
        parent_id=row.parent_id,
        kind=TaskKind(row.kind),
        role=Role(row.role),
        objective=row.objective,
        inputs=row.inputs or {},
        depends_on=row.depends_on or [],
        status=TaskStatus(row.status),
        priority=row.priority,
        budget=Budget.model_validate(row.budget or {}),
        attempts=row.attempts,
        version=row.version,
        result=row.result,
        error=row.error,
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


def _evidence_from_row(row: EvidenceRow) -> Evidence:
    return Evidence(
        id=row.id,
        run_id=row.run_id,
        task_id=row.task_id,
        kind=row.kind,
        source_url=row.source_url,
        method=row.method,
        collected_at=row.collected_at,
        content_hash=row.content_hash,
        raw_path=row.raw_path,
        summary=row.summary,
        derived_from=row.derived_from or [],
        in_scope=row.in_scope,
        size_bytes=row.size_bytes,
    )


def _finding_from_row(row: FindingRow) -> Finding:
    return Finding(
        id=row.id,
        run_id=row.run_id,
        task_id=row.task_id,
        title=row.title,
        category=row.category,
        severity=row.severity,
        confidence=row.confidence,
        description=row.description,
        impact=row.impact,
        evidence_ids=row.evidence_ids or [],
        reproduction=row.reproduction,
        remediation=row.remediation,
        status=FindingStatus(row.status),
        created_by=Role(row.created_by),
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


def _review_from_row(row: ReviewRow) -> ReviewRecord:
    return ReviewRecord(
        id=row.id,
        run_id=row.run_id,
        task_id=row.task_id,
        finding_id=row.finding_id,
        verdict=row.verdict,
        rationale=row.rationale,
        cited_evidence_ids=row.cited_evidence_ids or [],
        missing_evidence=row.missing_evidence or [],
        created_at=row.created_at,
    )


def _audit_from_row(row: AuditCheckRow) -> AuditCheckRecord:
    return AuditCheckRecord(
        id=row.id,
        run_id=row.run_id,
        task_id=row.task_id,
        finding_id=row.finding_id,
        check=row.check,
        passed=row.passed,
        detail=row.detail,
        created_at=row.created_at,
    )


class RunRepository:
    def __init__(self, db: Database) -> None:
        self.db = db

    def create(self, run: Run) -> Run:
        with self.db.session() as session:
            session.add(
                RunRow(
                    id=run.id,
                    target=run.target,
                    status=run.status.value,
                    scope_snapshot=run.scope_snapshot,
                    budget=run.budget,
                    stats=run.stats,
                    started_at=run.started_at,
                    finished_at=run.finished_at,
                )
            )
        return run

    def get(self, run_id: str) -> Run | None:
        with self.db.session() as session:
            row = session.get(RunRow, run_id)
            return _run_from_row(row) if row else None

    def list_all(self) -> list[Run]:
        with self.db.session() as session:
            rows = session.execute(select(RunRow).order_by(RunRow.started_at)).scalars().all()
            return [_run_from_row(row) for row in rows]

    def update(self, run: Run) -> Run:
        with self.db.session() as session:
            row = session.get(RunRow, run.id)
            if row is None:
                raise KeyError(f"run not found: {run.id}")
            row.status = run.status.value
            row.stats = run.stats
            row.finished_at = run.finished_at
        return run


class TaskRepository:
    def __init__(self, db: Database) -> None:
        self.db = db

    def create(self, task: Task) -> Task:
        with self.db.session() as session:
            session.add(
                TaskRow(
                    id=task.id,
                    run_id=task.run_id,
                    parent_id=task.parent_id,
                    kind=task.kind.value,
                    role=task.role.value,
                    objective=task.objective,
                    inputs=task.inputs,
                    depends_on=task.depends_on,
                    status=task.status.value,
                    priority=task.priority,
                    budget=task.budget.model_dump(),
                    attempts=task.attempts,
                    version=task.version,
                    result=task.result,
                    error=task.error,
                    created_at=task.created_at,
                    updated_at=task.updated_at,
                )
            )
        return task

    def get(self, task_id: str) -> Task | None:
        with self.db.session() as session:
            row = session.get(TaskRow, task_id)
            return _task_from_row(row) if row else None

    def update(self, task: Task) -> Task:
        with self.db.session() as session:
            row = session.get(TaskRow, task.id)
            if row is None:
                raise KeyError(f"task not found: {task.id}")
            if row.version != task.version:
                raise ConcurrentModification(
                    f"task {task.id} version conflict: db={row.version} expected={task.version}"
                )
            row.status = task.status.value
            row.objective = task.objective
            row.priority = task.priority
            row.inputs = task.inputs
            row.depends_on = task.depends_on
            row.budget = task.budget.model_dump()
            row.attempts = task.attempts
            row.result = task.result
            row.error = task.error
            row.version = task.version + 1
            task.version += 1
            task.updated_at = utcnow()
        return task

    def list_by_run(self, run_id: str) -> list[Task]:
        with self.db.session() as session:
            rows = session.scalars(
                select(TaskRow)
                .where(TaskRow.run_id == run_id)
                .order_by(TaskRow.created_at, TaskRow.id)
            ).all()
            return [_task_from_row(row) for row in rows]

    def list_by_status(self, run_id: str, status: TaskStatus) -> list[Task]:
        with self.db.session() as session:
            rows = session.scalars(
                select(TaskRow)
                .where(TaskRow.run_id == run_id, TaskRow.status == status.value)
                .order_by(TaskRow.priority.desc(), TaskRow.created_at)
            ).all()
            return [_task_from_row(row) for row in rows]

    def count_by_run(self, run_id: str) -> int:
        with self.db.session() as session:
            return int(
                session.scalar(
                    select(func.count()).select_from(TaskRow).where(TaskRow.run_id == run_id)
                )
                or 0
            )

    def replan_count(self, run_id: str) -> int:
        with self.db.session() as session:
            rows = session.scalars(select(TaskRow).where(TaskRow.run_id == run_id)).all()
            return sum(1 for row in rows if (row.inputs or {}).get("followup") is True)


class EvidenceRepository:
    def __init__(self, db: Database) -> None:
        self.db = db

    def create(self, evidence: Evidence) -> Evidence:
        with self.db.session() as session:
            session.add(
                EvidenceRow(
                    id=evidence.id,
                    run_id=evidence.run_id,
                    task_id=evidence.task_id,
                    kind=evidence.kind.value,
                    source_url=evidence.source_url,
                    method=evidence.method,
                    collected_at=evidence.collected_at,
                    content_hash=evidence.content_hash,
                    raw_path=evidence.raw_path,
                    summary=evidence.summary,
                    derived_from=evidence.derived_from,
                    in_scope=evidence.in_scope,
                    size_bytes=evidence.size_bytes,
                )
            )
        return evidence

    def get(self, evidence_id: str) -> Evidence | None:
        with self.db.session() as session:
            row = session.get(EvidenceRow, evidence_id)
            return _evidence_from_row(row) if row else None

    def list_by_run(self, run_id: str, limit: int | None = None) -> list[Evidence]:
        with self.db.session() as session:
            stmt = (
                select(EvidenceRow)
                .where(EvidenceRow.run_id == run_id)
                .order_by(EvidenceRow.collected_at, EvidenceRow.id)
            )
            if limit is not None:
                stmt = stmt.limit(limit)
            rows = session.scalars(stmt).all()
            return [_evidence_from_row(row) for row in rows]

    def list_by_ids(self, run_id: str, evidence_ids: list[str]) -> list[Evidence]:
        if not evidence_ids:
            return []
        with self.db.session() as session:
            rows = session.scalars(
                select(EvidenceRow).where(
                    EvidenceRow.run_id == run_id, EvidenceRow.id.in_(evidence_ids)
                )
            ).all()
            return [_evidence_from_row(row) for row in rows]

    def count_by_run(self, run_id: str) -> int:
        with self.db.session() as session:
            return int(
                session.scalar(
                    select(func.count()).select_from(EvidenceRow).where(EvidenceRow.run_id == run_id)
                )
                or 0
            )


class FindingRepository:
    def __init__(self, db: Database) -> None:
        self.db = db

    def create(self, finding: Finding) -> Finding:
        with self.db.session() as session:
            session.add(
                FindingRow(
                    id=finding.id,
                    run_id=finding.run_id,
                    task_id=finding.task_id,
                    title=finding.title,
                    category=finding.category,
                    severity=finding.severity.value,
                    confidence=finding.confidence,
                    description=finding.description,
                    impact=finding.impact,
                    evidence_ids=finding.evidence_ids,
                    reproduction=finding.reproduction,
                    remediation=finding.remediation,
                    status=finding.status.value,
                    created_by=finding.created_by.value,
                    created_at=finding.created_at,
                    updated_at=finding.updated_at,
                )
            )
        return finding

    def get(self, run_id: str, finding_id: str) -> Finding | None:
        with self.db.session() as session:
            row = session.scalar(
                select(FindingRow).where(FindingRow.run_id == run_id, FindingRow.id == finding_id)
            )
            return _finding_from_row(row) if row else None

    def list_by_run(self, run_id: str, status: FindingStatus | None = None) -> list[Finding]:
        with self.db.session() as session:
            stmt = select(FindingRow).where(FindingRow.run_id == run_id)
            if status is not None:
                stmt = stmt.where(FindingRow.status == status.value)
            rows = session.scalars(stmt.order_by(FindingRow.created_at, FindingRow.id)).all()
            return [_finding_from_row(row) for row in rows]

    def update(self, finding: Finding) -> Finding:
        with self.db.session() as session:
            row = session.get(FindingRow, finding.id)
            if row is None:
                raise KeyError(f"finding not found: {finding.id}")
            row.status = finding.status.value
            row.severity = finding.severity.value
            row.confidence = finding.confidence
            row.description = finding.description
            row.impact = finding.impact
            row.reproduction = finding.reproduction
            row.remediation = finding.remediation
            row.evidence_ids = finding.evidence_ids
            row.updated_at = utcnow()
            finding.updated_at = row.updated_at
        return finding

    def set_status(self, run_id: str, finding_id: str, status: FindingStatus) -> Finding:
        finding = self.get(run_id, finding_id)
        if finding is None:
            raise KeyError(f"finding not found: {finding_id}")
        finding.status = status
        return self.update(finding)


class ReviewRepository:
    def __init__(self, db: Database) -> None:
        self.db = db

    def create(self, review: ReviewRecord) -> ReviewRecord:
        with self.db.session() as session:
            session.add(
                ReviewRow(
                    id=review.id,
                    run_id=review.run_id,
                    task_id=review.task_id,
                    finding_id=review.finding_id,
                    verdict=review.verdict.value,
                    rationale=review.rationale,
                    cited_evidence_ids=review.cited_evidence_ids,
                    missing_evidence=review.missing_evidence,
                    created_at=review.created_at,
                )
            )
        return review

    def list_by_run(self, run_id: str) -> list[ReviewRecord]:
        with self.db.session() as session:
            rows = session.scalars(
                select(ReviewRow).where(ReviewRow.run_id == run_id).order_by(ReviewRow.created_at)
            ).all()
            return [_review_from_row(row) for row in rows]

    def list_for_finding(self, run_id: str, finding_id: str) -> list[ReviewRecord]:
        with self.db.session() as session:
            rows = session.scalars(
                select(ReviewRow).where(
                    ReviewRow.run_id == run_id, ReviewRow.finding_id == finding_id
                )
            ).all()
            return [_review_from_row(row) for row in rows]

    def reviewed_finding_ids(self, run_id: str) -> set[str]:
        with self.db.session() as session:
            rows = session.scalars(select(ReviewRow.finding_id).where(ReviewRow.run_id == run_id)).all()
            return set(rows)


class AuditRepository:
    def __init__(self, db: Database) -> None:
        self.db = db

    def create_many(self, checks: list[AuditCheckRecord]) -> list[AuditCheckRecord]:
        with self.db.session() as session:
            for check in checks:
                session.add(
                    AuditCheckRow(
                        id=check.id,
                        run_id=check.run_id,
                        task_id=check.task_id,
                        finding_id=check.finding_id,
                        check=check.check,
                        passed=check.passed,
                        detail=check.detail,
                        created_at=check.created_at,
                    )
                )
        return checks

    def list_by_run(self, run_id: str) -> list[AuditCheckRecord]:
        with self.db.session() as session:
            rows = session.scalars(
                select(AuditCheckRow)
                .where(AuditCheckRow.run_id == run_id)
                .order_by(AuditCheckRow.created_at, AuditCheckRow.id)
            ).all()
            return [_audit_from_row(row) for row in rows]

    def audited_finding_ids(self, run_id: str) -> set[str]:
        with self.db.session() as session:
            rows = session.scalars(
                select(AuditCheckRow.finding_id).where(AuditCheckRow.run_id == run_id)
            ).all()
            return set(rows)


class MessageRepository:
    def __init__(self, db: Database) -> None:
        self.db = db

    def create(self, message: MessageRecord) -> MessageRecord:
        with self.db.session() as session:
            session.add(
                MessageRow(
                    id=message.id,
                    run_id=message.run_id,
                    task_id=message.task_id,
                    role=message.role.value,
                    direction=message.direction,
                    content=message.content,
                    created_at=message.created_at,
                )
            )
        return message

    def list_for_task(self, task_id: str) -> list[MessageRecord]:
        with self.db.session() as session:
            rows = session.scalars(
                select(MessageRow).where(MessageRow.task_id == task_id).order_by(MessageRow.created_at)
            ).all()
            return [
                MessageRecord(
                    id=row.id,
                    run_id=row.run_id,
                    task_id=row.task_id,
                    role=Role(row.role),
                    direction=row.direction,
                    content=row.content,
                    created_at=row.created_at,
                )
                for row in rows
            ]


class LLMCallRepository:
    def __init__(self, db: Database) -> None:
        self.db = db

    def create(self, call: LLMCallRecord) -> LLMCallRecord:
        with self.db.session() as session:
            session.add(
                LLMCallRow(
                    id=call.id,
                    run_id=call.run_id,
                    task_id=call.task_id,
                    role=call.role.value,
                    provider=call.provider,
                    model=call.model,
                    tokens_in=call.tokens_in,
                    tokens_out=call.tokens_out,
                    cost_usd=call.cost_usd,
                    latency_ms=call.latency_ms,
                    created_at=call.created_at,
                )
            )
        return call

    def usage(self, run_id: str) -> tuple[int, float]:
        with self.db.session() as session:
            tokens_in = session.scalar(
                select(func.coalesce(func.sum(LLMCallRow.tokens_in), 0)).where(
                    LLMCallRow.run_id == run_id
                )
            )
            tokens_out = session.scalar(
                select(func.coalesce(func.sum(LLMCallRow.tokens_out), 0)).where(
                    LLMCallRow.run_id == run_id
                )
            )
            cost = session.scalar(
                select(func.coalesce(func.sum(LLMCallRow.cost_usd), 0.0)).where(
                    LLMCallRow.run_id == run_id
                )
            )
            return int(tokens_in or 0) + int(tokens_out or 0), float(cost or 0.0)

    def list_by_run(self, run_id: str) -> list[LLMCallRecord]:
        with self.db.session() as session:
            rows = session.scalars(
                select(LLMCallRow).where(LLMCallRow.run_id == run_id).order_by(LLMCallRow.created_at)
            ).all()
            return [
                LLMCallRecord(
                    id=row.id,
                    run_id=row.run_id,
                    task_id=row.task_id,
                    role=Role(row.role),
                    provider=row.provider,
                    model=row.model,
                    tokens_in=row.tokens_in,
                    tokens_out=row.tokens_out,
                    cost_usd=row.cost_usd,
                    latency_ms=row.latency_ms,
                    created_at=row.created_at,
                )
                for row in rows
            ]


class EventRepository:
    """Append-only: no update/delete API is exposed."""

    def __init__(self, db: Database) -> None:
        self.db = db

    def append(self, event: EventRecord) -> EventRecord:
        with self.db.session() as session:
            session.add(
                EventRow(
                    id=event.id,
                    run_id=event.run_id,
                    task_id=event.task_id,
                    type=event.type,
                    payload=event.payload,
                    created_at=event.created_at,
                )
            )
        return event

    def list_by_run(self, run_id: str) -> list[EventRecord]:
        with self.db.session() as session:
            rows = session.scalars(
                select(EventRow).where(EventRow.run_id == run_id).order_by(EventRow.created_at, EventRow.id)
            ).all()
            return [
                EventRecord(
                    id=row.id,
                    run_id=row.run_id,
                    task_id=row.task_id,
                    type=row.type,
                    payload=row.payload or {},
                    created_at=row.created_at,
                )
                for row in rows
            ]


class MemoryRepository:
    def __init__(self, db: Database) -> None:
        self.db = db

    def create(self, memory: MemoryRecord) -> MemoryRecord:
        with self.db.session() as session:
            session.add(
                MemoryRow(
                    id=memory.id,
                    run_id=memory.run_id,
                    scope=memory.scope,
                    target=memory.target,
                    key=memory.key,
                    content=memory.content,
                    embedding=memory.embedding,
                    created_at=memory.created_at,
                )
            )
        return memory

    def list_by_target(self, target: str) -> list[MemoryRecord]:
        with self.db.session() as session:
            rows = session.scalars(
                select(MemoryRow).where(MemoryRow.target == target).order_by(MemoryRow.created_at)
            ).all()
            return [
                MemoryRecord(
                    id=row.id,
                    run_id=row.run_id,
                    scope=row.scope,
                    target=row.target,
                    key=row.key,
                    content=row.content,
                    embedding=row.embedding,
                    created_at=row.created_at,
                )
                for row in rows
            ]


@dataclass
class ProjectRecord:
    id: str
    name: str
    urls: list[str]
    created_at: datetime
    updated_at: datetime

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "urls": list(self.urls),
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }


def _project_from_row(row: ProjectRow) -> ProjectRecord:
    return ProjectRecord(
        id=row.id,
        name=row.name,
        urls=[str(u) for u in (row.urls or [])],
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


class ProjectRepository:
    """Projects group many target URLs under one named engagement."""

    def __init__(self, db: Database) -> None:
        self.db = db

    def create(self, name: str, urls: list[str]) -> ProjectRecord:
        now = utcnow()
        record = ProjectRecord(
            id=uuid4().hex[:16], name=name, urls=list(urls), created_at=now, updated_at=now
        )
        with self.db.session() as session:
            session.add(
                ProjectRow(
                    id=record.id,
                    name=record.name,
                    urls=record.urls,
                    created_at=now,
                    updated_at=now,
                )
            )
        return record

    def list_all(self) -> list[ProjectRecord]:
        with self.db.session() as session:
            rows = session.scalars(
                select(ProjectRow).order_by(ProjectRow.created_at)
            ).all()
            return [_project_from_row(row) for row in rows]

    def get(self, project_id: str) -> ProjectRecord | None:
        with self.db.session() as session:
            row = session.get(ProjectRow, project_id)
            return _project_from_row(row) if row else None

    def update(
        self, project_id: str, name: str | None = None, urls: list[str] | None = None
    ) -> ProjectRecord | None:
        with self.db.session() as session:
            row = session.get(ProjectRow, project_id)
            if row is None:
                return None
            if name is not None:
                row.name = name
            if urls is not None:
                row.urls = list(urls)
            row.updated_at = utcnow()
            session.flush()
            return _project_from_row(row)

    def delete(self, project_id: str) -> bool:
        with self.db.session() as session:
            row = session.get(ProjectRow, project_id)
            if row is None:
                return False
            session.delete(row)
            for mapping in session.scalars(
                select(RunProjectRow).where(RunProjectRow.project_id == project_id)
            ).all():
                session.delete(mapping)
        return True

    def attach_run(self, run_id: str, project_id: str) -> None:
        with self.db.session() as session:
            existing = session.get(RunProjectRow, run_id)
            if existing is None:
                session.add(RunProjectRow(run_id=run_id, project_id=project_id))
            else:
                existing.project_id = project_id

    def project_for_run(self, run_id: str) -> str | None:
        with self.db.session() as session:
            row = session.get(RunProjectRow, run_id)
            return row.project_id if row else None

    def run_map(self) -> dict[str, str]:
        with self.db.session() as session:
            rows = session.scalars(select(RunProjectRow)).all()
            return {row.run_id: row.project_id for row in rows}


@dataclass
class Repositories:
    runs: RunRepository
    tasks: TaskRepository
    evidence: EvidenceRepository
    findings: FindingRepository
    reviews: ReviewRepository
    audits: AuditRepository
    messages: MessageRepository
    llm_calls: LLMCallRepository
    events: EventRepository
    memories: MemoryRepository
    projects: ProjectRepository

    @classmethod
    def build(cls, db: Database) -> "Repositories":
        return cls(
            runs=RunRepository(db),
            tasks=TaskRepository(db),
            evidence=EvidenceRepository(db),
            findings=FindingRepository(db),
            reviews=ReviewRepository(db),
            audits=AuditRepository(db),
            messages=MessageRepository(db),
            llm_calls=LLMCallRepository(db),
            events=EventRepository(db),
            memories=MemoryRepository(db),
            projects=ProjectRepository(db),
        )
