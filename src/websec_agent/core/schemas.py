from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def new_id() -> str:
    return uuid4().hex


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class TaskKind(str, Enum):
    PLAN = "plan"
    SUPERVISE = "supervise"
    RECON = "recon"
    ANALYZE = "analyze"
    EXPLOIT = "exploit"
    VALIDATE = "validate"
    REVIEW = "review"
    AUDIT = "audit"
    REPORT = "report"


class Role(str, Enum):
    # SYSTEM handles deterministic harness tasks (audit/report) without an LLM.
    SYSTEM = "system"
    PENTESTER = "pentester"
    SUPERVISOR = "supervisor"

    # Retained so historical database rows remain readable.
    PLANNER = "planner"
    REVIEWER = "reviewer"
    AUDITOR = "auditor"
    REPORTER = "reporter"


class TaskStatus(str, Enum):
    PENDING = "pending"
    READY = "ready"
    RUNNING = "running"
    WAITING = "waiting"
    DONE = "done"
    FAILED = "failed"
    SKIPPED = "skipped"


TERMINAL_STATUSES = {TaskStatus.DONE, TaskStatus.FAILED, TaskStatus.SKIPPED}


class RunStatus(str, Enum):
    RUNNING = "running"
    COMPLETED = "completed"
    COMPLETED_WITH_ERRORS = "completed_with_errors"
    FAILED = "failed"


class EvidenceKind(str, Enum):
    HTTP_RESPONSE = "http_response"
    TLS_CERT = "tls_cert"
    DNS = "dns"
    ROBOTS = "robots"
    EVIDENCE_DIFF = "evidence_diff"
    HEADER_SET = "header_set"
    ZAP_ALERT = "zap_alert"
    EXPLOIT_ATTEMPT = "exploit_attempt"
    COMMAND_OUTPUT = "command_output"
    OAST_CALLBACK = "oast_callback"
    POC_SCRIPT = "poc_script"
    BROWSER_SESSION = "browser_session"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingStatus(str, Enum):
    PROPOSED = "proposed"
    CONFIRMED = "confirmed"
    REJECTED = "rejected"
    UNCERTAIN = "uncertain"
    DUPLICATE = "duplicate"


class ReviewVerdictValue(str, Enum):
    CONFIRM = "confirm"
    REJECT = "reject"
    NEEDS_EVIDENCE = "needs_evidence"


class ToolName(str, Enum):
    HTTP_REQUEST = "http_request"
    TLS_PROBE = "tls_probe"
    DNS_LOOKUP = "dns_lookup"
    ROBOTS = "robots"
    EVIDENCE_DIFF = "evidence_diff"
    EXTERNAL_TOOL = "external_tool"
    BROWSER = "browser"


# ---------------------------------------------------------------------------
# Task / run
# ---------------------------------------------------------------------------


class Budget(StrictModel):
    max_tokens: int = Field(default=0, ge=0, description="0 = unlimited")
    max_tool_calls: int = Field(default=0, ge=0, description="0 = unlimited")
    max_cost_usd: float = Field(default=0, ge=0, description="0 = unlimited")


class Task(StrictModel):
    id: str = Field(default_factory=new_id)
    run_id: str
    parent_id: str | None = None
    kind: TaskKind
    role: Role
    objective: str = Field(min_length=1)
    inputs: dict[str, Any] = Field(default_factory=dict)
    depends_on: list[str] = Field(default_factory=list)
    status: TaskStatus = TaskStatus.PENDING
    priority: int = Field(default=50, ge=0, le=100)
    budget: Budget = Field(default_factory=Budget)
    attempts: int = Field(default=0, ge=0)
    version: int = Field(default=0, ge=0)
    result: dict[str, Any] | None = None
    error: str | None = None
    created_at: datetime = Field(default_factory=utcnow)
    updated_at: datetime = Field(default_factory=utcnow)


class Run(StrictModel):
    id: str = Field(default_factory=new_id)
    target: str
    status: RunStatus = RunStatus.RUNNING
    scope_snapshot: dict[str, Any] = Field(default_factory=dict)
    budget: dict[str, Any] = Field(default_factory=dict)
    stats: dict[str, Any] = Field(default_factory=dict)
    started_at: datetime = Field(default_factory=utcnow)
    finished_at: datetime | None = None


# ---------------------------------------------------------------------------
# Evidence / findings / reviews
# ---------------------------------------------------------------------------


class Evidence(StrictModel):
    id: str = Field(default_factory=new_id)
    run_id: str
    task_id: str | None = None
    kind: EvidenceKind
    source_url: str
    method: str = ""
    collected_at: datetime = Field(default_factory=utcnow)
    content_hash: str
    raw_path: str
    summary: str
    derived_from: list[str] = Field(default_factory=list)
    in_scope: bool = True
    size_bytes: int = Field(default=0, ge=0)


class Finding(StrictModel):
    id: str = Field(default_factory=new_id)
    run_id: str
    task_id: str | None = None
    title: str = Field(min_length=1)
    category: str = Field(min_length=1)
    severity: Severity
    confidence: int = Field(default=50, ge=0, le=100)
    description: str = Field(min_length=1)
    impact: str = Field(min_length=1)
    evidence_ids: list[str] = Field(min_length=1)
    reproduction: str = Field(min_length=1)
    remediation: str = Field(min_length=1)
    status: FindingStatus = FindingStatus.PROPOSED
    created_by: Role
    created_at: datetime = Field(default_factory=utcnow)
    updated_at: datetime = Field(default_factory=utcnow)


class ProposedFinding(StrictModel):
    title: str = Field(min_length=1)
    category: str = Field(min_length=1)
    severity: Severity
    confidence: int = Field(default=50, ge=0, le=100)
    description: str = Field(min_length=1)
    impact: str = Field(min_length=1)
    evidence_ids: list[str] = Field(min_length=1)
    reproduction: str = Field(min_length=1)
    remediation: str = Field(min_length=1)


class ReviewRecord(StrictModel):
    id: str = Field(default_factory=new_id)
    run_id: str
    task_id: str
    finding_id: str
    verdict: ReviewVerdictValue
    rationale: str
    cited_evidence_ids: list[str] = Field(default_factory=list)
    missing_evidence: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=utcnow)


class AuditCheckRecord(StrictModel):
    id: str = Field(default_factory=new_id)
    run_id: str
    task_id: str
    finding_id: str
    check: str
    passed: bool
    detail: str
    created_at: datetime = Field(default_factory=utcnow)


# ---------------------------------------------------------------------------
# Tools / agent outputs (ws-result/v1 payloads)
# ---------------------------------------------------------------------------


class ToolRequest(StrictModel):
    tool: ToolName
    params: dict[str, Any] = Field(default_factory=dict)
    reason: str = ""


class PlannedTask(StrictModel):
    key: str = Field(min_length=1)
    kind: TaskKind
    role: Role
    objective: str = Field(min_length=1)
    inputs: dict[str, Any] = Field(default_factory=dict)
    depends_on: list[str] = Field(default_factory=list)
    priority: int = Field(default=50, ge=0, le=100)
    budget: Budget = Field(default_factory=Budget)


class PlanOutput(StrictModel):
    rationale: str = Field(max_length=800)
    tasks: list[PlannedTask] = Field(default_factory=list, max_length=24)


class PentesterOutput(StrictModel):
    summary: str
    findings: list[ProposedFinding] = Field(default_factory=list)
    tool_requests: list[ToolRequest] = Field(default_factory=list)
    notes: str = ""


class SupervisorDirective(StrictModel):
    slot: int = Field(ge=1, le=4)
    focus: list[str] = Field(default_factory=list, max_length=5)
    avoid: list[str] = Field(default_factory=list, max_length=5)
    guidance: str = Field(default="", max_length=600)


class SupervisorOutput(StrictModel):
    summary: str = Field(max_length=800)
    assignments: list[SupervisorDirective] = Field(default_factory=list, max_length=4)
    overlap_warnings: list[str] = Field(default_factory=list, max_length=8)


class ReviewVerdictItem(StrictModel):
    finding_id: str = Field(min_length=1)
    verdict: ReviewVerdictValue
    rationale: str
    cited_evidence_ids: list[str] = Field(default_factory=list)
    missing_evidence: list[str] = Field(default_factory=list)


class ReviewOutput(StrictModel):
    verdicts: list[ReviewVerdictItem]
    notes: str = ""


class AuditOutput(StrictModel):
    checks: list[AuditCheckRecord] = Field(default_factory=list)
    summary: str = ""


class ReportOutput(StrictModel):
    summary_markdown: str = Field(min_length=1)


AgentOutput = PlanOutput | PentesterOutput | ReviewOutput | AuditOutput | ReportOutput


# ---------------------------------------------------------------------------
# Wire envelopes
# ---------------------------------------------------------------------------


class TaskEnvelope(StrictModel):
    v: Literal["ws-task/v1"] = "ws-task/v1"
    task_id: str
    run_id: str
    kind: TaskKind
    role: Role
    objective: str
    inputs: dict[str, Any] = Field(default_factory=dict)
    budget: Budget = Field(default_factory=Budget)
    context: dict[str, Any] = Field(default_factory=dict)


class ResultEnvelope(StrictModel):
    v: Literal["ws-result/v1"] = "ws-result/v1"
    task_id: str
    run_id: str
    status: Literal["ok", "failed"]
    output: dict[str, Any] = Field(default_factory=dict)
    error: str | None = None


# ---------------------------------------------------------------------------
# Auxiliary records
# ---------------------------------------------------------------------------


class ChatMessage(StrictModel):
    role: Literal["system", "user", "assistant"]
    content: str


class MessageRecord(StrictModel):
    id: str = Field(default_factory=new_id)
    run_id: str
    task_id: str
    role: Role
    direction: Literal["prompt", "response", "retry"]
    content: str
    created_at: datetime = Field(default_factory=utcnow)


class LLMCallRecord(StrictModel):
    id: str = Field(default_factory=new_id)
    run_id: str
    task_id: str
    role: Role
    provider: str
    model: str
    tokens_in: int = 0
    tokens_out: int = 0
    cost_usd: float = 0.0
    latency_ms: int = 0
    created_at: datetime = Field(default_factory=utcnow)


class EventRecord(StrictModel):
    id: str = Field(default_factory=new_id)
    run_id: str
    task_id: str | None = None
    type: str
    payload: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=utcnow)


class MemoryRecord(StrictModel):
    id: str = Field(default_factory=new_id)
    run_id: str | None = None
    scope: Literal["global", "target"] = "target"
    target: str | None = None
    key: str
    content: str
    embedding: list[float] | None = None
    created_at: datetime = Field(default_factory=utcnow)


class RunBudget(StrictModel):
    max_cost_usd: float = Field(default=0, ge=0)
    max_total_tokens: int = Field(default=0, ge=0)
    max_tasks: int = Field(default=0, ge=0)
    max_replans: int = Field(default=2, ge=0)
    max_parallel: int = Field(default=2, ge=1)


class ScopeSnapshot(StrictModel):
    allowed_hosts: list[str]
    denied_hosts: list[str]
    allow_private: bool
    allowed_ports: list[int]
    target: str


class TaskSpecValidationError(StrictModel):
    message: str


class PlannedTaskBundle(StrictModel):
    plan_task_id: str
    tasks: list[Task] = Field(default_factory=list)


class EvidenceSummary(StrictModel):
    id: str
    kind: EvidenceKind
    source_url: str
    method: str = ""
    summary: str
    in_scope: bool
    content_hash: str
    body_excerpt: str = ""


class FindingSummary(StrictModel):
    id: str
    title: str
    category: str
    severity: Severity
    confidence: int
    status: FindingStatus
    evidence_ids: list[str]
    description: str
    impact: str
    reproduction: str
    remediation: str


class ToolRequestBundle(StrictModel):
    """Validated tool request with resolved parent task."""

    request: ToolRequest
    parent_task_id: str
