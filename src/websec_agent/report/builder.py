from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

from ..core.schemas import (
    AuditCheckRecord,
    Evidence,
    EventRecord,
    Finding,
    LLMCallRecord,
    ReviewRecord,
    Run,
    Task,
    TaskStatus,
    utcnow,
)


def compute_stats(
    tasks: list[Task],
    evidence: list[Evidence],
    findings: list[Finding],
    calls: list[LLMCallRecord],
) -> dict:
    task_counts = Counter(task.status.value for task in tasks)
    finding_counts = Counter(finding.status.value for finding in findings)
    finished = sum(count for status, count in task_counts.items() if status in {"done", "failed", "skipped"})
    return {
        "tasks": dict(task_counts),
        "tasks_total": len(tasks),
        "tasks_finished": finished,
        "evidence": len(evidence),
        "findings": dict(finding_counts),
        "findings_total": len(findings),
        "llm_calls": len(calls),
        "tokens_in": sum(call.tokens_in for call in calls),
        "tokens_out": sum(call.tokens_out for call in calls),
        "cost_usd": round(sum(call.cost_usd for call in calls), 6),
        "incomplete": task_counts.get(TaskStatus.FAILED.value, 0) > 0
        or task_counts.get(TaskStatus.SKIPPED.value, 0) > 0,
        "generated_at": utcnow().isoformat(),
    }


def build_report(
    artifacts_root: str | Path,
    run: Run,
    tasks: list[Task],
    evidence: list[Evidence],
    findings: list[Finding],
    reviews: list[ReviewRecord],
    audits: list[AuditCheckRecord],
    calls: list[LLMCallRecord],
    events: list[EventRecord],
    summary_markdown: str,
) -> Path:
    root = Path(artifacts_root)
    run_dir = root / "runs" / run.id
    run_dir.mkdir(parents=True, exist_ok=True)

    stats = compute_stats(tasks, evidence, findings, calls)
    evidence_by_id = {item.id: item for item in evidence}
    failed_tasks = [task for task in tasks if task.status == TaskStatus.FAILED]
    skipped_tasks = [task for task in tasks if task.status == TaskStatus.SKIPPED]

    lines: list[str] = []
    lines.append("# WebSec Agent Security Report\n")
    lines.append(f"- **Target**: {run.target}")
    lines.append(f"- **Run**: `{run.id}`")
    lines.append(f"- **Status**: {run.status.value}")
    lines.append(f"- **Started**: {run.started_at.isoformat()}")
    lines.append(f"- **Scope hosts**: {', '.join(run.scope_snapshot.get('allowed_hosts', [])) or '(target only)'}")
    lines.append("")

    lines.append("## Executive Summary\n")
    lines.append(summary_markdown.strip() or "_No summary generated._")
    lines.append("")

    lines.append(f"## Findings ({len(findings)})\n")
    if not findings:
        lines.append("No findings were proposed.\n")
    for finding in findings:
        lines.append(
            f"### [{finding.severity.value.upper()}] {finding.title}  \n"
            f"Status: **{finding.status.value}** | Category: {finding.category} | "
            f"Confidence: {finding.confidence}/100\n"
        )
        lines.append(f"{finding.description}\n")
        lines.append(f"**Impact**: {finding.impact}\n")
        lines.append(f"**Reproduction**: {finding.reproduction}\n")
        lines.append(f"**Remediation**: {finding.remediation}\n")
        lines.append("**Evidence**:")
        for evidence_id in finding.evidence_ids:
            item = evidence_by_id.get(evidence_id)
            if item is None:
                lines.append(f"- `{evidence_id}` (missing)")
            else:
                lines.append(
                    f"- `{evidence_id}` [{item.kind.value}] {item.source_url} — {item.summary} "
                    f"(sha256 `{item.content_hash[:16]}…`)"
                )
        lines.append("")

        finding_reviews = [review for review in reviews if review.finding_id == finding.id]
        if finding_reviews:
            lines.append("**Reviews**:")
            for review in finding_reviews:
                lines.append(f"- {review.verdict.value}: {review.rationale}")
            lines.append("")

        finding_checks = [check for check in audits if check.finding_id == finding.id]
        if finding_checks:
            lines.append("**Audit**:")
            for check in finding_checks:
                mark = "PASS" if check.passed else "FAIL"
                lines.append(f"- [{mark}] {check.check}: {check.detail}")
            lines.append("")

    lines.append("## Analysis Completeness\n")
    lines.append(f"- Tasks: {stats['tasks_total']} total, {stats['tasks_finished']} terminal")
    lines.append(f"- Task states: {json.dumps(stats['tasks'], ensure_ascii=False)}")
    lines.append(f"- Evidence items: {stats['evidence']}")
    lines.append(f"- LLM calls: {stats['llm_calls']} ({stats['tokens_in']} in / {stats['tokens_out']} out)")
    lines.append(f"- Estimated cost: ${stats['cost_usd']}")
    if failed_tasks:
        lines.append("\n**Failed tasks**:")
        for task in failed_tasks:
            lines.append(f"- {task.kind.value} `{task.id}` ({task.objective}) — {task.error or 'unknown error'}")
    if skipped_tasks:
        lines.append("\n**Skipped tasks**:")
        for task in skipped_tasks:
            lines.append(f"- {task.kind.value} `{task.id}` ({task.objective}) — {task.error or 'skipped'}")
    if not failed_tasks and not skipped_tasks:
        lines.append("\nAll scheduled tasks completed.")
    lines.append("")

    lines.append("## Evidence Index\n")
    for item in evidence:
        lines.append(
            f"- `{item.id}` [{item.kind.value}] {item.method} {item.source_url} — {item.summary}"
        )
    lines.append("")

    report_path = run_dir / "report.md"
    report_path.write_text("\n".join(lines), encoding="utf-8")

    findings_path = run_dir / "findings.json"
    findings_path.write_text(
        json.dumps(
            [finding.model_dump(mode="json") for finding in findings],
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )

    run_payload = {
        "run": run.model_dump(mode="json"),
        "stats": stats,
        "tasks": [task.model_dump(mode="json") for task in tasks],
        "evidence": [item.model_dump(mode="json") for item in evidence],
        "findings": [finding.model_dump(mode="json") for finding in findings],
        "reviews": [review.model_dump(mode="json") for review in reviews],
        "audit_checks": [check.model_dump(mode="json") for check in audits],
        "llm_calls": [call.model_dump(mode="json") for call in calls],
        "events": [event.model_dump(mode="json") for event in events],
    }
    (run_dir / "run.json").write_text(
        json.dumps(run_payload, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    return run_dir
