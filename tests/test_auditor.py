from __future__ import annotations

import hashlib
from pathlib import Path

from websec_agent.agents.auditor import EvidenceAuditor
from websec_agent.core.schemas import (
    Evidence,
    EvidenceKind,
    Finding,
    FindingStatus,
    Role,
    Run,
    Severity,
)
from websec_agent.store.db import Database
from websec_agent.store.repos import EvidenceRepository, Repositories


def _database(tmp_path: Path) -> Database:
    db = Database(f"sqlite+pysqlite:///{tmp_path / 'audit.db'}")
    db.create_all()
    return db


def test_auditor_detects_tampered_evidence_and_placeholder_fields(tmp_path):
    db = _database(tmp_path)
    repos = Repositories.build(db)
    run = Run(target="https://example.com")
    repos.runs.create(run)

    raw = b"HTTP/1.1 200 OK\n\nhello"
    artifacts = tmp_path / "artifacts"
    (artifacts / "evidence" / run.id).mkdir(parents=True)
    path = artifacts / "evidence" / run.id / "sample.json"
    path.write_bytes(raw)

    evidence = Evidence(
        run_id=run.id,
        kind=EvidenceKind.HTTP_RESPONSE,
        source_url="https://example.com/",
        method="GET",
        content_hash=hashlib.sha256(raw).hexdigest(),
        raw_path=f"evidence/{run.id}/sample.json",
        summary="baseline response",
    )
    repo: EvidenceRepository = repos.evidence
    repo.create(evidence)

    finding = Finding(
        run_id=run.id,
        title="Missing headers",
        category="misconfiguration",
        severity=Severity.MEDIUM,
        description="Security headers are absent.",
        impact="Clickjacking and XSS impact increase.",
        evidence_ids=[evidence.id],
        reproduction="curl -I https://example.com",
        remediation="Set CSP, X-Frame-Options and HSTS.",
        status=FindingStatus.CONFIRMED,
        created_by=Role.PENTESTER,
    )

    auditor = EvidenceAuditor(repo, artifacts)
    checks, failed = auditor.audit(run.id, "audit-task", [finding])
    assert failed == []
    assert all(check.passed for check in checks)

    path.write_bytes(b"tampered")

    checks, failed = auditor.audit(run.id, "audit-task-2", [finding])
    assert failed == [finding.id]
    assert any(check.check.startswith("evidence_integrity") and not check.passed for check in checks)

    bad_fields = finding.model_copy(update={"reproduction": "   "})
    checks, failed = auditor.audit(run.id, "audit-task-3", [bad_fields])
    assert failed == [bad_fields.id]
    assert any(check.check == "reproduction_present" and not check.passed for check in checks)
