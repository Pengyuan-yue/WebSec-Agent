from __future__ import annotations

import hashlib
from pathlib import Path

from ..core.schemas import AuditCheckRecord, Finding
from ..store.repos import EvidenceRepository


class EvidenceAuditor:
    """Programmatic evidence auditor. No model is involved, so checks are reproducible."""

    def __init__(self, evidence_repo: EvidenceRepository, artifacts_root: str | Path) -> None:
        self._evidence_repo = evidence_repo
        self._artifacts_root = Path(artifacts_root)

    def audit(
        self, run_id: str, task_id: str, findings: list[Finding]
    ) -> tuple[list[AuditCheckRecord], list[str]]:
        checks: list[AuditCheckRecord] = []
        failed_findings: list[str] = []

        for finding in findings:
            before = len(checks)
            checks.extend(self._check_finding(run_id, task_id, finding))
            if any(not check.passed for check in checks[before:]):
                failed_findings.append(finding.id)
        return checks, failed_findings

    def _check_finding(
        self, run_id: str, task_id: str, finding: Finding
    ) -> list[AuditCheckRecord]:
        checks: list[AuditCheckRecord] = []

        def add(name: str, passed: bool, detail: str) -> None:
            checks.append(
                AuditCheckRecord(
                    run_id=run_id,
                    task_id=task_id,
                    finding_id=finding.id,
                    check=name,
                    passed=passed,
                    detail=detail,
                )
            )

        add(
            "evidence_ids_nonempty",
            bool(finding.evidence_ids),
            f"{len(finding.evidence_ids)} evidence id(s)",
        )
        add("reproduction_present", bool(finding.reproduction.strip()), finding.reproduction[:200])
        add("remediation_present", bool(finding.remediation.strip()), finding.remediation[:200])
        add("description_present", bool(finding.description.strip()), finding.description[:200])
        add("impact_present", bool(finding.impact.strip()), finding.impact[:200])

        for evidence_id in finding.evidence_ids:
            evidence = self._evidence_repo.get(evidence_id)
            if evidence is None or evidence.run_id != run_id:
                add(
                    f"evidence_exists:{evidence_id}",
                    False,
                    "evidence not found in this run",
                )
                continue
            add(f"evidence_exists:{evidence_id}", True, evidence.kind.value)

            add(
                f"evidence_in_scope:{evidence_id}",
                evidence.in_scope,
                "in scope" if evidence.in_scope else "collected outside authorized scope",
            )

            path = self._artifacts_root / evidence.raw_path
            if not path.exists():
                add(f"evidence_integrity:{evidence_id}", False, f"missing raw file: {evidence.raw_path}")
                continue
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            add(
                f"evidence_integrity:{evidence_id}",
                digest == evidence.content_hash,
                f"sha256={digest}",
            )

        return checks
