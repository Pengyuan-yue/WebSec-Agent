from __future__ import annotations

from dataclasses import dataclass, field

from ..core.schemas import EvidenceKind


@dataclass
class Collected:
    kind: EvidenceKind
    source_url: str
    method: str
    summary: str
    raw: bytes
    derived_from: list[str] = field(default_factory=list)
