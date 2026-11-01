from __future__ import annotations

from ..core.schemas import EvidenceKind
from .base import Collected
from .http import HttpCollector


class RobotsCollector:
    def __init__(self, http: HttpCollector) -> None:
        self._http = http

    def collect(self, robots_url: str) -> Collected:
        collected = self._http.fetch(robots_url, kind=EvidenceKind.ROBOTS)
        collected.summary = f"robots.txt {collected.summary}"
        return collected
