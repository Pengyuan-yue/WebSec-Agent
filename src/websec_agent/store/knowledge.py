from __future__ import annotations

import hashlib
import json
import os
import tempfile
from pathlib import Path
from typing import Any

from ..core.schemas import utcnow

MAX_ENTRIES_PER_TARGET = 50


def entry_key(entry: dict[str, Any]) -> str:
    raw = "|".join(
        str(entry.get(field, ""))
        for field in ("kind", "title", "detail", "url")
    )
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


class KnowledgeStore:
    """Cross-run memory keyed by target host.

    Confirmed facts (credentials, paths, injection points) are persisted to a
    JSON file next to the run artifacts so later runs start from prior wins.
    Every entry carries its source run_id and evidence hash for traceability.
    """

    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)

    def load(self) -> dict[str, Any]:
        try:
            payload = json.loads(self._path.read_text(encoding="utf-8"))
            if isinstance(payload, dict) and isinstance(payload.get("targets"), dict):
                return payload
        except (OSError, ValueError):
            pass
        return {"version": 1, "targets": {}}

    def entries_for(self, target_host: str) -> list[dict[str, Any]]:
        data = self.load()
        entries = data["targets"].get(target_host, [])
        return entries if isinstance(entries, list) else []

    def entries_for_all(self) -> list[dict[str, Any]]:
        data = self.load()
        collected: list[dict[str, Any]] = []
        for host, entries in sorted(data["targets"].items()):
            if isinstance(entries, list):
                collected.extend(
                    {**entry, "host": host}
                    for entry in entries
                    if isinstance(entry, dict)
                )
        return collected

    def record(self, target_host: str, entries: list[dict[str, Any]]) -> int:
        """Merge entries (dedup by content key). Returns newly added count."""
        if not entries:
            return 0
        data = self.load()
        bucket = data["targets"].setdefault(target_host, [])
        known = {entry_key(entry) for entry in bucket if isinstance(entry, dict)}
        added = 0
        for entry in entries:
            key = entry_key(entry)
            if key in known:
                continue
            known.add(key)
            bucket.append({**entry, "key": key, "recorded_at": utcnow().isoformat()})
            added += 1
        if added:
            del bucket[:-MAX_ENTRIES_PER_TARGET]
            self._save(data)
        return added

    def _save(self, data: dict[str, Any]) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_name = tempfile.mkstemp(
            dir=str(self._path.parent), prefix=".knowledge-", suffix=".tmp"
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(data, handle, ensure_ascii=False, indent=2)
            os.replace(tmp_name, self._path)
        except OSError:
            if os.path.exists(tmp_name):
                os.unlink(tmp_name)
            raise
