from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Sequence


@dataclass(frozen=True)
class EvidenceCompression:
    available: int
    included: int
    omitted: int
    deduplicated: int
    truncated: int
    excerpt_chars: int
    budget_chars: int


def compress_evidence(
    evidence: Sequence[Any],
    get_excerpt: Callable[[Any], str],
    *,
    max_items: int,
    max_total_excerpt_chars: int,
) -> tuple[list[Any], dict[str, str], EvidenceCompression]:
    """Deduplicate by content hash, keep the newest items, and bound body excerpts.

    Returns selected evidence in chronological order, an excerpt map keyed by
    evidence id, and counters describing what was dropped.
    """

    deduped: list[Any] = []
    seen: set[str] = set()
    for item in reversed(evidence):
        key = getattr(item, "content_hash", "") or getattr(item, "id", "")
        if key in seen:
            continue
        seen.add(key)
        deduped.append(item)

    newest_first = deduped[:max_items]
    excerpts: dict[str, str] = {}
    remaining = max_total_excerpt_chars
    truncated = 0
    for item in newest_first:
        if remaining <= 0:
            excerpts[getattr(item, "id", "")] = ""
            continue
        raw = get_excerpt(item) or ""
        if len(raw) > remaining:
            raw = raw[:remaining] + "\n...[truncated]"
            truncated += 1
        excerpts[getattr(item, "id", "")] = raw
        remaining -= len(raw)

    selected = list(reversed(newest_first))
    stats = EvidenceCompression(
        available=len(evidence),
        included=len(selected),
        omitted=len(evidence) - len(selected),
        deduplicated=len(evidence) - len(deduped),
        truncated=truncated,
        excerpt_chars=sum(len(value) for value in excerpts.values()),
        budget_chars=max_total_excerpt_chars,
    )
    return selected, excerpts, stats


def compress_list(items: Sequence[Any], limit: int) -> tuple[list[Any], int]:
    """Keep the most recent ``limit`` items and report how many were omitted."""

    if limit <= 0 or len(items) <= limit:
        return list(items), 0
    return list(items[-limit:]), len(items) - limit
