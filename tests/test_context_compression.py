from __future__ import annotations

from types import SimpleNamespace

from websec_agent.agents.context import compress_evidence, compress_list


def _item(item_id: str, content_hash: str, body: str = "") -> SimpleNamespace:
    return SimpleNamespace(id=item_id, content_hash=content_hash, body=body)


def test_compress_evidence_dedupes_by_hash_and_keeps_newest_items():
    evidence = [
        _item("e0", "h0"),
        _item("e1", "h1"),
        _item("e2", "h2"),
        _item("e3", "h3"),
        _item("e4", "h1"),  # duplicate of e1, newer
    ]

    selected, excerpts, stats = compress_evidence(
        evidence,
        lambda item: item.body,
        max_items=3,
        max_total_excerpt_chars=1000,
    )

    assert [item.id for item in selected] == ["e2", "e3", "e4"]
    assert list(excerpts) == ["e4", "e3", "e2"]
    assert stats.available == 5
    assert stats.included == 3
    assert stats.omitted == 2


def test_compress_evidence_bounds_excerpts_newest_first():
    evidence = [
        _item("old", "h-old", body="o" * 100),
        _item("new", "h-new", body="n" * 100),
    ]

    selected, excerpts, stats = compress_evidence(
        evidence,
        lambda item: item.body,
        max_items=10,
        max_total_excerpt_chars=20,
    )

    assert [item.id for item in selected] == ["old", "new"]
    assert excerpts["new"].startswith("n" * 20)
    assert excerpts["new"].endswith("[truncated]")
    assert excerpts["old"] == ""
    assert stats.excerpt_chars == len(excerpts["new"])


def test_compress_list_keeps_most_recent_items():
    items = [{"id": index} for index in range(10)]

    kept, omitted = compress_list(items, limit=3)

    assert [item["id"] for item in kept] == [7, 8, 9]
    assert omitted == 7
