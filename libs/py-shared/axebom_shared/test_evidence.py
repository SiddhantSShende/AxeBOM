"""The one evidence parser every engine's occurrences go through."""

from __future__ import annotations

from axebom_shared.evidence import occurrences, repo_path


def component(*entries: object) -> dict:
    return {"evidence": {"occurrences": list(entries)}}


def test_theia_s_line_zero_is_no_line() -> None:
    """cbomkit-theia reports `key.pem` at `line: 0` — a zero that means "none"."""
    assert occurrences(component({"location": "key.pem", "line": 0})) == [
        {"path": "key.pem", "line": None}
    ]


def test_cdxgen_s_anchor_form_is_read() -> None:
    assert occurrences(component({"location": "src/app.js#L12"})) == [
        {"path": "src/app.js", "line": 12}
    ]


def test_the_sandbox_mount_is_stripped() -> None:
    assert occurrences(component({"location": "/src/Main.java", "line": 42})) == [
        {"path": "Main.java", "line": 42}
    ]
    assert repo_path("/src/a/b.py") == "a/b.py"
    assert repo_path("a/b.py") == "a/b.py"


def test_duplicates_collapse_and_order_is_stable() -> None:
    got = occurrences(
        component(
            {"location": "b.py", "line": 2},
            {"location": "a.py", "line": 9},
            {"location": "/src/b.py", "line": 2},
            {"location": "a.py"},
        )
    )
    assert got == [
        {"path": "a.py", "line": None},
        {"path": "a.py", "line": 9},
        {"path": "b.py", "line": 2},
    ]


def test_malformed_entries_are_ignored_not_raised() -> None:
    assert occurrences({"evidence": "nope"}) == []
    assert occurrences({"evidence": {"occurrences": "nope"}}) == []
    assert occurrences(component(None, 7, {"location": ""}, {"line": 3}, {"location": 5})) == []
