"""Where an engine says it saw something — one parser, one mount-strip rule.

⚠ ENGINES DISAGREE ABOUT HOW TO SAY "HERE", and stored as reported one finding
looks like several files:

    airom            {"location": "src/app.py", "line": 9}
    cdxgen           {"location": "src/app.py#L12"}
    cbomkit-theia    {"location": "key.pem", "line": 0}     ← 0 means "no line"
    ai-bom           {"location": "/src/app.py:13"}         ← echoes the mount

A path that still carries the sandbox mount (`/src/...`) also reads, to anyone who
does not know the mount, like a location outside the repository.

So occurrences go through `occurrences()`: repository-relative path, a positive
line or none, one shape — `{"path": ..., "line": ...}`. Stripping the mount here
rather than in each adapter means one rule, applied once, that a new engine
cannot forget. `workers/aibom/discovery.repo_path` delegates here.
"""

from __future__ import annotations

from typing import Any

#: Where every sandboxed engine sees the customer's source tree.
#:
#: ⚠ NOT A GUESS AND NOT PER-ENGINE. `axebom_shared.sandbox.WorkspaceLayout
#: .container_source` is `/src` for every engine, because the sandbox mounts the
#: tree there. It is a constant of OUR runner, not of any tool.
CONTAINER_SOURCE_PREFIX = "/src/"


def repo_path(location: str) -> str:
    """One evidence path, relative to the repository root."""
    location = location.strip() if isinstance(location, str) else ""
    if location.startswith(CONTAINER_SOURCE_PREFIX):
        return location[len(CONTAINER_SOURCE_PREFIX) :]
    return location


def occurrences(raw: dict[str, Any]) -> list[dict[str, Any]]:
    """A CycloneDX component's `evidence.occurrences[]` as `[{path, line}]`.

    De-duplicated and sorted, so the same asset reported twice by one engine, or
    replayed, produces the same list. `line` is None when the engine gave none —
    including theia's `line: 0`, which is not a line.
    """
    evidence = raw.get("evidence")
    if not isinstance(evidence, dict):
        return []
    entries = evidence.get("occurrences")
    if not isinstance(entries, list):
        return []

    seen: set[tuple[str, int | None]] = set()
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        location = entry.get("location")
        if not isinstance(location, str) or not location.strip():
            continue
        location = location.strip()
        line: int | None = None
        if "#L" in location:
            path, _, suffix = location.partition("#L")
            location = path
            line = int(suffix) if suffix.isdigit() else None
        else:
            reported = entry.get("line")
            if isinstance(reported, int) and not isinstance(reported, bool):
                line = reported
        path = repo_path(location)
        if not path:
            continue
        seen.add((path, line if line and line > 0 else None))

    return [
        {"path": path, "line": line}
        for path, line in sorted(seen, key=lambda item: (item[0], item[1] or 0))
    ]
