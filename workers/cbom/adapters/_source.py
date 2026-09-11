"""Which source languages a tree actually contains — for a source engine's zero.

⚠ A SOURCE ENGINE'S "NOTHING FOUND" MEANS DIFFERENT THINGS. cbomkit-action
finding nothing in a repository full of Java is suspicious (a layout it could not
read, calls through wrappers) and is `partial`. Finding nothing in a repository
with no Java or Python is simply correct — and reporting THAT as `partial` would
make every such scan `completed_with_errors`, the mistake cbomkit-theia's
unconditional `partial` made until 2026-09-11.
"""

from __future__ import annotations

import os
from pathlib import Path

#: Vendored or generated trees that say nothing about the project's own code.
_SKIP_DIRS = frozenset({".git", ".hg", ".svn", "node_modules", "__pycache__", ".venv", "venv"})

#: Bounded, so a pathological tree cannot turn a status check into a long walk.
_MAX_FILES = 200_000

#: Every source language a CBOM source engine could be asked about, by extension.
#:
#: ⚠ A LANGUAGE HERE THAT NO ENGINE READS IS A GAP, AND IS REPORTED AS ONE. A Go
#: repository scanned for cryptography by engines that read Java and JavaScript
#: is not a repository with no cryptography: without this list, its CBOM held
#: the certificates theia found and nothing else, and read as complete
#: (invariant 12). Each adapter's own surfaces must use these exact names and
#: extensions (test_source_coverage.py).
SOURCE_LANGUAGES: dict[str, tuple[str, ...]] = {
    "java-source": (".java",),
    "kotlin-source": (".kt", ".kts"),
    "scala-source": (".scala",),
    "python-source": (".py",),
    "js-source": (".js", ".mjs", ".cjs", ".jsx", ".ts", ".mts", ".cts", ".tsx"),
    "go-source": (".go",),
    "csharp-source": (".cs",),
    "c-cpp-source": (".c", ".h", ".cc", ".cpp", ".cxx", ".hh", ".hpp", ".hxx"),
    "rust-source": (".rs",),
    "swift-source": (".swift",),
    "php-source": (".php",),
    "ruby-source": (".rb",),
}


def source_coverage(root: Path, own: dict[str, tuple[str, ...]]) -> tuple[list[str], list[str]]:
    """`(covered, uncovered)`: the source languages present under `root` that an
    engine reading `own` covers, and the ones present that it does not."""
    present = languages_present(root, {**SOURCE_LANGUAGES, **own})
    return sorted(present & own.keys()), sorted(present - own.keys())


def languages_present(root: Path, suffixes: dict[str, tuple[str, ...]]) -> set[str]:
    """The keys of `suffixes` whose extensions occur anywhere under `root`."""
    wanted = {suffix.lower(): surface for surface, exts in suffixes.items() for suffix in exts}
    found: set[str] = set()
    seen = 0
    if not root.is_dir():
        return found
    for _dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        for filename in filenames:
            seen += 1
            surface = wanted.get(Path(filename).suffix.lower())
            if surface:
                found.add(surface)
            if len(found) == len(suffixes) or seen >= _MAX_FILES:
                return found
    return found
