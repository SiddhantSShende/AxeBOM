"""Bounded discovery of hardware design files in a materialized source tree.

⚠ EVERY FILE THIS MODULE HANDS BACK IS UNTRUSTED CUSTOMER INPUT.

The HBOM adapters parse in-process rather than in a sandboxed container, which
is the same posture `webrecon_fingerprint.py` and `github_dependency_graph.py`
already take, and consistent with CLAUDE.md invariant 7's actual scope: that
rule is about EXECUTING third-party binaries over untrusted code, and there is
no binary here. But `json.loads` is a hardened C parser and an S-expression
tokeniser is not, so the bounds have to be explicit rather than inherited.

Four limits, each for a failure this module can actually see:

  MAX_FILES        a repository with 40,000 generated .csv files
  MAX_FILE_BYTES   one 2 GB file that would be read into memory whole
  MAX_TOTAL_BYTES  ten thousand small files that add up to the same thing
  the symlink rule a link pointing at /etc/passwd, or out of the workspace

⚠ SYMLINKS ARE SKIPPED, NOT RESOLVED-AND-CHECKED. Resolving first and
comparing paths afterwards is the classic TOCTOU shape; a design file that is
a symlink has no legitimate meaning here, so it is simply never followed.

A limit that is hit is REPORTED, never silent — the caller turns it into a
diagnostic. A parts list that was truncated without saying so is exactly the
false-negative class invariant 12 exists to prevent.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

#: How many candidate files to visit before stopping.
MAX_FILES = 2_000

#: The largest single design file that will be read. A KiCad schematic for a
#: large board is a few MB; 64 is generous and still bounded.
MAX_FILE_BYTES = 64 * 1024 * 1024

#: The ceiling across everything read in one job.
MAX_TOTAL_BYTES = 256 * 1024 * 1024

#: Directories never worth walking. Not security — a `.git` directory holds no
#: schematic, and `node_modules` in a firmware repo is thousands of wasted
#: stat calls that would eat the MAX_FILES budget before reaching the hardware.
SKIP_DIRS = frozenset(
    {
        ".git",
        ".svn",
        ".hg",
        "node_modules",
        "__pycache__",
        ".venv",
        "venv",
        ".tox",
        "dist",
        "build",
        "target",
        ".gradle",
        ".idea",
        ".vscode",
    }
)


@dataclass
class Found:
    """One design file, and how it was classified."""

    path: Path
    #: Path relative to the workspace root — what a report shows, and what
    #: never leaks an absolute host path into a customer document.
    relative: str
    kind: str
    data: bytes


@dataclass
class Discovery:
    """What a walk found, and what it had to leave out."""

    files: list[Found] = field(default_factory=list)
    #: Extensions that were looked for, so an empty result can say what it
    #: searched rather than only that it found nothing.
    searched: list[str] = field(default_factory=list)
    diagnostics: list[dict[str, Any]] = field(default_factory=list)

    def by_kind(self, kind: str) -> list[Found]:
        return [f for f in self.files if f.kind == kind]


def classify(path: Path) -> str | None:
    """Name the parser a file belongs to, or None if it is not ours.

    ⚠ EXTENSION PLUS A CONTENT PEEK FOR THE AMBIGUOUS ONES. `.xml` is a KiCad
    netlist, a Windows manifest, or anything else; `.csv` is a BOM export or a
    test log. Guessing from the extension alone would hand a parser a file it
    has no business reading, and the parser would then report a confusing
    failure about a file the customer never meant to include.
    """
    suffix = path.suffix.lower()
    if suffix == ".kicad_sch":
        return "kicad-schematic"
    if suffix == ".sch":
        # ⚠ `.sch` IS AMBIGUOUS AND ALWAYS HAS BEEN. EAGLE, gEDA and KiCad's
        # own legacy format all use it, so this is a guess that `_looks_like`
        # must confirm against `<eagle` in the bytes. Only EAGLE is parsed
        # today; the others fall out as unclassified rather than being handed
        # to a parser that cannot read them.
        return "eagle-schematic"
    if suffix in (".net", ".xml"):
        return "kicad-netlist"  # confirmed by content in `_looks_like`
    if suffix in (".csv", ".tsv"):
        return "bom-table"
    return None


#: What the walk looks for, published so an empty result can name it.
SEARCHED_EXTENSIONS = (".kicad_sch", ".sch", ".net", ".xml", ".csv", ".tsv")


def walk(root: Path, subpath: str = "") -> Discovery:
    """Find candidate design files under a materialized source tree.

    Deterministic order (sorted), because two runs over the same archive must
    produce the same document — normalization is replayable (invariant 10) and
    a walk whose order depended on the filesystem would break that before the
    parser was even reached.
    """
    out = Discovery(searched=list(SEARCHED_EXTENSIONS))
    base = (root / subpath).resolve() if subpath else root.resolve()
    if not base.is_dir():
        out.diagnostics.append(
            {
                "severity": "warn",
                "code": "ENGINE_INPUT_MISSING",
                "message": f"no directory at {subpath or '.'} in the materialized source",
            }
        )
        return out

    visited = 0
    total_bytes = 0

    for path in _candidates(base):
        if visited >= MAX_FILES:
            out.diagnostics.append(
                {
                    "severity": "warn",
                    "code": "HBOM_FILE_LIMIT_REACHED",
                    "message": f"stopped after visiting {MAX_FILES:,} candidate files",
                    "hint": "anything below that point was not read; narrow the "
                    "upload or the repository subpath so the parts list is "
                    "complete rather than partial",
                }
            )
            break
        visited += 1

        kind = classify(path)
        if kind is None:
            continue

        try:
            size = path.stat().st_size
        except OSError:
            continue

        if size > MAX_FILE_BYTES:
            out.diagnostics.append(
                {
                    "severity": "warn",
                    "code": "HBOM_FILE_TOO_LARGE",
                    "message": f"{_relative(path, base)} is {size:,} bytes and was skipped",
                    "hint": f"the per-file cap is {MAX_FILE_BYTES:,} bytes",
                }
            )
            continue

        if total_bytes + size > MAX_TOTAL_BYTES:
            out.diagnostics.append(
                {
                    "severity": "warn",
                    "code": "HBOM_TOTAL_SIZE_LIMIT_REACHED",
                    "message": f"stopped reading at {MAX_TOTAL_BYTES:,} bytes total",
                    "hint": "files after this point were not read",
                }
            )
            break

        try:
            data = path.read_bytes()
        except OSError:
            continue

        if not _looks_like(kind, data):
            continue

        total_bytes += len(data)
        out.files.append(Found(path=path, relative=_relative(path, base), kind=kind, data=data))

    out.files.sort(key=lambda f: f.relative)
    return out


def _candidates(base: Path) -> Iterator[Path]:
    """Every regular, non-symlink file under base, in deterministic order."""
    stack = [base]
    while stack:
        current = stack.pop()
        try:
            entries = sorted(current.iterdir(), key=lambda p: p.name)
        except OSError:
            continue
        for entry in entries:
            # ⚠ NEVER FOLLOWED. is_symlink() is checked BEFORE is_dir()/is_file(),
            # because those follow the link and would report on the target.
            if entry.is_symlink():
                continue
            if entry.is_dir():
                if entry.name not in SKIP_DIRS:
                    stack.append(entry)
                continue
            if entry.is_file():
                yield entry


def _relative(path: Path, base: Path) -> str:
    try:
        return path.relative_to(base).as_posix()
    except ValueError:
        # Cannot happen for a walk rooted at base, but an absolute host path in
        # a customer's compliance document would be an information leak, so the
        # fallback is the bare name rather than str(path).
        return path.name


def _looks_like(kind: str, data: bytes) -> bool:
    """Confirm an extension's guess against the first bytes of the file.

    ⚠ THE XML CASE ALSO REFUSES DOCTYPE AND ENTITY DECLARATIONS OUTRIGHT.

    A KiCad netlist contains neither, and both are the vector for the
    quadratic-entity-expansion attack that `xml.etree.ElementTree` is
    documented as vulnerable to. Rejecting the shape is stronger than trying to
    parse it safely, and it costs nothing real: no legitimate input has them.
    """
    head = data[:4096].lstrip()
    if kind == "kicad-schematic":
        return head.startswith(b"(kicad_sch") or head.startswith(b"(export")
    if kind == "eagle-schematic":
        lowered = head.lower()
        if b"<!doctype" in lowered or b"<!entity" in lowered:
            return False
        # `<eagle` is the root element and appears within the first bytes after
        # the XML declaration. A gEDA or legacy-KiCad .sch has no such element,
        # so it stays unclassified rather than reaching a parser that would
        # report a confusing failure about a file it cannot read.
        return b"<eagle" in lowered
    if kind == "kicad-netlist":
        lowered = head.lower()
        if b"<!doctype" in lowered or b"<!entity" in lowered:
            return False
        return b"<export" in lowered and b"<components" in data[:200_000].lower()
    if kind == "bom-table":
        return bool(head)
    return False
