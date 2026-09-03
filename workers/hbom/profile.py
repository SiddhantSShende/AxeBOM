"""The manufacturing profile — AxeBOM's own field set, read at runtime.

⚠ THIS IS NOT `HBOM_FIELDS`, AND THE DIFFERENCE IS THE ENTIRE POINT.

`HBOM_FIELDS` comes from `generated_certin.py`, is generated from
`docs/reference/certin-v2.0.yaml`, and is what produces `completeness_pct` and
`declaration_pct` — the two numbers a customer hands to a regulator.

The fields here come from `docs/reference/hbom-manufacturing-v1.yaml`, a
different file with a different authority (ours, not CERT-In's), and produce a
different, separately-labelled number. They answer "how buildable and buyable is
this parts list", not "how much of what CERT-In requires is present". Merging
them would let a customer's diligence about unit prices raise a compliance
percentage, which is exactly what CLAUDE.md invariants 2 and 3 exist to prevent.

⚠ READ AT RUNTIME, NOT GENERATED. `axebom profile gen` refuses an operational
profile outright: the generated Go/Python models declare package-level
`ProfileID`/`ProfileRevision`/`ProfileField`, and a second profile would collide
with all three. Nothing in Go needs this list, and Python reads it the same way
`workers/sbom/normalize_runner.sbom_fields()` already reads the CERT-In one.

⚠ THE COUNT IS NEVER WRITTEN HERE OR ANYWHERE ELSE (invariant 2). It is
whatever the profile says.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

from axebom_shared.normalize.coverage import Field, fields_from_profile

#: Repo-relative, resolved by the caller's working directory — the identical
#: convention `workers/sbom/normalize_runner.PROFILE_PATH` uses for
#: `certin-v2.0.yaml`.
#:
#: ⚠ ANY CONTAINER THAT NORMALIZES AN HBOM MUST COPY THIS FILE IN. The CERT-In
#: profile is already COPYed into the normalize-consumer image for exactly this
#: reason; omitting this one raises FileNotFoundError on the first HBOM trigger
#: rather than at build time.
MANUFACTURING_PROFILE_PATH = Path("docs/reference/hbom-manufacturing-v1.yaml")

_SECTION = "hbom_manufacturing"


@lru_cache(maxsize=2)
def _load(path: str) -> dict[str, Any]:
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    return data if isinstance(data, dict) else {}


def manufacturing_profile(path: Path | None = None) -> dict[str, Any]:
    """The parsed operational profile."""
    return _load(str(path or MANUFACTURING_PROFILE_PATH))


def manufacturing_fields(path: Path | None = None) -> list[Field]:
    """The manufacturing field set, scored separately from CERT-In's.

    Built through the SAME `fields_from_profile` the CERT-In path uses, so both
    numbers apply one implementation of weighting and of the `[]` canonical-path
    convention. Two implementations would eventually disagree about what a field
    is worth, and the disagreement would surface as two percentages that cannot
    both be right.
    """
    section = manufacturing_profile(path).get(_SECTION) or {}
    return fields_from_profile(section.get("elements") or [])


def manufacturing_label(path: Path | None = None) -> str:
    """What a report calls this number.

    ⚠ DATA, NOT A STRING IN A RENDERER. A renderer that hardcoded a label could
    print "coverage" next to a number that is not the compliance one, and the
    reader would have no way to tell.
    """
    section = manufacturing_profile(path).get(_SECTION) or {}
    return str(section.get("label") or "Manufacturing and procurement readiness")


def manufacturing_meta(path: Path | None = None) -> dict[str, Any]:
    """Identity of the profile this score came from, to store beside the score.

    `is_compliance` travels with the number so no consumer has to know which
    profile ids are compliance standards — the flag is checkable, a naming
    convention is not.
    """
    meta = manufacturing_profile(path).get("profile") or {}
    return {
        "profile_id": str(meta.get("id") or ""),
        "profile_revision": int(meta.get("revision") or 0),
        "label": manufacturing_label(path),
        "is_compliance": str(meta.get("kind") or "compliance") == "compliance",
    }
