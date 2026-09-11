"""One definition of a crypto asset's per-field status, shared by writer and scorer.

⚠ WHY THIS MODULE EXISTS: EVERY CBOM PUBLISHED THE SAME NUMBER TWICE.

`bulk._crypto_field_status` recorded every field of an asset's type as either
`provided` or `not-provided` — the explicit, reported gap invariant 3 asks for.
The scorer never saw it. The CBOM pipeline handed `score_crypto` only the values
`crypto.py` had kept, and `crypto.py` keeps only substantive ones, so a field the
stored `field_status` called `not-provided` reached the scorer as absent,
`is_declared(None)` said no, and `declaration_pct` came out identical to
`completeness_pct` on every CBOM ever written. Live, 60.14 / 60.14 — while every
AIBOM and HBOM document published two different numbers, as they must.

Two functions computing one fact in two places is how that happened, so there is
now one place: `field_status` is what the writer stores, `scored_entity` is what
the scorer reads, and both walk the same profile-generated field list.

⚠ THE `[]` SUFFIX IS NOTATION, NOT PART OF THE KEY. The profile writes list-valued
paths as `crypto_asset.crypto_functions[]`; the column is `crypto_functions`.
Reading the path verbatim is what made every list field — crypto functions,
algorithm list, cipher suites — score zero on every asset.

⚠ `derived` IS PRESENT, AND IS LABELLED. A value AxeBOM filled from a cited
reference table (axebom_shared.crypto.reference; user decision 2026-09-11:
derive + count, labelled) is real and counts toward completeness — but the stored
status says `derived`, not `provided`, so no reader can mistake AxeBOM's lookup
for an engine's claim. `derived_counts` gives the per-field tally every report
footnotes.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from axebom_shared.model.generated_certin import CRYPTO_FIELDS_BY_ASSET_TYPE

from .coverage import is_declared, is_substantive

PROVIDED = "provided"
DERIVED = "derived"
NOT_PROVIDED = "not-provided"

_PREFIX = "crypto_asset."


def column_of(canonical_path: str) -> str:
    """`crypto_asset.crypto_functions[]` -> `crypto_functions`."""
    return canonical_path.removeprefix(_PREFIX).removesuffix("[]")


def scored_path(canonical_path: str) -> str:
    """The key `score_crypto` looks a field up by: the profile path without `[]`."""
    return canonical_path.removesuffix("[]")


def type_columns(asset_type: str) -> list[str]:
    """The canonical columns CERT-In scores for one asset type, from the profile."""
    return [column_of(f.canonical_path) for f in CRYPTO_FIELDS_BY_ASSET_TYPE.get(asset_type, [])]


def field_status(asset: dict[str, Any]) -> dict[str, str]:
    """Each of THIS asset's TYPE's CERT-In fields: provided, derived or not-provided.

    Only the asset's own type's fields appear — a certificate carries no
    `key_size` entry at all, rather than a `not-provided` one it was never asked
    for (invariant 5). A column is `derived` only when it holds a substantive
    value AND the asset's `derivations` names it; a derivation record for a value
    that is not there is ignored rather than turned into a claim.
    """
    asset_type = str(asset.get("asset_type") or "")
    derivations = asset.get("derivations") or {}
    status: dict[str, str] = {}
    for column in type_columns(asset_type):
        if not is_substantive(asset.get(column)):
            status[column] = NOT_PROVIDED
        elif column in derivations:
            status[column] = DERIVED
        else:
            status[column] = PROVIDED
    return status


def scored_entity(asset: dict[str, Any]) -> dict[str, Any]:
    """The flat mapping `score_crypto` reads for one asset.

    Every field of the asset's type is present: its value when the asset holds
    one, otherwise the explicit `not-provided` that `field_status` records for it.
    So an unknown field is DECLARED (it counts toward `declaration_pct`) and not
    PRESENT (it scores zero toward `completeness_pct`) — exactly the distinction
    invariant 3 draws, and exactly what the stored `field_status` says.

    A value the asset does hold passes through untouched, including a
    non-substantive one: `key_state = "unknown"` is declared and not present.

    An asset whose type has no field set keeps only its `asset_type`, so
    `score_crypto` counts it as unidentified rather than scoring it against a
    guess.
    """
    asset_type = str(asset.get("asset_type") or "")
    entity: dict[str, Any] = {f"{_PREFIX}asset_type": asset_type}
    for f in CRYPTO_FIELDS_BY_ASSET_TYPE.get(asset_type, []):
        value = asset.get(column_of(f.canonical_path))
        entity[scored_path(f.canonical_path)] = value if is_declared(value) else NOT_PROVIDED
    return entity


def derived_counts(assets: Iterable[dict[str, Any]]) -> dict[str, int]:
    """Per profile field id, how many assets hold a DERIVED value for it.

    Counted from `field_status`, so the tally a report footnotes is exactly the
    statuses the writer stores — a third implementation of "is this derived"
    would be the next thing to drift.
    """
    counts: dict[str, int] = {}
    for asset in assets:
        status = field_status(asset)
        for f in CRYPTO_FIELDS_BY_ASSET_TYPE.get(str(asset.get("asset_type") or ""), []):
            if status.get(column_of(f.canonical_path)) == DERIVED:
                counts[f.id] = counts.get(f.id, 0) + 1
    return counts
