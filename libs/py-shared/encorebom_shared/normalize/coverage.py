"""Coverage scoring — two numbers, always both, type-aware for crypto.

⚠ THIS MODULE PRODUCES THE NUMBER THE CUSTOMER QUOTES. Three rules make it
honest, and all three are easy to get wrong in a direction that flatters.

**1. Two numbers, never one.**

    completeness_pct   substantive values only    ← the compliance signal
    declaration_pct    any value, incl. not-provided ← representation check

`not-provided`, `NOASSERTION`, `unknown`, `""` and `[]` score **present = 0** for
completeness. They score 1 for declaration. Publishing only the second and
calling it "coverage" produces a 100% score for a BOM that knows almost nothing.
That is the specific way tools in this space mislead, and it is why both numbers
appear in every report.

**2. The denominator keeps what it cannot identify.**

Components with `scope = excluded` or `identity_rule = opaque` go to
`unidentified_count` and stay in the denominator. Dropping them lets a scan that
understood almost nothing report a high percentage.

**3. Crypto scoring branches on `asset_type`.**

CERT-In Table 9 is type-discriminated: Algorithms, Keys, Protocols and
Certificates have different field sets. Scoring a certificate against `key_size`
would report every CBOM at roughly 30% — falsely, in a compliance document.

⚠ NO FIELD COUNT IS EVER HARDCODED HERE (invariant 2). Everything comes from
`docs/reference/certin-v2.0.yaml`, so a guideline revision is a data change.

See `docs/03-NORMALIZER-SPEC.md` §5.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

#: Values that are REPORTED but do not count as covered.
#:
#: `not-provided` is stored explicitly rather than omitted, because omission
#: hides the gap — but storing it is not the same as knowing the answer.
NON_SUBSTANTIVE = frozenset({"not-provided", "noassertion", "unknown", "none-provided", "n/a", ""})

#: The one deliberate exception, documented so it can be argued about from a
#: written position: SPDX `NONE` on a licence field is a substantive assertion —
#: "we looked, there is no licence" — and counts as PRESENT. `NOASSERTION`
#: declines to say and does not. See `licenses.Resolution.is_substantive`.
LICENSE_NONE = "NONE"

#: Field ids whose canonical path is a licence, where the NONE exception applies.
_LICENSE_PATH_MARKERS = ("license", "licence")


@dataclass(frozen=True)
class Field:
    """One scored field from the compliance profile."""

    id: str
    name: str
    canonical_path: str
    weight: int
    required: bool = True

    @property
    def is_license(self) -> bool:
        lowered = self.canonical_path.lower()
        return any(marker in lowered for marker in _LICENSE_PATH_MARKERS)


@dataclass
class FieldScore:
    """Per-field roll-up, for the breakdown table every report renders."""

    field_id: str
    name: str
    weight: int
    #: Entities where the field held a substantive value.
    present: int = 0
    #: Entities where the field held any value, including `not-provided`.
    declared: int = 0
    total: int = 0

    @property
    def completeness_pct(self) -> float:
        return _pct(self.present, self.total)

    @property
    def declaration_pct(self) -> float:
        return _pct(self.declared, self.total)


@dataclass
class CoverageResult:
    """Both numbers, plus everything needed to explain them."""

    completeness_pct: float
    declaration_pct: float
    #: Weighted numerators and denominator, published so the number is
    #: auditable rather than magic (spec §5.1).
    completeness_numerator: int
    declaration_numerator: int
    denominator: int
    fields: list[FieldScore] = field(default_factory=list)
    #: Entities kept in the denominator that could not be identified.
    unidentified_count: int = 0
    scored_entities: int = 0
    diagnostics: list[dict[str, Any]] = field(default_factory=list)

    #: The formula itself, rendered into the report so a reader can check it.
    # ⚠ The multiplication signs are deliberate. This string is rendered
    # verbatim into every report so the number is auditable, and it must
    # match the formula in docs/03-NORMALIZER-SPEC.md §5.1 exactly.
    formula: str = "pct = 100 × Σ_c Σ_f (w_f × present(c,f)) / Σ_c Σ_f w_f"  # noqa: RUF001

    def as_dict(self) -> dict[str, Any]:
        return {
            "completeness_pct": round(self.completeness_pct, 2),
            "declaration_pct": round(self.declaration_pct, 2),
            "completeness_numerator": self.completeness_numerator,
            "declaration_numerator": self.declaration_numerator,
            "denominator": self.denominator,
            "scored_entities": self.scored_entities,
            "unidentified_count": self.unidentified_count,
            "field_count": len(self.fields),
            "formula": self.formula,
            "fields": [
                {
                    "field_id": f.field_id,
                    "name": f.name,
                    "weight": f.weight,
                    "present": f.present,
                    "declared": f.declared,
                    "total": f.total,
                    "completeness_pct": round(f.completeness_pct, 2),
                    "declaration_pct": round(f.declaration_pct, 2),
                }
                for f in self.fields
            ],
        }


def is_substantive(value: Any, *, is_license: bool = False) -> bool:
    """Whether a value counts as PRESENT for `completeness_pct`.

    ⚠ The whole coverage distinction lives in this function. An empty list and
    an empty string are absences that a naive truthiness check would treat the
    same as a missing key — which is correct — but `not-provided` is a STRING
    that a truthiness check would count as present. That is the bug that turns a
    BOM full of `not-provided` into a 100% score.
    """
    if value is None:
        return False

    if isinstance(value, str):
        text = value.strip()
        if is_license and text.upper() == LICENSE_NONE:
            # The documented exception: a substantive assertion.
            return True
        return text.lower() not in NON_SUBSTANTIVE

    if isinstance(value, (list, tuple, set, dict)):
        # Empty collections are absences. A non-empty one still has to contain
        # something substantive — `["not-provided"]` is not coverage.
        if not value:
            return False
        if isinstance(value, dict):
            return True
        return any(is_substantive(v, is_license=is_license) for v in value)

    if isinstance(value, bool):
        # ⚠ `False` is an answer. Treating it as absent would make every
        # component that is legitimately not an archive look unscored.
        return True

    if isinstance(value, (int, float)):
        return True

    return True


def is_declared(value: Any) -> bool:
    """Whether a value counts for `declaration_pct`.

    Anything at all, including an explicit `not-provided`. Absent means the key
    is missing or holds None/empty — the field was not addressed at all.
    """
    if value is None:
        return False
    if isinstance(value, str):
        return value.strip() != ""
    if isinstance(value, (list, tuple, set, dict)):
        return bool(value)
    return True


def score(
    entities: Iterable[Mapping[str, Any]],
    fields: list[Field],
    *,
    unidentified: int = 0,
) -> CoverageResult:
    """Score a homogeneous set of entities against one field set.

    `entities` are flat mappings keyed by the profile's `canonical_path`. The
    caller flattens; this module does not know the canonical model's shape, so a
    model change cannot silently break scoring.
    """
    scores = {f.id: FieldScore(field_id=f.id, name=f.name, weight=f.weight) for f in fields}

    completeness_numerator = 0
    declaration_numerator = 0
    denominator = 0
    counted = 0

    for entity in entities:
        counted += 1
        for f in fields:
            value = entity.get(f.canonical_path)
            fs = scores[f.id]
            fs.total += 1
            denominator += f.weight

            if is_substantive(value, is_license=f.is_license):
                fs.present += 1
                completeness_numerator += f.weight
            if is_declared(value):
                fs.declared += 1
                declaration_numerator += f.weight

    # ⚠ UNIDENTIFIED ENTITIES STAY IN THE DENOMINATOR.
    #
    # They contribute their full weight and score zero. Removing them would let
    # a scan that identified three components out of three hundred report a
    # coverage figure computed over the three.
    if unidentified:
        per_entity = sum(f.weight for f in fields)
        denominator += per_entity * unidentified
        counted += unidentified

    diagnostics: list[dict[str, Any]] = []
    if unidentified:
        diagnostics.append(
            {
                "severity": "warn",
                "code": "NORMALIZE_UNIDENTIFIED_IN_DENOMINATOR",
                "message": f"{unidentified} unidentified entities scored zero",
                "hint": (
                    "they remain in the coverage denominator; dropping them would let "
                    "a scan that understood almost nothing report a high percentage"
                ),
            }
        )

    return CoverageResult(
        completeness_pct=_pct(completeness_numerator, denominator),
        declaration_pct=_pct(declaration_numerator, denominator),
        completeness_numerator=completeness_numerator,
        declaration_numerator=declaration_numerator,
        denominator=denominator,
        fields=sorted(scores.values(), key=lambda s: s.field_id),
        unidentified_count=unidentified,
        scored_entities=counted,
        diagnostics=diagnostics,
    )


def score_crypto(
    assets: Iterable[Mapping[str, Any]],
    field_sets: Mapping[str, list[Field]],
    *,
    unidentified: int = 0,
) -> CoverageResult:
    """Score crypto assets, each against the field set for ITS `asset_type`.

    ⚠ THIS IS A CORRECTNESS REQUIREMENT, NOT AN OPTIMIZATION.

    CERT-In Table 9 gives Algorithms, Keys, Protocols and Certificates different
    field sets. Scoring every asset against the union — so a certificate is
    marked down for having no `key_size`, and a key for having no `issuer_name` —
    reports every CBOM at roughly 30% coverage. In a compliance document that is
    a false statement about the customer's posture.

    `field_sets` maps `asset_type` value -> its fields.
    """
    scores: dict[str, FieldScore] = {}
    completeness_numerator = 0
    declaration_numerator = 0
    denominator = 0
    counted = 0
    diagnostics: list[dict[str, Any]] = []
    unknown_types: set[str] = set()

    for asset in assets:
        asset_type = str(asset.get("crypto_asset.asset_type") or "").strip().lower()
        fields = field_sets.get(asset_type)

        if fields is None:
            # An asset whose type we do not recognise cannot be scored against
            # any field set. It is counted as unidentified rather than scored
            # against a guess — scoring it against the wrong set is exactly the
            # failure this function exists to prevent.
            unknown_types.add(asset_type or "<empty>")
            unidentified += 1
            continue

        counted += 1
        for f in fields:
            value = asset.get(f.canonical_path)
            fs = scores.setdefault(f.id, FieldScore(field_id=f.id, name=f.name, weight=f.weight))
            fs.total += 1
            denominator += f.weight

            if is_substantive(value, is_license=f.is_license):
                fs.present += 1
                completeness_numerator += f.weight
            if is_declared(value):
                fs.declared += 1
                declaration_numerator += f.weight

    if unknown_types:
        diagnostics.append(
            {
                "severity": "warn",
                "code": "NORMALIZE_CRYPTO_ASSET_TYPE_UNKNOWN",
                "message": (
                    f"{len(unknown_types)} crypto asset type(s) have no field set: "
                    f"{', '.join(sorted(unknown_types))}"
                ),
                "hint": (
                    "counted as unidentified rather than scored against another type's "
                    "fields, which would report a false percentage"
                ),
            }
        )

    if unidentified:
        # Unidentified crypto assets have no field set, so their weight is taken
        # from the largest defined set. Using the largest is the conservative
        # choice: it cannot understate the gap.
        per_entity = max((sum(f.weight for f in fs) for fs in field_sets.values()), default=0)
        denominator += per_entity * unidentified
        counted += unidentified
        diagnostics.append(
            {
                "severity": "warn",
                "code": "NORMALIZE_UNIDENTIFIED_IN_DENOMINATOR",
                "message": f"{unidentified} crypto assets scored zero",
                "hint": "they remain in the coverage denominator",
            }
        )

    return CoverageResult(
        completeness_pct=_pct(completeness_numerator, denominator),
        declaration_pct=_pct(declaration_numerator, denominator),
        completeness_numerator=completeness_numerator,
        declaration_numerator=declaration_numerator,
        denominator=denominator,
        fields=sorted(scores.values(), key=lambda s: s.field_id),
        unidentified_count=unidentified,
        scored_entities=counted,
        diagnostics=diagnostics,
    )


def fields_from_profile(entries: Iterable[Mapping[str, Any]]) -> list[Field]:
    """Build the scored field list from profile YAML entries.

    ⚠ THE COUNT COMES FROM THE DATA. Nothing here or downstream may write a
    field count as a literal — that is exactly how a product ships a false
    compliance claim when the guideline is revised (invariant 2).
    """
    out: list[Field] = []
    for entry in entries:
        field_id = str(entry.get("id") or "").strip()
        path = str(entry.get("canonical_path") or "").strip()
        if not field_id or not path:
            continue
        out.append(
            Field(
                id=field_id,
                name=str(entry.get("name") or field_id),
                # A list-valued path is written `component.hashes[]` in the
                # profile; the trailing [] is notation, not part of the key.
                canonical_path=path.removesuffix("[]"),
                weight=int(entry.get("weight") or 1),
                required=bool(entry.get("required", True)),
            )
        )
    return out


def _pct(numerator: int, denominator: int) -> float:
    """Percentage, with an explicit zero-denominator answer.

    Zero entities means zero coverage, not 100%. A scan that found nothing must
    not report perfect coverage of nothing — which is what `0/0 → 1` would do.
    """
    if denominator <= 0:
        return 0.0
    return 100.0 * numerator / denominator
