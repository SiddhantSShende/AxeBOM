"""The `component_key` fallback chain — seven rules, first match wins.

⚠ THE RULE THAT FIRED IS PART OF THE ANSWER.

A component identified by PURL and one identified by a filename are both
"identified", and treating them as equally trustworthy is how a guess becomes a
compliance claim. Every key records `identity_rule` and `identity_confidence`,
which drive provenance, the candidate-identity rules in `merge.py`, and the
unidentified count that keeps the coverage denominator honest.

    1  purl    high     syft, trivy, osv-scanner
    2  cpe     medium   dependency-check
    3  swid    medium   firmware, HBOM
    4  hash    medium   syft binary classifier, opaque blobs
    5  file    low      vendored source trees
    6  name    low      AIBOM model lists, HBOM CSV
    7  opaque  low      last resort — NEVER merges with anything

Rule 7 exists so that a component we cannot identify is still *counted*. The
alternative — dropping it — makes a bad scan look like a clean one, because the
component vanishes from both the numerator and the denominator.

See `docs/03-NORMALIZER-SPEC.md` §1.2.
"""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass
from typing import Any

from .purl import PurlError
from .purl import parse as parse_purl

#: Namespace for opaque ids. Fixed, because a random namespace would make
#: normalization non-deterministic and break replay (ADR-0003).
OPAQUE_NAMESPACE = uuid.UUID("6f9619ff-8b86-d011-b42d-00c04fc964ff")

#: Confidence by rule. Kept as data so provenance and the merge rules read the
#: same table rather than each hardcoding a judgement.
CONFIDENCE = {
    "purl": "high",
    "cpe": "medium",
    "swid": "medium",
    "hash": "medium",
    "file": "low",
    "name": "low",
    "opaque": "low",
}

_SHA256 = re.compile(r"^[a-f0-9]{64}$", re.IGNORECASE)
_CPE23 = re.compile(r"^cpe:2\.3:[aho\*\-]:", re.IGNORECASE)
_CPE22 = re.compile(r"^cpe:/[aho]:", re.IGNORECASE)


@dataclass(frozen=True)
class Identity:
    """A resolved component identity."""

    key: str
    rule: str
    confidence: str
    #: Canonical PURL when rule 1 fired, else "". Stored separately because
    #: `component.purl` is a real column and must not carry a `cpe:` string.
    purl: str = ""
    ecosystem: str = ""
    name: str = ""
    version_raw: str = ""

    @property
    def is_opaque(self) -> bool:
        return self.rule == "opaque"

    @property
    def mergeable(self) -> bool:
        """⚠ Opaque identities never merge.

        An opaque key means "we could not tell what this is". Merging two of
        them asserts they are the same thing, which is exactly the claim we just
        said we could not make.
        """
        return self.rule != "opaque"


def resolve(raw: dict[str, Any], *, scan_id: str, engine: str) -> Identity:
    """Run the fallback chain over one engine's component record.

    `scan_id` and `engine` are only used by rule 7, and are passed rather than
    read from anywhere ambient so that normalization stays a pure function of
    its inputs (ADR-0003).
    """
    for rule in (_try_purl, _try_cpe, _try_swid, _try_hash, _try_file, _try_name):
        identity = rule(raw)
        if identity is not None:
            return identity

    return _opaque(raw, scan_id=scan_id, engine=engine)


# -- rule 1: PURL ---------------------------------------------------------


def _try_purl(raw: dict[str, Any]) -> Identity | None:
    value = _first_str(raw, "purl", "packageUrl", "package_url")
    if not value:
        return None
    try:
        purl = parse_purl(value)
    except PurlError:
        # A malformed PURL falls through to the next rule rather than failing.
        # Engines do emit broken PURLs, and losing the component entirely is
        # worse than identifying it by a weaker rule and saying so.
        return None

    canonical = purl.canonical()
    return Identity(
        key=f"purl:{canonical}",
        rule="purl",
        confidence=CONFIDENCE["purl"],
        purl=canonical,
        ecosystem=purl.ecosystem,
        name=purl.name,
        version_raw=purl.version,
    )


# -- rule 2: CPE ----------------------------------------------------------


def _try_cpe(raw: dict[str, Any]) -> Identity | None:
    value = _first_str(raw, "cpe", "cpe23", "cpe23Uri", "cpe_name")
    if not value:
        cpes = raw.get("cpes")
        if isinstance(cpes, list) and cpes:
            first = cpes[0]
            value = first if isinstance(first, str) else ""
    if not value:
        return None

    canonical = canonicalize_cpe(value)
    if not canonical:
        return None

    return Identity(
        key=f"cpe:{canonical}",
        rule="cpe",
        confidence=CONFIDENCE["cpe"],
        ecosystem=_str(raw.get("ecosystem")),
        name=_first_str(raw, "name", "product") or _cpe_product(canonical),
        version_raw=_first_str(raw, "version", "versionInfo"),
    )


def canonicalize_cpe(value: str) -> str:
    """Normalize a CPE for comparison, or "" if it is not one.

    Only the case is normalized. CPE component values are otherwise left alone:
    the wildcard and NA forms (`*` and `-`) are meaningful, and rewriting them
    would change what the CPE matches.
    """
    text = value.strip()
    if _CPE23.match(text):
        return text.lower()
    if _CPE22.match(text):
        return text.lower()
    return ""


def _cpe_product(cpe: str) -> str:
    parts = cpe.split(":")
    # cpe:2.3:a:vendor:product:version:...
    return parts[4] if len(parts) > 4 else ""


# -- rule 3: SWID ---------------------------------------------------------


def _try_swid(raw: dict[str, Any]) -> Identity | None:
    swid = raw.get("swid")
    tag_id = ""
    if isinstance(swid, dict):
        tag_id = _str(swid.get("tagId") or swid.get("tag_id"))
    elif isinstance(swid, str):
        tag_id = swid.strip()
    if not tag_id:
        return None

    return Identity(
        key=f"swid:{tag_id}",
        rule="swid",
        confidence=CONFIDENCE["swid"],
        name=_first_str(raw, "name"),
        version_raw=_first_str(raw, "version"),
    )


# -- rule 4: hash ---------------------------------------------------------


def _try_hash(raw: dict[str, Any]) -> Identity | None:
    """Identify by sha256.

    Only sha256 is accepted. md5 and sha1 both have practical collisions, and a
    collision here silently merges two unrelated components — the failure that
    removes a real component, and its vulnerabilities, from the report.
    """
    for value in _iter_hashes(raw):
        if _SHA256.match(value):
            return Identity(
                key=f"hash:{value.lower()}",
                rule="hash",
                confidence=CONFIDENCE["hash"],
                name=_first_str(raw, "name"),
                version_raw=_first_str(raw, "version"),
            )
    return None


def _iter_hashes(raw: dict[str, Any]):
    hashes = raw.get("hashes")
    if isinstance(hashes, list):
        for entry in hashes:
            if isinstance(entry, dict):
                alg = _str(entry.get("alg") or entry.get("algorithm")).upper().replace("-", "")
                if alg in ("SHA256", "SHA2256"):
                    value = _str(entry.get("value") or entry.get("content"))
                    if value:
                        yield value
            elif isinstance(entry, str):
                yield entry
    direct = _first_str(raw, "sha256", "digest")
    if direct:
        yield direct.removeprefix("sha256:")


# -- rule 5: file ---------------------------------------------------------


def _try_file(raw: dict[str, Any]) -> Identity | None:
    """Identify a vendored file by path plus the digest OF THAT FILE.

    ⚠ The digest is required. A path alone is not identity — the same path in
    two scans can hold different content, and two paths can hold the same file.
    Path-only keys are how a vendored tree inflates a component count.

    ⚠ The digest is read from the LOCATION, not from the component's own
    `hashes`. If it came from the same place rule 4 reads, rule 4 would always
    fire first and this rule would be unreachable — a whole branch of the
    fallback chain that looks implemented and never runs.
    """
    path = ""
    digest = ""

    locations = raw.get("locations")
    if isinstance(locations, list):
        for entry in locations:
            if not isinstance(entry, dict):
                continue
            candidate_path = _str(entry.get("path") or entry.get("file"))
            candidate_digest = _str(
                entry.get("sha256") or entry.get("digest") or entry.get("hash")
            ).removeprefix("sha256:")
            if candidate_path and _SHA256.match(candidate_digest):
                path, digest = candidate_path, candidate_digest.lower()
                break

    if not path:
        # A flat `path` + `file_sha256` pair, as emitted by some binary
        # classifiers.
        candidate_path = _first_str(raw, "path", "location", "file")
        candidate_digest = _first_str(raw, "file_sha256", "location_sha256").removeprefix("sha256:")
        if candidate_path and _SHA256.match(candidate_digest):
            path, digest = candidate_path, candidate_digest.lower()

    if not path or not digest:
        return None

    return Identity(
        key=f"file:{normalize_path(path)}@{digest}",
        rule="file",
        confidence=CONFIDENCE["file"],
        name=_first_str(raw, "name") or path.rsplit("/", 1)[-1],
        version_raw=_first_str(raw, "version"),
    )


# -- rule 6: name ---------------------------------------------------------


def _try_name(raw: dict[str, Any]) -> Identity | None:
    """Identify by ecosystem-qualified name and version.

    ⚠ THE ECOSYSTEM PREFIX IS NOT OPTIONAL.

    `name:npm/lodash@4.17.21` and `name:maven/lodash@4.17.21` are different
    components. Keying on bare name+version is the single most common dedup bug
    in SBOM tooling: it collapses unrelated packages that happen to share a
    name, and the report simply shows fewer components with no indication that
    anything was lost.
    """
    name = _first_str(raw, "name")
    if not name:
        return None

    version = _first_str(raw, "version", "versionInfo")
    ecosystem = _str(raw.get("ecosystem") or raw.get("type")).lower() or "unknown"

    return Identity(
        key=f"name:{ecosystem}/{name.strip().lower()}@{version}",
        rule="name",
        confidence=CONFIDENCE["name"],
        ecosystem=ecosystem,
        name=name.strip(),
        version_raw=version,
    )


# -- rule 7: opaque -------------------------------------------------------


def _opaque(raw: dict[str, Any], *, scan_id: str, engine: str) -> Identity:
    """Last resort: a stable, scan-scoped id that never merges.

    uuid5, not uuid4: normalization must be replayable, so the same inputs have
    to produce the same key on every run (ADR-0003). A random id would make
    every re-normalization produce a different report.
    """
    native = _first_str(raw, "id", "bom-ref", "bomRef", "ref") or repr(sorted(raw.items()))[:200]
    value = uuid.uuid5(OPAQUE_NAMESPACE, f"{scan_id}|{engine}|{native}")
    return Identity(
        key=f"opaque:{value}",
        rule="opaque",
        confidence=CONFIDENCE["opaque"],
        name=_first_str(raw, "name") or "unidentified",
        version_raw=_first_str(raw, "version"),
    )


def opaque_diagnostic(identity: Identity, engine: str) -> dict[str, Any]:
    """The diagnostic every opaque identity must carry.

    Unidentified components stay in the coverage denominator (spec §5.4), so
    this number is what stops a scan that understood almost nothing from
    reporting a high percentage.
    """
    return {
        "severity": "warn",
        "code": "NORMALIZE_IDENTITY_OPAQUE",
        "message": f"{engine} reported a component that could not be identified",
        "hint": (
            "counted in unidentified_count and kept in the coverage denominator; "
            "it will not merge with anything"
        ),
        "component_key": identity.key,
    }


# -- shared helpers -------------------------------------------------------

#: Characters that must never reach Postgres in a path.
#:
#: A NUL byte SILENTLY TRUNCATES a Postgres text value — the row inserts, no
#: error is raised, and the stored path is a prefix of the real one. User
#: repositories do contain these (spec §8).
_HOSTILE = re.compile(r"[\x00-\x1f\x7f]")

#: Longest path stored. Truncation is explicit and marked so a reader can tell
#: a shortened path from a real one.
MAX_PATH = 1024


def normalize_path(path: str) -> str:
    """Make a repository path safe to store and compare.

    Sanitized BEFORE insert, not after: the damage a NUL does happens at the
    database boundary, and by the time the row is read back the information is
    already gone.
    """
    cleaned = _HOSTILE.sub("", path).replace("\\", "/").strip()
    while "//" in cleaned:
        cleaned = cleaned.replace("//", "/")
    cleaned = cleaned.lstrip("./").removeprefix("/")
    if len(cleaned) > MAX_PATH:
        # The marker matters: a silently truncated path looks like a real path
        # to a different file.
        cleaned = cleaned[: MAX_PATH - 12] + "…[truncated]"
    return cleaned


def _first_str(raw: dict[str, Any], *keys: str) -> str:
    for key in keys:
        value = raw.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


def _str(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""
