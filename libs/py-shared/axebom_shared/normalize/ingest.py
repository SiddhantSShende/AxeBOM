"""Parsers from each engine's native output into normalizer input.

⚠ THIS IS THE LAYER THAT MUST NEVER RAISE ON UNEXPECTED SHAPE.

These parsers read third-party output that changes on someone else's schedule.
A shape change must degrade to reduced coverage — loudly — not crash a
normalization run and lose every other engine's contribution along with it.

So every accessor is defensive, every missing field produces a diagnostic rather
than an exception, and an unparseable document yields an empty contribution with
a diagnostic explaining that it was unparseable.

⚠ AND IT MUST NEVER INVENT. Where a field is absent, the value is absent — not
guessed, not defaulted to something plausible. A fabricated supplier or licence
lands in a compliance artifact.

See `docs/04-OSINT-INTEGRATION.md` §4 for the output→canonical mapping.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .findings import CvssVector, RawFinding
from .graph import Edge
from .identity import Identity, opaque_diagnostic
from .identity import resolve as resolve_identity
from .licenses import LicenseSet
from .licenses import resolve as resolve_license
from .merge import Contribution, Location, Observation
from .purl import PurlError
from .purl import parse as parse_purl


@dataclass
class Ingested:
    """Everything one engine's artifact contributed."""

    contributions: list[Contribution] = field(default_factory=list)
    findings: list[RawFinding] = field(default_factory=list)
    edges: list[Edge] = field(default_factory=list)
    #: bom-ref -> component_key, so dependency edges can be resolved to keys.
    ref_to_key: dict[str, str] = field(default_factory=dict)
    roots: list[str] = field(default_factory=list)
    diagnostics: list[dict[str, Any]] = field(default_factory=list)


def ingest(
    engine: str,
    payload: Any,
    *,
    scan_id: str,
    engine_version: str = "",
    trusted_graph_ecosystems: frozenset[str] = frozenset(),
) -> Ingested:
    """Dispatch to the right parser for this engine's native format."""
    parser = _PARSERS.get(engine)
    if parser is None:
        return Ingested(
            diagnostics=[
                {
                    "severity": "warn",
                    "code": "NORMALIZE_NO_PARSER",
                    "message": f"no normalizer parser for engine {engine!r}",
                    "hint": "its raw artifact is stored but contributes nothing to the BOM",
                }
            ]
        )

    if not isinstance(payload, dict):
        return Ingested(
            diagnostics=[
                {
                    "severity": "error",
                    "code": "NORMALIZE_ARTIFACT_UNPARSEABLE",
                    "message": f"{engine} artifact is not a JSON object",
                }
            ]
        )

    return parser(
        payload,
        engine=engine,
        scan_id=scan_id,
        engine_version=engine_version,
        trusted=trusted_graph_ecosystems,
    )


# -- CycloneDX (syft, trivy-fs, trivy-image) ------------------------------


def _ingest_cyclonedx(
    payload: dict[str, Any],
    *,
    engine: str,
    scan_id: str,
    engine_version: str,
    trusted: frozenset[str],
) -> Ingested:
    out = Ingested()

    components = payload.get("components")
    if not isinstance(components, list):
        out.diagnostics.append(
            {
                "severity": "warn",
                "code": "ENGINE_FIELD_MISSING",
                "message": f"{engine} output has no `components` array",
                "hint": "treated as zero components; the output shape may have changed",
            }
        )
        components = []

    for entry in components:
        if not isinstance(entry, dict):
            continue

        identity = resolve_identity(entry, scan_id=scan_id, engine=engine)
        if identity.is_opaque:
            out.diagnostics.append(opaque_diagnostic(identity, engine))

        ref = str(entry.get("bom-ref") or entry.get("bomRef") or "")
        if ref:
            out.ref_to_key[ref] = identity.key

        out.contributions.append(
            Contribution(
                identity=identity,
                observation=Observation(
                    engine=engine,
                    engine_version=engine_version,
                    native_id=ref,
                    confidence=identity.confidence,
                ),
                locations=_cyclonedx_locations(entry),
                hashes=_cyclonedx_hashes(entry),
                licenses=_cyclonedx_licenses(entry),
                scope=_cyclonedx_scope(entry),
                is_direct_from_trusted_graph=False,
                cpes=_cyclonedx_cpes(entry, engine),
            )
        )

    # ⚠ The dependency graph is only claimed for ecosystems this engine is
    # TRUSTED for. Contributing edges everywhere would then get replaced anyway,
    # but claiming them is what makes `merge_edges` unable to tell a real graph
    # from a flat inventory.
    for edge in _cyclonedx_dependencies(payload, out.ref_to_key, engine, trusted):
        out.edges.append(edge)

    metadata = payload.get("metadata")
    if isinstance(metadata, dict):
        root = metadata.get("component")
        if isinstance(root, dict):
            ref = str(root.get("bom-ref") or root.get("bomRef") or "")
            if ref and ref in out.ref_to_key:
                out.roots.append(out.ref_to_key[ref])

    return out


def _cyclonedx_locations(entry: dict[str, Any]) -> list[Location]:
    """Extract locations from syft's property bag.

    syft records paths as `syft:location:N:path` properties rather than a
    dedicated field, so they have to be pulled out by prefix.
    """
    locations: list[Location] = []
    properties = entry.get("properties")
    if isinstance(properties, list):
        for prop in properties:
            if not isinstance(prop, dict):
                continue
            name = str(prop.get("name", ""))
            if "location" in name and name.endswith(":path"):
                value = str(prop.get("value", "")).strip()
                if value:
                    locations.append(Location(path=value))
    return locations


def _cyclonedx_hashes(entry: dict[str, Any]) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    hashes = entry.get("hashes")
    if isinstance(hashes, list):
        for item in hashes:
            if isinstance(item, dict):
                alg = str(item.get("alg", "")).strip()
                value = str(item.get("content") or item.get("value") or "").strip()
                if alg and value:
                    out.append({"alg": alg.lower().replace("-", ""), "value": value})
    return out


def _cyclonedx_licenses(entry: dict[str, Any]) -> LicenseSet:
    """Read CycloneDX licences into the three-kind model.

    ⚠ CycloneDX does not distinguish declared from concluded, so everything here
    lands as `declared`. Inventing a `concluded` value from a manifest field
    would misrepresent how the licence was determined — and `concluded` is the
    one a reviewer trusts more.
    """
    licenses = LicenseSet()
    entries = entry.get("licenses")
    if not isinstance(entries, list):
        return licenses

    for item in entries:
        if not isinstance(item, dict):
            continue
        expression = item.get("expression")
        if isinstance(expression, str) and expression.strip():
            licenses.declared = resolve_license(expression)
            continue
        lic = item.get("license")
        if isinstance(lic, dict):
            value = lic.get("id") or lic.get("name")
            if isinstance(value, str) and value.strip():
                licenses.declared = resolve_license(value)
    return licenses


#: CycloneDX component types that are EVIDENCE rather than dependencies.
#:
#: syft catalogues the lockfile itself as `type: file`. It belongs in the BOM —
#: it is what the inventory was derived from — but a customer asking "how many
#: dependencies do I have?" does not want package-lock.json in that number.
#:
#: Marked `excluded` rather than dropped: per spec §5.4 an excluded component
#: stays in the coverage denominator, so it cannot be used to quietly improve a
#: percentage, and nothing is silently lost.
_NON_DEPENDENCY_TYPES = frozenset({"file", "operating-system", "device", "firmware"})


def _cyclonedx_scope(entry: dict[str, Any]) -> str:
    declared = str(entry.get("scope", "")).strip().lower()
    if declared in ("required", "optional", "excluded"):
        return declared
    if str(entry.get("type", "")).strip().lower() in _NON_DEPENDENCY_TYPES:
        return "excluded"
    return "required"


def _cyclonedx_cpes(entry: dict[str, Any], engine: str) -> list[tuple[str, str]]:
    """Collect CPEs as candidate identities.

    Confidence is `medium` for an engine that derives CPEs deterministically
    from a PURL (syft) — it is still a claim, and it still attaches without
    merging when a PURL is present.
    """
    out: list[tuple[str, str]] = []
    cpe = entry.get("cpe")
    if isinstance(cpe, str) and cpe.strip():
        out.append((cpe.strip(), "medium"))
    return out


def _cyclonedx_dependencies(
    payload: dict[str, Any],
    ref_to_key: dict[str, str],
    engine: str,
    trusted: frozenset[str],
) -> list[Edge]:
    out: list[Edge] = []
    dependencies = payload.get("dependencies")
    if not isinstance(dependencies, list):
        return out

    for entry in dependencies:
        if not isinstance(entry, dict):
            continue
        source_ref = str(entry.get("ref", ""))
        source_key = ref_to_key.get(source_ref)
        if not source_key:
            continue
        for target_ref in entry.get("dependsOn", []) or []:
            target_key = ref_to_key.get(str(target_ref))
            if not target_key:
                continue
            ecosystem = _ecosystem_of_key(target_key)
            out.append(
                Edge(
                    from_key=source_key,
                    to_key=target_key,
                    relationship="depends_on",
                    owning_engine=engine,
                    ecosystem=ecosystem,
                    confidence="high" if ecosystem in trusted else "low",
                )
            )
    return out


# -- SPDX (syft-spdx) -----------------------------------------------------


def _ingest_spdx(
    payload: dict[str, Any],
    *,
    engine: str,
    scan_id: str,
    engine_version: str,
    trusted: frozenset[str],
) -> Ingested:
    out = Ingested()

    packages = payload.get("packages")
    if not isinstance(packages, list):
        out.diagnostics.append(
            {
                "severity": "warn",
                "code": "ENGINE_FIELD_MISSING",
                "message": f"{engine} output has no `packages` array",
            }
        )
        packages = []

    described = _spdx_described_refs(payload)

    for entry in packages:
        if not isinstance(entry, dict):
            continue

        spdx_id_raw = str(entry.get("SPDXID", ""))

        # ⚠ THE DOCUMENT ROOT IS THE SCAN TARGET, NOT A COMPONENT.
        #
        # syft emits `SPDXRef-DocumentRoot-Directory--src` describing the
        # directory it scanned. It has no PURL and no version, so it would fall
        # to the name rule and appear in the report as a dependency called
        # "/src" — a component the customer does not have.
        #
        # It becomes a ROOT instead, which is also what the graph needs.
        if _is_spdx_document_root(spdx_id_raw, entry, described):
            out.diagnostics.append(
                {
                    "severity": "info",
                    "code": "NORMALIZE_SPDX_DOCUMENT_ROOT",
                    "message": f"{spdx_id_raw} describes the scan target, not a component",
                    "hint": "recorded as a dependency-graph root rather than an inventory entry",
                }
            )
            continue

        record = dict(entry)
        record["name"] = entry.get("name", "")
        record["version"] = entry.get("versionInfo", "")

        # SPDX carries the PURL in externalRefs rather than a top-level field.
        for ref in entry.get("externalRefs", []) or []:
            if not isinstance(ref, dict):
                continue
            if str(ref.get("referenceType", "")).lower() == "purl":
                record["purl"] = ref.get("referenceLocator", "")
            elif "cpe" in str(ref.get("referenceType", "")).lower():
                record.setdefault("cpes", []).append(ref.get("referenceLocator", ""))

        identity = resolve_identity(record, scan_id=scan_id, engine=engine)
        if identity.is_opaque:
            out.diagnostics.append(opaque_diagnostic(identity, engine))

        spdx_id = str(entry.get("SPDXID", ""))
        if spdx_id:
            out.ref_to_key[spdx_id] = identity.key

        # ⚠ SPDX DISTINGUISHES declared FROM concluded, and this is the one
        # format that does. Collapsing them here would throw away exactly the
        # distinction reviewers ask for.
        licenses = LicenseSet()
        declared = entry.get("licenseDeclared")
        if isinstance(declared, str) and declared.strip():
            licenses.declared = resolve_license(declared)
        concluded = entry.get("licenseConcluded")
        if isinstance(concluded, str) and concluded.strip():
            licenses.concluded = resolve_license(concluded)

        out.contributions.append(
            Contribution(
                identity=identity,
                observation=Observation(
                    engine=engine,
                    engine_version=engine_version,
                    native_id=spdx_id,
                    confidence=identity.confidence,
                ),
                locations=[],
                hashes=_spdx_hashes(entry),
                licenses=licenses,
                cpes=[(c, "medium") for c in record.get("cpes", []) if c],
            )
        )

    return out


def _spdx_described_refs(payload: dict[str, Any]) -> set[str]:
    """SPDX ids the document explicitly describes."""
    refs: set[str] = set()
    for value in payload.get("documentDescribes", []) or []:
        if isinstance(value, str):
            refs.add(value)
    for rel in payload.get("relationships", []) or []:
        if not isinstance(rel, dict):
            continue
        if str(rel.get("relationshipType", "")).upper() == "DESCRIBES":
            target = rel.get("relatedSpdxElement")
            if isinstance(target, str):
                refs.add(target)
    return refs


def _is_spdx_document_root(spdx_id: str, entry: dict[str, Any], described: set[str]) -> bool:
    """Whether this package is the scanned target rather than a dependency.

    Recognised by the SPDXID prefix syft uses, or by being DESCRIBES-ed by the
    document while carrying no PURL and no version — the shape of a scan target
    rather than a package.
    """
    if spdx_id.startswith("SPDXRef-DocumentRoot-"):
        return True
    if spdx_id not in described:
        return False
    has_purl = any(
        isinstance(ref, dict) and str(ref.get("referenceType", "")).lower() == "purl"
        for ref in entry.get("externalRefs", []) or []
    )
    return not has_purl and not str(entry.get("versionInfo", "")).strip()


def _spdx_hashes(entry: dict[str, Any]) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    for item in entry.get("checksums", []) or []:
        if isinstance(item, dict):
            alg = str(item.get("algorithm", "")).lower().replace("-", "")
            value = str(item.get("checksumValue", "")).strip()
            if alg and value:
                out.append({"alg": alg, "value": value})
    return out


# -- grype ----------------------------------------------------------------


def _ingest_grype(
    payload: dict[str, Any],
    *,
    engine: str,
    scan_id: str,
    engine_version: str,
    trusted: frozenset[str],
) -> Ingested:
    out = Ingested()

    matches = payload.get("matches")
    if not isinstance(matches, list):
        out.diagnostics.append(
            {
                "severity": "warn",
                "code": "ENGINE_FIELD_MISSING",
                "message": "grype output has no `matches` array",
            }
        )
        matches = []

    for match in matches:
        if not isinstance(match, dict):
            continue
        vuln = match.get("vulnerability")
        artifact = match.get("artifact")
        if not isinstance(vuln, dict) or not isinstance(artifact, dict):
            continue

        identity = resolve_identity(artifact, scan_id=scan_id, engine=engine)

        # ⚠ grype matches against OUR syft SBOM, so it re-states components syft
        # already reported. They are contributed so `observed_by` records that
        # grype saw them — the merge collapses them onto syft's entry by key.
        out.contributions.append(
            Contribution(
                identity=identity,
                observation=Observation(
                    engine=engine,
                    engine_version=engine_version,
                    native_id=str(artifact.get("id", "")),
                    confidence=identity.confidence,
                ),
                locations=[
                    Location(path=str(loc.get("path", "")))
                    for loc in artifact.get("locations", []) or []
                    if isinstance(loc, dict) and loc.get("path")
                ],
            )
        )

        out.findings.append(
            RawFinding(
                vuln_id=str(vuln.get("id", "")),
                component_key=identity.key,
                engine=engine,
                engine_version=engine_version,
                severity=str(vuln.get("severity", "")),
                cvss=_grype_cvss(vuln),
                fixed_versions=_grype_fix_versions(vuln),
                ecosystem=identity.ecosystem or _ecosystem_of_key(identity.key),
                native_id=str(vuln.get("id", "")),
                description=str(vuln.get("description", ""))[:2000],
            )
        )

    return out


def _grype_cvss(vuln: dict[str, Any]) -> list[CvssVector]:
    out: list[CvssVector] = []
    for entry in vuln.get("cvss", []) or []:
        if not isinstance(entry, dict):
            continue
        metrics = entry.get("metrics")
        score = None
        if isinstance(metrics, dict):
            raw = metrics.get("baseScore")
            if isinstance(raw, (int, float)):
                score = float(raw)
        out.append(
            CvssVector(
                version=str(entry.get("version", "")),
                vector=str(entry.get("vector", "")),
                score=score,
                # ⚠ The severity WORD is not derived from the score here.
                # Mapping a score to a band is a per-version judgement, and
                # doing it wrong across versions is exactly the cross-scale
                # error the precedence ladder exists to avoid.
                severity=str(vuln.get("severity", "")),
                source=str(entry.get("type", "") or vuln.get("namespace", "")),
            )
        )
    return out


def _grype_fix_versions(vuln: dict[str, Any]) -> list[str]:
    fix = vuln.get("fix")
    if not isinstance(fix, dict):
        return []
    versions = fix.get("versions")
    if not isinstance(versions, list):
        return []
    return [str(v) for v in versions if isinstance(v, str) and v.strip()]


# -- osv-scanner ----------------------------------------------------------


def _ingest_osv(
    payload: dict[str, Any],
    *,
    engine: str,
    scan_id: str,
    engine_version: str,
    trusted: frozenset[str],
) -> Ingested:
    out = Ingested()

    results = payload.get("results")
    if not isinstance(results, list):
        return out

    for entry in results:
        if not isinstance(entry, dict):
            continue
        source_path = ""
        source = entry.get("source")
        if isinstance(source, dict):
            source_path = str(source.get("path", ""))

        for pkg in entry.get("packages", []) or []:
            if not isinstance(pkg, dict):
                continue
            info = pkg.get("package")
            if not isinstance(info, dict):
                continue

            record = {
                "name": info.get("name", ""),
                "version": info.get("version", ""),
                "ecosystem": _osv_ecosystem(str(info.get("ecosystem", ""))),
            }
            # osv-scanner does not emit a PURL on the package, so one is built
            # from its own fields rather than left unidentified — the ecosystem
            # and name come straight from the tool, nothing is invented.
            purl = _osv_purl(record["ecosystem"], str(record["name"]), str(record["version"]))
            if purl:
                record["purl"] = purl

            identity = resolve_identity(record, scan_id=scan_id, engine=engine)

            out.contributions.append(
                Contribution(
                    identity=identity,
                    observation=Observation(
                        engine=engine,
                        engine_version=engine_version,
                        native_id=f"{record['name']}@{record['version']}",
                        confidence=identity.confidence,
                    ),
                    locations=[Location(path=source_path)] if source_path else [],
                )
            )

            for vuln in pkg.get("vulnerabilities", []) or []:
                if not isinstance(vuln, dict):
                    continue
                out.findings.append(
                    RawFinding(
                        vuln_id=str(vuln.get("id", "")),
                        component_key=identity.key,
                        engine=engine,
                        engine_version=engine_version,
                        severity=_osv_severity(pkg, str(vuln.get("id", ""))),
                        cvss=_osv_cvss(vuln),
                        fixed_versions=_osv_fixed_versions(vuln),
                        ecosystem=str(record["ecosystem"]),
                        native_id=str(vuln.get("id", "")),
                        description=str(vuln.get("summary", ""))[:2000],
                    )
                )

    return out


def _osv_ecosystem(value: str) -> str:
    """Map OSV's ecosystem names onto PURL types.

    OSV writes `PyPI`, `Go` and `Maven`; PURL writes `pypi`, `golang`, `maven`.
    Leaving them unmapped would create parallel ecosystems in the coverage table
    and stop osv's components merging with syft's.
    """
    lowered = value.strip().lower()
    return {
        "pypi": "pypi",
        "go": "golang",
        "maven": "maven",
        "npm": "npm",
        "crates.io": "cargo",
        "rubygems": "gem",
        "nuget": "nuget",
        "packagist": "composer",
        "hex": "hex",
        "pub": "pub",
    }.get(lowered, lowered)


def _osv_purl(ecosystem: str, name: str, version: str) -> str:
    """Build a PURL from osv-scanner's own fields.

    ⚠ Maven names arrive as `group:artifact` and must become `group/artifact`,
    or the PURL is malformed and the component falls to a weaker identity that
    will not merge with syft's.
    """
    if not ecosystem or not name:
        return ""
    if ecosystem == "maven" and ":" in name:
        name = name.replace(":", "/", 1)
    return f"pkg:{ecosystem}/{name}@{version}" if version else f"pkg:{ecosystem}/{name}"


def _osv_severity(pkg: dict[str, Any], vuln_id: str) -> str:
    """osv-scanner reports severity per GROUP, not per vulnerability."""
    for group in pkg.get("groups", []) or []:
        if not isinstance(group, dict):
            continue
        if vuln_id in (group.get("ids") or []):
            value = group.get("max_severity")
            if isinstance(value, str) and value.strip():
                return _severity_from_score(value)
    return ""


def _severity_from_score(value: str) -> str:
    """Map a CVSS base score to a severity band.

    ⚠ CVSS v3.1 BANDS, and only used where osv gives a bare number with no
    version. It is recorded as a `vendor-string`-level signal precisely because
    it is the weakest step in the precedence ladder.
    """
    try:
        score = float(value)
    except (TypeError, ValueError):
        return ""
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return "none"


def _osv_cvss(vuln: dict[str, Any]) -> list[CvssVector]:
    out: list[CvssVector] = []
    for entry in vuln.get("severity", []) or []:
        if not isinstance(entry, dict):
            continue
        kind = str(entry.get("type", ""))
        vector = str(entry.get("score", ""))
        version = "4.0" if "V4" in kind.upper() else "3.1" if "V3" in kind.upper() else ""
        out.append(
            CvssVector(
                version=version,
                vector=vector,
                score=None,
                severity="",
                source="osv.dev",
            )
        )
    return out


def _osv_fixed_versions(vuln: dict[str, Any]) -> list[str]:
    out: list[str] = []
    for affected in vuln.get("affected", []) or []:
        if not isinstance(affected, dict):
            continue
        for rng in affected.get("ranges", []) or []:
            if not isinstance(rng, dict):
                continue
            for event in rng.get("events", []) or []:
                if isinstance(event, dict) and event.get("fixed"):
                    out.append(str(event["fixed"]))
    return sorted(set(out))


# -- shared ---------------------------------------------------------------


def _ecosystem_of_key(key: str) -> str:
    """Recover the ecosystem from a component key, best effort."""
    if not key.startswith("purl:"):
        return ""
    try:
        return parse_purl(key[5:]).ecosystem
    except PurlError:
        return ""


_PARSERS = {
    "syft": _ingest_cyclonedx,
    "trivy-fs": _ingest_cyclonedx,
    "trivy-image": _ingest_cyclonedx,
    "syft-spdx": _ingest_spdx,
    "grype": _ingest_grype,
    "osv-scanner": _ingest_osv,
}


def supported_engines() -> list[str]:
    return sorted(_PARSERS)


def identity_of(raw: dict[str, Any], *, scan_id: str, engine: str) -> Identity:
    """Exposed for tests that need the identity without a full ingest."""
    return resolve_identity(raw, scan_id=scan_id, engine=engine)
