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

import re
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

    findings, finding_diagnostics = _cyclonedx_vulnerabilities(
        payload, out.ref_to_key, engine=engine, engine_version=engine_version
    )
    out.findings.extend(findings)
    out.diagnostics.extend(finding_diagnostics)

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

    kind = str(entry.get("type", "")).strip().lower()
    if kind in _NON_DEPENDENCY_TYPES:
        return "excluded"

    # ⚠ AN `application` WITH NO PURL IS A MANIFEST ROOT, NOT A DEPENDENCY.
    #
    # cdxgen emits one `application` component per manifest it finds, named
    # after the FILE — `package-lock.json`, `services/auth-svc/requirements.txt`,
    # `services/ws-gateway/go.mod`. Found live: 31 such rows counted as
    # `required` dependencies across this stack's scans, identified by NAME at
    # LOW confidence because they have nothing else.
    #
    # They are the same kind of thing the `file` rule above already excludes —
    # evidence the inventory was derived FROM — and the comment there applies
    # verbatim: a customer asking "how many dependencies do I have?" does not
    # want package-lock.json in that number.
    #
    # ⚠ THE `not purl` CONDITION IS LOAD-BEARING, not belt-and-braces. A
    # genuinely bundled application IS a dependency and carries a purl; only the
    # synthetic manifest roots lack one. Excluding every `application` would
    # drop real components.
    #
    # ⚠ AND THIS CANNOT FLATTER A PERCENTAGE. An excluded component goes to
    # `unidentified_count` and STAYS IN THE DENOMINATOR (§5.4) — so this changes
    # the dependency count and the level projections, and moves neither coverage
    # number. Verified before making the change, because "it improves the score"
    # would have been a reason not to.
    if kind == "application" and not str(entry.get("purl", "")).strip():
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


def _cyclonedx_vulnerabilities(
    payload: dict[str, Any],
    ref_to_key: dict[str, str],
    *,
    engine: str,
    engine_version: str,
) -> tuple[list[RawFinding], list[dict[str, Any]]]:
    """Read CycloneDX 1.6's top-level `vulnerabilities` array.

    syft never sets this; trivy-fs and trivy-image do (`--scanners vuln,...`),
    and until this existed their real findings were parsed for components only
    and silently dropped — not marked unavailable, just gone.

    ⚠ NO `fixed_versions` HERE. `affects[].versions[].status` has no clean
    "fixed" event the way OSV's `ranges[].events[].fixed` does — only
    `affected`/`unaffected`/`unknown` against a version list. Guessing a
    minimum fix from that would be exactly the fabrication `findings.py`
    forbids; `fixed_versions` stays empty and `resolve_fix_version` reports
    `unknown` honestly instead.
    """
    findings: list[RawFinding] = []
    diagnostics: list[dict[str, Any]] = []

    vulnerabilities = payload.get("vulnerabilities")
    if not isinstance(vulnerabilities, list):
        return findings, diagnostics

    for entry in vulnerabilities:
        if not isinstance(entry, dict):
            continue
        vuln_id = str(entry.get("id", "")).strip()
        if not vuln_id:
            continue

        affects = entry.get("affects")
        if not isinstance(affects, list) or not affects:
            continue

        cvss = _cyclonedx_cvss(entry)
        description = str(entry.get("description", ""))[:2000]
        severity = _cyclonedx_vendor_severity(entry)

        for affected in affects:
            if not isinstance(affected, dict):
                continue
            ref = str(affected.get("ref", ""))
            component_key = ref_to_key.get(ref)
            if not component_key:
                # A dangling `affects.ref` is evidence of an ingest bug (a ref
                # this parser's own component walk should have seen) rather
                # than a normal case — surfaced, not silently skipped.
                diagnostics.append(
                    {
                        "severity": "warn",
                        "code": "ENGINE_FIELD_MISSING",
                        "message": (
                            f"{engine} vulnerability {vuln_id!r} affects ref "
                            f"{ref!r}, which does not match any reported component"
                        ),
                        "hint": "the finding was dropped; the output shape may have changed",
                    }
                )
                continue

            findings.append(
                RawFinding(
                    vuln_id=vuln_id,
                    component_key=component_key,
                    engine=engine,
                    engine_version=engine_version,
                    severity=severity,
                    cvss=cvss,
                    fixed_versions=[],
                    ecosystem=_ecosystem_of_key(component_key),
                    native_id=vuln_id,
                    description=description,
                )
            )

    return findings, diagnostics


#: CycloneDX `ratings[].method` -> the CVSS version string the rest of the
#: normalizer expects (matching what the grype/osv parsers already produce).
_CVSS_METHOD_VERSION = {
    "cvssv2": "2.0",
    "cvssv3": "3.0",
    "cvssv31": "3.1",
    "cvssv4": "4.0",
}


def _cyclonedx_cvss(entry: dict[str, Any]) -> list[CvssVector]:
    out: list[CvssVector] = []
    for rating in entry.get("ratings", []) or []:
        if not isinstance(rating, dict):
            continue
        method = str(rating.get("method", "")).strip().lower()
        version = _CVSS_METHOD_VERSION.get(method, "")
        if not version:
            # A rating with no recognised CVSS method (e.g. a bare vendor
            # severity word with no `method`) carries no numeric vector worth
            # keeping here — it is picked up by `_cyclonedx_vendor_severity`
            # instead rather than invented a version for.
            continue
        score = rating.get("score")
        source = rating.get("source")
        source_name = str(source.get("name", "")) if isinstance(source, dict) else ""
        out.append(
            CvssVector(
                version=version,
                vector=str(rating.get("vector", "")),
                score=float(score) if isinstance(score, (int, float)) else None,
                severity=str(rating.get("severity", "")),
                source=source_name,
            )
        )
    return out


def _cyclonedx_vendor_severity(entry: dict[str, Any]) -> str:
    """The first rating's severity word, as a vendor-string fallback.

    Mirrors `_grype_cvss`'s discipline: the severity WORD is read from the
    engine's own assertion, never derived by mapping a score to a band here.
    """
    for rating in entry.get("ratings", []) or []:
        if isinstance(rating, dict):
            severity = str(rating.get("severity", "")).strip()
            if severity:
                return severity
    return ""


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


# -- webrecon-fingerprint (services/webrecon) ------------------------------


def _ingest_webrecon_fingerprint(
    payload: dict[str, Any],
    *,
    engine: str,
    scan_id: str,
    engine_version: str,
    trusted: frozenset[str],
) -> Ingested:
    """Parse services/webrecon's own JSON shape — never a CycloneDX or SPDX
    document, because there is no "native" format for a retire.js-style
    fingerprint result. See docs/04-OSINT-INTEGRATION.md §4's webrecon
    subsection for the field-by-field mapping this mirrors.

    Version-range evaluation (does this library's version fall inside a
    known-vulnerable range) already happened in Go
    (services/webrecon/internal/fingerprint/retire.go's vulnerableAt) before
    this JSON was ever written — every entry in a library's
    `vulnerabilities[]` here is already applicable to the detected version,
    not re-evaluated.
    """
    out = Ingested()

    hosts = payload.get("hosts")
    if not isinstance(hosts, list):
        out.diagnostics.append(
            {
                "severity": "warn",
                "code": "ENGINE_FIELD_MISSING",
                "message": f"{engine} output has no `hosts` array",
            }
        )
        return out

    for host_entry in hosts:
        if not isinstance(host_entry, dict):
            continue
        host = str(host_entry.get("host", ""))
        fetched_url = str(host_entry.get("fetched_url", ""))
        location_path = fetched_url or host

        for lib in host_entry.get("libraries", []) or []:
            if not isinstance(lib, dict):
                continue
            name = str(lib.get("name", ""))
            version = str(lib.get("version", ""))
            if not name:
                continue

            record = {
                "name": name,
                "version": version,
                "ecosystem": "npm",
            }
            purl = str(lib.get("npm_purl") or "")
            if purl:
                record["purl"] = purl

            identity = resolve_identity(record, scan_id=scan_id, engine=engine)

            out.contributions.append(
                Contribution(
                    identity=identity,
                    observation=Observation(
                        engine=engine,
                        engine_version=engine_version,
                        native_id=f"{name}@{version}",
                        confidence=identity.confidence,
                    ),
                    locations=[Location(path=location_path)] if location_path else [],
                )
            )

            for vuln in lib.get("vulnerabilities", []) or []:
                if not isinstance(vuln, dict):
                    continue
                cve_list = [str(c) for c in (vuln.get("cve") or []) if c]
                ghsa = str(vuln.get("ghsa") or "")
                # A CVE is preferred as the primary id — the same precedence
                # every other ingest path in this file gives it — falling
                # back to the GHSA advisory id when retire.js recorded no
                # CVE for this entry.
                vuln_id = cve_list[0] if cve_list else ghsa
                if not vuln_id:
                    continue

                out.findings.append(
                    RawFinding(
                        vuln_id=vuln_id,
                        component_key=identity.key,
                        engine=engine,
                        engine_version=engine_version,
                        severity=str(vuln.get("severity", "")),
                        ecosystem="npm",
                        native_id=vuln_id,
                        description=str(vuln.get("summary", ""))[:2000],
                    )
                )

    return out


# -- dependency-check -------------------------------------------------------


def _ingest_dependency_check(
    payload: dict[str, Any],
    *,
    engine: str,
    scan_id: str,
    engine_version: str,
    trusted: frozenset[str],
) -> Ingested:
    """Parse OWASP Dependency-Check's JSON report.

    ⚠ THIS FILE'S SCHEMA HAS SHIFTED BETWEEN MAJOR VERSIONS (the adapter's own
    `highest_confidence()` says so). Every accessor here is defensive for the
    same reason the rest of this module is: an unrecognised shape degrades to
    a diagnostic, never a crash.

    Identity: `packages[].id` is fed to the normal `resolve_identity` chain
    when it looks like a real PURL (rule 1, high confidence) — dependency-check
    does emit these when a manifest match was possible. Otherwise the
    dependency's own `vulnerabilityIds[]` (the CPEs it matched against to find
    vulnerabilities) is offered as `cpe`, which resolves via rule 2 (medium
    confidence, a DIFFERENT key namespace from any `purl:` key — so it
    structurally cannot merge into a PURL-identified component, which is the
    whole point of this engine's confidence story).
    """
    out = Ingested()

    dependencies = payload.get("dependencies")
    if not isinstance(dependencies, list):
        out.diagnostics.append(
            {
                "severity": "warn",
                "code": "ENGINE_FIELD_MISSING",
                "message": f"{engine} output has no `dependencies` array",
                "hint": "treated as zero components; the output shape may have changed",
            }
        )
        dependencies = []

    for dep in dependencies:
        if not isinstance(dep, dict):
            continue

        record = _dependency_check_identity_record(dep)
        if record is None:
            # Neither a usable PURL nor a CPE — this dependency contributed no
            # identifying evidence at all (dependency-check reports one entry
            # per file it opened, including ones it could not identify).
            continue

        identity = resolve_identity(record, scan_id=scan_id, engine=engine)
        if identity.is_opaque:
            out.diagnostics.append(opaque_diagnostic(identity, engine))

        out.contributions.append(
            Contribution(
                identity=identity,
                observation=Observation(
                    engine=engine,
                    engine_version=engine_version,
                    native_id=str(dep.get("sha256") or dep.get("fileName") or ""),
                    confidence=identity.confidence,
                ),
                locations=(
                    [Location(path=str(dep["filePath"]))]
                    if isinstance(dep.get("filePath"), str) and dep["filePath"].strip()
                    else []
                ),
                hashes=_dependency_check_hashes(dep),
            )
        )

        vulns = dep.get("vulnerabilities")
        if not isinstance(vulns, list):
            continue
        for vuln in vulns:
            if not isinstance(vuln, dict):
                continue
            vuln_id = str(vuln.get("name", "")).strip()
            if not vuln_id:
                continue
            out.findings.append(
                RawFinding(
                    vuln_id=vuln_id,
                    component_key=identity.key,
                    engine=engine,
                    engine_version=engine_version,
                    severity=str(vuln.get("severity", "")),
                    cvss=_dependency_check_cvss(vuln),
                    # No structured "fixed version" concept exists in this
                    # engine's output — left empty rather than guessed.
                    fixed_versions=[],
                    ecosystem=identity.ecosystem or _ecosystem_of_key(identity.key),
                    native_id=vuln_id,
                    description=str(vuln.get("description", ""))[:2000],
                )
            )

    return out


def _dependency_check_identity_record(dep: dict[str, Any]) -> dict[str, Any] | None:
    packages = dep.get("packages")
    if isinstance(packages, list):
        for pkg in packages:
            if not isinstance(pkg, dict):
                continue
            pkg_id = str(pkg.get("id", "")).strip()
            if pkg_id.startswith("pkg:"):
                return {"purl": pkg_id}

    for vuln_ref in dep.get("vulnerabilityIds", []) or []:
        if not isinstance(vuln_ref, dict):
            continue
        cpe = str(vuln_ref.get("id", "")).strip()
        if cpe:
            return {"cpe": cpe, "name": str(dep.get("fileName", ""))}

    return None


def _dependency_check_hashes(dep: dict[str, Any]) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    sha256 = dep.get("sha256")
    if isinstance(sha256, str) and sha256.strip():
        out.append({"alg": "sha256", "value": sha256.strip()})
    return out


def _dependency_check_cvss(vuln: dict[str, Any]) -> list[CvssVector]:
    out: list[CvssVector] = []

    v3 = vuln.get("cvssv3")
    if isinstance(v3, dict):
        # Newer report versions nest the score fields under `cvssData`; older
        # ones put them directly on `cvssv3`. Both are tried rather than
        # picking one and silently losing the other.
        data = v3.get("cvssData") if isinstance(v3.get("cvssData"), dict) else v3
        score = data.get("baseScore")
        severity = data.get("baseSeverity") or v3.get("baseSeverity")
        vector = data.get("vectorString") or v3.get("vectorString")
        if score is not None or severity or vector:
            out.append(
                CvssVector(
                    version=_cvss_v3_version(data, v3, vector),
                    vector=str(vector or ""),
                    score=float(score) if isinstance(score, (int, float)) else None,
                    severity=str(severity or ""),
                    source="nvd",
                )
            )

    v2 = vuln.get("cvssv2")
    if isinstance(v2, dict):
        score = v2.get("score")
        severity = v2.get("severity")
        vector = v2.get("vectorString") or v2.get("accessVector")
        if score is not None or severity:
            out.append(
                CvssVector(
                    version="2.0",
                    vector=str(vector or ""),
                    score=float(score) if isinstance(score, (int, float)) else None,
                    severity=str(severity or ""),
                    source="nvd",
                )
            )

    return out


def _cvss_v3_version(data: dict[str, Any], v3: dict[str, Any], vector: Any) -> str:
    """The CVSS v3 point release, read from whatever the report actually
    asserts — 3.0 and 3.1 are structurally identical in Dependency-Check's
    `cvssv3` block, so this must never assume one.

    A `CVSS:3.x/...` vector-string prefix is the most direct signal a report
    can give — it is the source data itself, not a side field that could go
    stale. The newer `cvssData.version` field (report versions that mirror
    NVD's own schema) is the fallback. Left empty, never defaulted to "3.1",
    when neither is present: a version we did not observe is not a version we
    get to assert (CLAUDE.md — never fabricate a value the source lacks).
    """
    if isinstance(vector, str):
        match = re.match(r"CVSS:(3\.[01])/", vector)
        if match:
            return match.group(1)
    explicit = data.get("version") or v3.get("version")
    return str(explicit) if explicit else ""


# -- shared ---------------------------------------------------------------


def _ecosystem_of_key(key: str) -> str:
    """Recover the ecosystem from a component key, best effort."""
    if not key.startswith("purl:"):
        return ""
    try:
        return parse_purl(key[5:]).ecosystem
    except PurlError:
        return ""


#: Engines whose parsers contribute `RawFinding`s (as opposed to components
#: only). Shared with `cluster_store.py`'s pre-pass so the two modules cannot
#: independently drift on which engines' output is worth re-ingesting for
#: alias-graph seeding.
FINDING_ENGINES = frozenset(
    {"trivy-fs", "trivy-image", "grype", "osv-scanner", "dependency-check", "webrecon-fingerprint"}
)

_PARSERS = {
    "syft": _ingest_cyclonedx,
    # ⚠ cdxgen RAN ON EVERY SCAN AND EVERY COMPONENT IT FOUND WAS DISCARDED.
    #
    # It is a registered, dispatchable SBOM engine that succeeds in about two
    # seconds and writes a raw artifact — and it was absent from this map, so
    # `ingest()` returned zero contributions and a NORMALIZE_NO_PARSER
    # diagnostic. A 15.5 GB image pulled, stored and executed for nothing.
    #
    # Its native format is `cyclonedx-json-1.6`, which is exactly what
    # `_ingest_cyclonedx` already handles for syft and both trivy modes. No new
    # parser is written here for the same reason `github-dependency-graph-sbom`
    # reuses `_ingest_spdx` below: a bespoke one would be unverified against any
    # real captured fixture, and this document shape is already covered.
    "cdxgen": _ingest_cyclonedx,
    "trivy-fs": _ingest_cyclonedx,
    "trivy-image": _ingest_cyclonedx,
    "syft-spdx": _ingest_spdx,
    "grype": _ingest_grype,
    "osv-scanner": _ingest_osv,
    "dependency-check": _ingest_dependency_check,
    # The fetcher unwraps GitHub's `{"sbom": {...}}` envelope before ever
    # storing this artifact (services/fetcher/internal/work/work.go), so what
    # reaches this dispatch is a genuine, standalone SPDX 2.3 document —
    # exactly the shape _ingest_spdx already handles for syft-spdx. No new
    # parser needed, and none written: a bespoke one would be unverified
    # against any real captured GitHub fixture.
    "github-dependency-graph-sbom": _ingest_spdx,
    "webrecon-fingerprint": _ingest_webrecon_fingerprint,
}


def supported_engines() -> list[str]:
    return sorted(_PARSERS)


def identity_of(raw: dict[str, Any], *, scan_id: str, engine: str) -> Identity:
    """Exposed for tests that need the identity without a full ingest."""
    return resolve_identity(raw, scan_id=scan_id, engine=engine)
