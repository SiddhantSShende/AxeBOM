"""osv-scanner — lockfile-based vulnerability matching.

⚠ THE `aliases` FIELD IS THE POINT OF THIS ADAPTER.

osv-scanner is the AUTHORITATIVE SOURCE of vulnerability alias edges — the
GHSA↔CVE↔PYSEC↔GO links that Phase 8's union-find uses to decide two findings
are the same vulnerability. Grype emits GHSA, dependency-check emits CVE, trivy
emits both; naive dedup across them inflates counts roughly threefold.

Losing `aliases` here is expensive to notice later: nothing fails, the counts
are simply wrong, and they look plausible. So it is captured verbatim and
counted, and a result with no aliases at all carries a diagnostic.
"""

from __future__ import annotations

import re
from typing import Any

from encorebom_shared.adapters.base import Capabilities, GenerateResult, ResultStatus, ScanTarget
from encorebom_shared.adapters.summary import count_distinct_vulnerabilities, summarize
from encorebom_shared.sandbox import SandboxResult, WorkspaceLayout

from .common import SandboxedAdapter

CAPABILITIES = Capabilities(
    engine_id="osv-scanner",
    families=("sbom",),
    source_kinds=("git", "upload"),
    produces=("vulnerabilities",),
    native_format="osv-json",
    ecosystems=("npm", "pypi", "maven", "golang", "gem", "cargo", "nuget"),
    db_backed=True,
    default_weight=2,
)


class OSVScannerAdapter(SandboxedAdapter):
    """Runs osv-scanner over a source tree."""

    media_type = "application/json"
    requires_db_version = True
    database_id = "osv"

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(CAPABILITIES, **kwargs)

    def acceptable_exit_codes(self) -> frozenset[int]:
        """osv-scanner exits 1 when it finds vulnerabilities.

        0 means "scanned, nothing found"; 1 means "scanned, found something".
        Both are successful scans. Its error codes are 127 and above.

        ⚠ 128 IS NOT LISTED HERE, AND THAT IS DELIBERATE — see classify_nonzero.
        It means "no package sources found", which is a legitimate outcome for a
        repository with no lockfiles AND the symptom of a workspace the engine
        could not read. Those two must not be given the same status, so the
        decision needs the stderr, which acceptable_exit_codes cannot see.
        """
        return frozenset({0, 1})

    #: osv-scanner's exit code for "nothing to scan".
    NO_SOURCES_EXIT = 128

    def classify_nonzero(self, result: SandboxResult) -> tuple[ResultStatus, str, str] | None:
        """Separate "no lockfiles here" from "I could not see the tree".

        ⚠ THE SAME EXIT CODE AND THE SAME MESSAGE COVER BOTH, and they deserve
        opposite statuses. A repository that commits no lockfile — express, for
        one — has genuinely nothing for osv-scanner to match against, and
        reporting `failed` puts a false alarm in a compliance document. An empty
        or unreadable workspace produces the identical message, and reporting
        that as merely zero coverage would hide a real defect.

        The distinguishing signal is in stderr, which osv-scanner prints before
        giving up:

            End status: 69 dirs visited, 283 inodes visited, 0 Extract calls

        A walk that visited a real tree and found no manifests is a coverage
        gap. A walk that visited almost nothing did not see the source. Both
        cases were observed on this stack — the second while the archive was
        being mounted from a tmpfs the daemon could not read.

        Parsing stderr is fragile against upstream rewording, so the failure
        direction is chosen deliberately: an unparsed count falls through to
        `failed`, which overstates the problem visibly rather than
        understating it.
        """
        if result.exit_code != self.NO_SOURCES_EXIT:
            return None

        stderr = (result.stderr or "") + (result.stdout or "")
        if "no package sources found" not in stderr.lower():
            return None

        match = re.search(r"(\d+)\s+inodes visited", stderr)
        if match is None or int(match.group(1)) <= 1:
            return (
                ResultStatus.FAILED,
                "ENGINE_INPUT_UNREADABLE",
                "osv-scanner walked an empty tree; the workspace was not "
                "materialized or could not be read",
            )

        return (
            ResultStatus.PARTIAL,
            "ENGINE_ZERO_RESULTS",
            f"osv-scanner found no lockfiles to match against "
            f"({match.group(1)} inodes walked). It matches lockfiles only, so a "
            f"project that commits none is outside its coverage",
        )

    def database_env(self, database: Any) -> dict[str, str]:
        """Point osv-scanner at the provisioned database.

        There is no ``--db-path`` flag: osv-scanner reads the OS cache
        directory, so redirecting ``XDG_CACHE_HOME`` is the only way to steer
        it. It looks for ``$XDG_CACHE_HOME/osv-scalibr/<ecosystem>/all.zip``.
        """
        return {"XDG_CACHE_HOME": self.database_target}

    def build_argv(self, target: ScanTarget, layout: WorkspaceLayout) -> list[str]:
        """Scan lockfiles.

        `scan source` is the v2 subcommand. THE CLI CHANGED SHAPE ACROSS
        MAJORS — v1 took a bare path, v2 requires the subcommand — which is why
        the manifest pins an exact version and the nightly contract test exists.
        A drifted CLI here produces an exit code and no output, which the
        classifier reports as a failure rather than as zero vulnerabilities.

        ⚠ `-r` IS LOAD-BEARING. Without it osv-scanner visits ONE directory.
        On a monorepo — services/api, services/worker, libs/shared, tools/build
        — it would report on whatever sits at the root, find nothing, and exit
        0. The result is a clean-looking report for a repository that was
        essentially not scanned.

        ⚠ `--offline`, NOT `--offline-vulnerabilities`.

        This one is genuinely nasty. `--offline-vulnerabilities` is documented
        as "checks for vulnerabilities using local databases that are already
        cached", which is exactly what we want and exactly what it does not do:
        with a fully populated cache mounted and XDG_CACHE_HOME pointing at it,
        it loads NOTHING, matches NOTHING, prints `{"results": []}` and exits 0.
        No warning, no error.

        `--offline` on the same cache logs `Loaded npm local db from
        /enginedb/osv-scalibr/npm/all.zip` and returns real findings. The local
        matcher is only engaged by the full offline flag.

        The difference between the two flags is the difference between a report
        that lists a project's vulnerabilities and one that says it has none.
        Verified by running both against the same mount; see
        ``loaded_local_databases`` for the check that stops this recurring.
        """
        return [
            "scan",
            "source",
            "--format",
            "json",
            "--offline",
            "--no-resolve",
            "-r",
            layout.container_source,
        ]

    def interpret(
        self,
        target: ScanTarget,
        payload: Any,
        result: SandboxResult,
        base: GenerateResult,
    ) -> GenerateResult:
        if not isinstance(payload, dict):
            base.status = ResultStatus.FAILED
            base.diagnostics.append(
                {
                    "severity": "error",
                    "code": "ENGINE_OUTPUT_UNEXPECTED",
                    "message": "osv-scanner returned a document that is not a JSON object",
                }
            )
            return base

        results = payload.get("results")
        if not isinstance(results, list):
            results = []

        ecosystems: set[str] = set()
        vuln_ids: list[Any] = []
        vuln_count = 0
        alias_count = 0
        vulns_without_aliases = 0

        for entry in results:
            if not isinstance(entry, dict):
                continue
            for pkg in entry.get("packages", []) or []:
                if not isinstance(pkg, dict):
                    continue

                info = pkg.get("package")
                if isinstance(info, dict):
                    ecosystem = info.get("ecosystem")
                    if isinstance(ecosystem, str) and ecosystem:
                        ecosystems.add(ecosystem.lower())

                for vuln in pkg.get("vulnerabilities", []) or []:
                    if not isinstance(vuln, dict):
                        continue
                    vuln_count += 1
                    vuln_ids.append(vuln.get("id"))

                    # ⚠ THE ALIAS EDGES. Phase 8's union-find is built on these.
                    aliases = vuln.get("aliases")
                    if isinstance(aliases, list) and aliases:
                        alias_count += len(aliases)
                    else:
                        vulns_without_aliases += 1

        base.ecosystems_covered = sorted(ecosystems)
        # osv-scanner nests findings per package, so the same advisory against
        # two packages appears twice. Counted DISTINCT, as everywhere else.
        base.summary = summarize(
            self.capabilities,
            {"vulnerabilities": count_distinct_vulnerabilities(vuln_ids)},
        )

        # ⚠ THE ENGINE MUST PROVE IT LOADED A DATABASE, NOT MERELY THAT ONE
        # EXISTS ON DISK.
        #
        # The provisioning guard checks that a stamped database is present and
        # mounted. It cannot check that osv-scanner actually USED it — and the
        # `--offline-vulnerabilities` flag proved that gap is real: with a fully
        # populated cache mounted, it loaded nothing and reported a clean
        # project with exit 0.
        #
        # osv-scanner announces each archive it opens ("Loaded npm local db
        # from …"). If it scanned packages and opened no database, the empty
        # result is a false all-clear, so it is reported `unavailable`.
        loaded = loaded_local_databases(result.stderr)
        if scanned_packages(result.stderr) and not loaded:
            base.status = ResultStatus.UNAVAILABLE
            base.diagnostics.append(
                self.db_stale_diagnostic(
                    "osv-scanner opened no local database, so its empty result means "
                    "'not matched' rather than 'no vulnerabilities'"
                )
            )
            return base

        if loaded:
            base.diagnostics.append(
                {
                    "severity": "info",
                    "code": "OSV_DATABASES_LOADED",
                    "message": f"matched against {len(loaded)} local database(s)",
                    "hint": ", ".join(sorted(loaded)),
                }
            )

        # `base.engine_db_version` already carries the provisioner's stamp.
        # Only overwrite it if the payload states something more precise.
        reported = osv_db_version(payload)
        if reported:
            base.engine_db_version = reported

        if not base.engine_db_version:
            base.status = ResultStatus.UNAVAILABLE
            base.diagnostics.append(
                self.db_stale_diagnostic("no OSV database version could be determined")
            )
            return base

        base.status = ResultStatus.SUCCEEDED

        if vuln_count and alias_count == 0:
            # Every finding lacking an alias is a real signal, not a curiosity:
            # Phase 8 would then have nothing to union on and would report each
            # source's identifier as a separate vulnerability.
            base.diagnostics.append(
                {
                    "severity": "warn",
                    "code": "OSV_ALIASES_ABSENT",
                    "message": f"none of {vuln_count} osv findings carry alias edges",
                    "hint": (
                        "alias edges are the authoritative input to vulnerability "
                        "deduplication; without them the same CVE reported by two "
                        "engines will be counted twice"
                    ),
                }
            )
        elif vulns_without_aliases:
            base.diagnostics.append(
                {
                    "severity": "info",
                    "code": "OSV_ALIASES_PARTIAL",
                    "message": (
                        f"{vulns_without_aliases} of {vuln_count} findings carry no aliases"
                    ),
                    "hint": "those will not be merged with the same vulnerability from another engine",
                }
            )

        if not results:
            base.diagnostics.append(
                {
                    "severity": "info",
                    "code": "ENGINE_ZERO_FINDINGS",
                    "message": "osv-scanner matched no vulnerabilities",
                    "hint": "a lockfile with no known vulnerabilities is a legitimate result",
                }
            )

        return base


#: osv-scanner logs one of these per archive it opens:
#:     Loaded npm local db from /enginedb/osv-scalibr/npm/all.zip
_LOADED_DB = re.compile(r"Loaded\s+(\S+)\s+local db from\s+(\S+)", re.IGNORECASE)

#: And one of these per manifest it parsed:
#:     Scanned /src/package-lock.json file and found 2 packages
_SCANNED = re.compile(r"found\s+\d+\s+packages?", re.IGNORECASE)


def loaded_local_databases(stderr: str) -> set[str]:
    """Which local databases osv-scanner actually opened.

    Read from stderr because there is nowhere else to read it from: the JSON
    output says nothing about what was matched against. That makes this
    fragile against upstream rewording — and the failure direction is chosen
    accordingly. A miss reports `unavailable`, which understates coverage
    visibly; the alternative is reporting a project clean because we could not
    tell whether anything was checked.
    """
    return {m.group(1).lower() for m in _LOADED_DB.finditer(stderr)}


def scanned_packages(stderr: str) -> bool:
    """Whether osv-scanner parsed any manifest at all.

    Distinguishes "found no packages to check" — legitimately empty, and not a
    database problem — from "found packages and checked them against nothing".
    """
    return bool(_SCANNED.search(stderr))


def osv_db_version(payload: dict[str, Any]) -> str:
    """The database vintage osv-scanner reports, or "" if it reports none.

    ⚠ THERE IS DELIBERATELY NO FALLBACK TO THE ENGINE VERSION.

    An earlier version of this function returned
    ``f"osv-scanner {engine_version} (offline database bundled in the image)"``
    when the payload carried nothing. That was false in a way that defeated the
    check it was part of: the image is a single 57 MB binary and bundles no
    database at all. osv-scanner downloads one per ecosystem on demand, and with
    none present it matches against nothing and exits 0.

    So the fabricated version made `requires_db_version` pass for an engine that
    had no database, which is precisely the state that check exists to catch.
    Inventing provenance is worse than having none: the caller cannot tell the
    difference, and the number ends up in a compliance document.

    The real vintage now comes from the provisioner's stamp (see
    :mod:`encorebom_shared.enginedb`), which is a claim we can stand behind
    because we wrote it when we downloaded the data.
    """
    for key in ("db_version", "database_version", "osv_version"):
        value = payload.get(key)
        if isinstance(value, str) and value:
            return f"osv {value}"
    return ""
