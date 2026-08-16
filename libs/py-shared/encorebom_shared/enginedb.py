"""Provisioned vulnerability databases.

⚠ WHY THIS MODULE EXISTS: A VULNERABILITY ENGINE WITH NO DATABASE REPORTS A
CLEAN BILL OF HEALTH.

This is not hypothetical and it is not loud. Run osv-scanner with
``--offline-vulnerabilities`` and no cached database and it will parse the
lockfile, find every package, match against nothing, print ``{"results": []}``
and **exit 0**. Nothing in stdout, stderr or the exit code distinguishes that
from a genuinely clean project. Downstream it renders as "no vulnerabilities
found", which is the single most dangerous output this product can produce: an
unknown converted into a false negative the customer trusts.

grype and trivy happen to fail loudly today, but that is their choice, not a
guarantee, and it has changed between releases. So the rule here does not depend
on any engine's behaviour:

    A DB-backed engine runs ONLY against a database we provisioned and stamped.
    No stamp, no run — `unavailable`, before the container starts.

Refusing to run is what makes the gap visible in Engine Coverage instead of
invisible in the findings list.

The stamp is written by the provisioner (:mod:`workers.sbom.dbsync`), never by
the engine, so ``engine_db_version`` is something we asserted rather than
something the engine claimed about itself.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

#: Marker written into a provisioned database directory. Its presence is the
#: assertion "we put this here, on this date, from this source".
STAMP_NAME = "encorebom-db.json"

#: Where provisioned databases live, one directory per ``database_id``.
DEFAULT_ROOT = Path("/var/lib/encorebom/enginedb")

#: Environment override, so a developer machine and CI can point elsewhere
#: without a code change.
ROOT_ENV = "ENCOREBOM_ENGINE_DB_ROOT"


def database_root(root: Path | None = None) -> Path:
    """Resolve the database root."""
    if root is not None:
        return root
    from_env = os.environ.get(ROOT_ENV)
    if from_env:
        return Path(from_env)
    return DEFAULT_ROOT


@dataclass(frozen=True)
class EngineDatabase:
    """A provisioned database directory and its provenance."""

    database_id: str
    path: Path
    version: str
    provisioned_at: str
    source: str = ""
    #: Ecosystems the provisioner actually fetched. Empty means "not recorded",
    #: which is different from "none" and is reported as such.
    ecosystems: tuple[str, ...] = ()

    def describe(self) -> str:
        """The string that lands in ``engine_db_version``.

        It carries a DATE because the only question a reader ever asks about a
        vulnerability finding is how stale the data behind it was. A version
        with no date cannot answer that.
        """
        detail = f"{self.database_id} {self.version}" if self.version else self.database_id
        return f"{detail} provisioned {self.provisioned_at}"

    def age_days(self, now: datetime | None = None) -> float | None:
        """How old the database is, or None if the stamp date is unreadable."""
        try:
            stamped = datetime.fromisoformat(self.provisioned_at.replace("Z", "+00:00"))
        except ValueError:
            return None
        current = now or datetime.now(UTC)
        if stamped.tzinfo is None:
            stamped = stamped.replace(tzinfo=UTC)
        return (current - stamped).total_seconds() / 86400.0


def resolve(database_id: str, root: Path | None = None) -> EngineDatabase | None:
    """Return the provisioned database, or None if there is not one.

    ⚠ RETURNS None RATHER THAN RAISING, and callers must treat None as
    `unavailable` rather than as "proceed without a database". A missing
    database is an operational gap to report, not an error to crash on: the
    other engines in the same scan still have useful work to do.

    A directory that exists but has no stamp is deliberately treated as absent.
    An unstamped directory is one somebody created by hand or one a half-failed
    download left behind, and we cannot state its vintage — which is precisely
    the claim ``engine_db_version`` is supposed to make.
    """
    base = database_root(root) / database_id
    stamp = base / STAMP_NAME
    if not stamp.is_file():
        return None

    try:
        payload = json.loads(stamp.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(payload, dict):
        return None

    provisioned_at = payload.get("provisioned_at")
    if not isinstance(provisioned_at, str) or not provisioned_at:
        # No date means no defensible vintage, so the database does not count
        # as provisioned even though the bytes are on disk.
        return None

    ecosystems = payload.get("ecosystems")
    if not isinstance(ecosystems, list):
        ecosystems = []

    return EngineDatabase(
        database_id=database_id,
        path=base,
        version=str(payload.get("version") or ""),
        provisioned_at=provisioned_at,
        source=str(payload.get("source") or ""),
        ecosystems=tuple(str(e) for e in ecosystems),
    )


def write_stamp(
    database_id: str,
    *,
    version: str,
    source: str,
    ecosystems: list[str] | None = None,
    root: Path | None = None,
    now: datetime | None = None,
) -> EngineDatabase:
    """Record that a database directory was provisioned, and by what.

    Called by the provisioner AFTER a successful download. Writing it before
    would mark a half-downloaded directory as usable, which is the failure this
    whole module exists to prevent.
    """
    base = database_root(root) / database_id
    base.mkdir(parents=True, exist_ok=True)

    stamped = (now or datetime.now(UTC)).strftime("%Y-%m-%dT%H:%M:%SZ")
    payload = {
        "database_id": database_id,
        "version": version,
        "provisioned_at": stamped,
        "source": source,
        "ecosystems": sorted(ecosystems or []),
    }
    (base / STAMP_NAME).write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

    return EngineDatabase(
        database_id=database_id,
        path=base,
        version=version,
        provisioned_at=stamped,
        source=source,
        ecosystems=tuple(sorted(ecosystems or [])),
    )
