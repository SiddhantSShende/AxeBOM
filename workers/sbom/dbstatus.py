"""Report which vulnerability databases are provisioned, and how stale they are.

The point of this command is that **age is the only question anyone asks about a
vulnerability finding**. A report saying "no critical vulnerabilities" means
something entirely different against a database from yesterday and one from last
year, so the age has to be visible before a scan, not discovered afterwards.

Absent is reported as loudly as stale: a missing database means that engine
contributes nothing and every scan through it is `unavailable` (ADR-0009).

Usage::

    python -m workers.sbom.dbstatus
"""

from __future__ import annotations

import sys

from encorebom_shared.enginedb import database_root, resolve

from .dbsync import SPECS

#: Past this, the database is old enough that findings should not be trusted
#: without saying so. Not a hard refusal — a stale database is still a database,
#: and reporting it with its age beats refusing to scan at all.
STALE_AFTER_DAYS = 7


def main(argv: list[str] | None = None) -> int:
    root = database_root(None)
    print(f"engine databases under {root}\n")

    missing: list[str] = []
    stale: list[str] = []

    width = max(len(d) for d in SPECS)
    for database_id in sorted(SPECS):
        db = resolve(database_id)
        if db is None:
            missing.append(database_id)
            print(f"  {database_id:<{width}}  NOT PROVISIONED")
            continue

        age = db.age_days()
        if age is None:
            detail = "age unknown"
        else:
            detail = f"{age:.1f} days old"
            if age > STALE_AFTER_DAYS:
                stale.append(database_id)
                detail += "  ← STALE"

        ecosystems = f"  [{', '.join(db.ecosystems)}]" if db.ecosystems else ""
        print(f"  {database_id:<{width}}  {db.version:<10} {detail}{ecosystems}")

    print()
    if missing:
        print(
            f"{len(missing)} database(s) not provisioned: {', '.join(missing)}\n"
            "  Those engines will report `unavailable` and match NOTHING. An engine\n"
            "  with no database does not fail — it would report a clean project — so\n"
            "  the run is refused instead (ADR-0009).\n"
            "  Fix: task osint:dbsync"
        )
    if stale:
        print(
            f"{len(stale)} database(s) older than {STALE_AFTER_DAYS} days: "
            f"{', '.join(stale)}\n"
            "  Scans still run and report the vintage, but recent advisories are\n"
            "  missing. Fix: task osint:dbsync"
        )
    if not missing and not stale:
        print("all databases provisioned and current")

    # Non-zero on missing only. Staleness is reportable, not a failure — a build
    # that breaks on a week-old database would be disabled within a month.
    return 1 if missing else 0


if __name__ == "__main__":
    sys.exit(main())
