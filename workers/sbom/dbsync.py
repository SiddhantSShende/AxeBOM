"""Provision the vulnerability databases the DB-backed engines read.

⚠ THIS IS THE ONE PLACE THAT RUNS AN ENGINE IMAGE WITH A NETWORK, AND IT NEVER
TOUCHES USER CODE.

The scan sandbox runs ``--network=none`` because it executes third-party
binaries over untrusted repositories. That is not negotiable, and it is why the
databases cannot be fetched during a scan.

This module is the deliberate other half. It differs from a scan in the two
ways that make the network acceptable:

    * no user repository is mounted — only the database directory, writable
    * it is invoked by an operator or a scheduled job, never by a scan

Those two together mean the attacker-controlled input is absent, so the reason
the sandbox denies egress does not apply. Provisioning is NOT a weakened
sandbox; it is a different operation on different data.

Databases are written to ``$ENCOREBOM_ENGINE_DB_ROOT/<database_id>`` and stamped
only on success — see :mod:`encorebom_shared.enginedb` for why the stamp is what
makes a database count as present.

Usage::

    python -m workers.sbom.dbsync osv
    python -m workers.sbom.dbsync --all
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from encorebom_shared.enginedb import database_root, write_stamp
from encorebom_shared.logging import get_logger

from .adapters.common import ManifestResolver

log = get_logger("dbsync")

#: Ecosystems the OSV database is warmed for.
#:
#: osv-scanner downloads ONE ARCHIVE PER ECOSYSTEM, lazily, based on what it
#: finds in the tree it is scanning. So warming it means scanning a tree that
#: contains every ecosystem we support — a tree with only a package-lock.json
#: yields an npm-only database, and every later Python scan then silently
#: matches against nothing.
OSV_WARM_ECOSYSTEMS = ("npm", "pypi", "maven", "golang")


@dataclass
class DatabaseSpec:
    """How to provision one database."""

    database_id: str
    engine_id: str
    #: Command that performs the download, run inside the pinned image.
    argv: list[str]
    entrypoint: list[str] | None = None
    env: dict[str, str] = field(default_factory=dict)
    #: Container path the writable database directory is mounted at.
    target: str = "/enginedb"
    #: A tree the engine must walk before it will fetch anything.
    needs_warm_tree: bool = False
    ecosystems: tuple[str, ...] = ()
    #: Minutes to allow. Dependency-Check's first NVD sync genuinely takes this
    #: long, and killing it halfway leaves an unstamped directory.
    timeout_min: int = 60
    #: Exit codes that mean the download worked. osv-scanner exits 1 when it
    #: finds vulnerabilities, and the warm tree is deliberately vulnerable, so
    #: 1 is the EXPECTED outcome there rather than an error.
    ok_exit_codes: tuple[int, ...] = (0,)
    #: Download inside the container and copy the result out, instead of writing
    #: straight to a bind mount.
    #:
    #: ⚠ grype REQUIRES THIS ON WINDOWS AND macOS. Its database is SQLite, and
    #: activating it runs a migration. Docker Desktop's bind mounts are a
    #: network filesystem, on which SQLite's locking fails:
    #:     unable to migrate: disk I/O error (778)
    #: The download itself succeeds — 1m26s of it — and then the activation
    #: dies. Writing to the container's own overlay filesystem and copying the
    #: finished database out avoids the filesystem entirely.
    stage_in_container: str = ""


SPECS: dict[str, DatabaseSpec] = {
    "osv": DatabaseSpec(
        database_id="osv",
        engine_id="osv-scanner",
        # osv-scanner has no --db-path flag; it uses the OS cache directory,
        # which XDG_CACHE_HOME redirects. The archives land in
        # $XDG_CACHE_HOME/osv-scalibr/<ecosystem>/all.zip.
        #
        # --download-offline-databases is REFUSED unless an offline flag is also
        # present ("databases can only be downloaded when running in offline
        # mode"), which is why both appear here.
        argv=[
            "scan",
            "source",
            "--format",
            "json",
            "--offline-vulnerabilities",
            "--download-offline-databases",
            "--no-resolve",
            "-r",
            "/warm",
        ],
        env={"XDG_CACHE_HOME": "/enginedb"},
        needs_warm_tree=True,
        ecosystems=OSV_WARM_ECOSYSTEMS,
        timeout_min=30,
        # The warm tree contains express@4.18.2 precisely so the download is
        # exercised end to end; finding its vulnerabilities is exit 1.
        ok_exit_codes=(0, 1),
    ),
    "grype": DatabaseSpec(
        database_id="grype",
        engine_id="grype",
        argv=["db", "update", "-v"],
        env={"GRYPE_DB_CACHE_DIR": "/grypedb"},
        stage_in_container="/grypedb",
        timeout_min=30,
    ),
    "trivy": DatabaseSpec(
        database_id="trivy",
        engine_id="trivy-fs",
        argv=["image", "--download-db-only", "--cache-dir", "/enginedb"],
        timeout_min=30,
    ),
}


def warm_tree(root: Path) -> None:
    """Write a tree containing one manifest per ecosystem.

    Exists solely to make osv-scanner fetch every archive rather than only the
    one ecosystem a real fixture happens to contain. The contents are irrelevant
    beyond being parseable — nothing is reported from this scan, only the
    download it triggers.
    """
    (root / "npm").mkdir(parents=True, exist_ok=True)
    (root / "npm" / "package-lock.json").write_text(
        '{"name":"warm","version":"1.0.0","lockfileVersion":3,"packages":'
        '{"":{"name":"warm","version":"1.0.0"},'
        '"node_modules/express":{"version":"4.18.2"}}}',
        encoding="utf-8",
    )

    (root / "pypi").mkdir(parents=True, exist_ok=True)
    (root / "pypi" / "requirements.txt").write_text("flask==2.3.2\n", encoding="utf-8")

    (root / "maven").mkdir(parents=True, exist_ok=True)
    (root / "maven" / "pom.xml").write_text(
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<project xmlns="http://maven.apache.org/POM/4.0.0">\n'
        "  <modelVersion>4.0.0</modelVersion>\n"
        "  <groupId>com.example</groupId><artifactId>warm</artifactId><version>1.0.0</version>\n"
        "  <dependencies><dependency><groupId>org.apache.commons</groupId>"
        "<artifactId>commons-lang3</artifactId><version>3.12.0</version></dependency>"
        "</dependencies>\n</project>\n",
        encoding="utf-8",
    )

    (root / "golang").mkdir(parents=True, exist_ok=True)
    (root / "golang" / "go.mod").write_text(
        "module example.com/warm\n\ngo 1.21\n\nrequire github.com/google/uuid v1.3.1\n",
        encoding="utf-8",
    )


def provision(database_id: str, *, root: Path | None = None, force: bool = False) -> bool:
    """Download one database and stamp it. Returns True on success."""
    spec = SPECS.get(database_id)
    if spec is None:
        log.error("unknown database", extra={"database_id": database_id})
        return False

    resolver = ManifestResolver()
    image = resolver.image_for(spec.engine_id)
    if image is None:
        log.error(
            "no pinned image; cannot provision",
            extra={"database_id": database_id, "engine": spec.engine_id},
        )
        return False

    destination = database_root(root) / database_id
    if destination.exists() and force:
        # ⚠ The stamp goes first. If the wipe or the download dies partway, the
        # directory must not still look provisioned — an unstamped directory is
        # treated as absent, which is the safe direction.
        stamp = destination / "encorebom-db.json"
        if stamp.exists():
            stamp.unlink()
        shutil.rmtree(destination, ignore_errors=True)
    destination.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="encorebom-warm-") as tmp:
        mounts: list[str] = []
        if not spec.stage_in_container:
            mounts += ["-v", f"{destination.resolve()}:{spec.target}"]
        if spec.needs_warm_tree:
            tree = Path(tmp)
            warm_tree(tree)
            mounts += ["-v", f"{tree.resolve()}:/warm:ro"]

        log.info(
            "provisioning database",
            extra={
                "database_id": database_id,
                "image": image.reference,
                "staged": bool(spec.stage_in_container),
            },
        )

        if spec.stage_in_container:
            ok, proc = _run_staged(spec, image.reference, destination, mounts)
        else:
            argv = ["docker", "run", "--rm"]
            for key, value in spec.env.items():
                argv += ["-e", f"{key}={value}"]
            argv += mounts
            if spec.entrypoint:
                argv += ["--entrypoint", spec.entrypoint[0]]
            argv.append(image.reference)
            argv += spec.argv
            ok, proc = _run(argv, spec.timeout_min)

        if not ok or proc is None:
            log.error(
                "provisioning did not complete; the directory is left UNSTAMPED "
                "and so counts as absent",
                extra={"database_id": database_id},
            )
            return False

    if proc.returncode not in spec.ok_exit_codes:
        log.error(
            "provisioning failed; the directory is left UNSTAMPED and so counts as absent",
            extra={
                "database_id": database_id,
                "exit_code": proc.returncode,
                "stderr": proc.stderr.strip()[-600:],
            },
        )
        return False

    payload = _downloaded_bytes(destination)
    if payload == 0:
        # Exit 0 with nothing downloaded is the failure this module exists to
        # catch: it is what produces an engine that runs happily and matches
        # against nothing.
        log.error(
            "provisioning reported success but wrote no database; NOT stamping",
            extra={"database_id": database_id},
        )
        return False

    # ⚠ A DATABASE THE ENGINE CANNOT READ IS NOT PROVISIONED.
    #
    # The download runs as root; the SCAN runs as uid 65534, because the sandbox
    # drops privileges. osv-scanner's archives landed root-owned 0750, so the
    # scan user got EACCES on the directory — and osv-scanner does not treat an
    # unreadable database as an error. It reported a clean project.
    #
    # So permissions are normalised and then VERIFIED as the unprivileged user,
    # before the stamp is written. Anything less means "provisioned" would
    # describe bytes on disk rather than a database that works.
    _make_world_readable(destination, image.reference)
    if not _readable_as_scan_user(destination, image.reference):
        log.error(
            "the database is not readable by the sandbox user; NOT stamping",
            extra={"database_id": database_id, "uid": SCAN_UID},
        )
        return False

    stamped = write_stamp(
        database_id,
        version=image.version,
        source=image.reference,
        ecosystems=list(spec.ecosystems),
        root=root,
    )
    log.info(
        "database provisioned",
        extra={
            "database_id": database_id,
            "megabytes": round(payload / (1024 * 1024), 1),
            "vintage": stamped.describe(),
        },
    )
    return True


def _run(argv: list[str], timeout_min: int) -> tuple[bool, subprocess.CompletedProcess[str] | None]:
    """Run a docker command, converting its failure modes into a flag."""
    try:
        return True, subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=timeout_min * 60,
            check=False,
        )
    except subprocess.TimeoutExpired:
        log.error("provisioning timed out", extra={"minutes": timeout_min})
        return False, None
    except OSError as exc:
        log.error("could not run docker", extra={"cause": str(exc)})
        return False, None


def _run_staged(
    spec: DatabaseSpec,
    image: str,
    destination: Path,
    extra_mounts: list[str],
) -> tuple[bool, subprocess.CompletedProcess[str] | None]:
    """Download inside the container, then copy the result out.

    ``docker cp`` rather than a bind mount, because the bind mount is the
    problem: see ``DatabaseSpec.stage_in_container``. The container is created
    and started rather than ``run --rm`` so its filesystem still exists to copy
    from after the process exits.
    """
    name = f"encorebom-dbsync-{spec.database_id}"
    # Clear a container left behind by an interrupted run. `docker` is resolved
    # from PATH deliberately: the runtime is whatever the operator installed,
    # and hardcoding a path would break every platform but the one it was
    # written on. Same reasoning as S603 in pyproject.toml.
    subprocess.run(
        ["docker", "rm", "-f", name],  # noqa: S607
        capture_output=True,
        text=True,
        check=False,
    )

    create = ["docker", "create", "--name", name]
    for key, value in spec.env.items():
        create += ["-e", f"{key}={value}"]
    create += extra_mounts
    if spec.entrypoint:
        create += ["--entrypoint", spec.entrypoint[0]]
    create.append(image)
    create += spec.argv

    ok, proc = _run(create, 5)
    if not ok or proc is None or proc.returncode != 0:
        detail = proc.stderr.strip()[-400:] if proc else ""
        log.error("could not create the staging container", extra={"stderr": detail})
        return False, None

    try:
        ok, proc = _run(["docker", "start", "-a", name], spec.timeout_min)
        if not ok or proc is None:
            return False, None
        if proc.returncode not in spec.ok_exit_codes:
            return True, proc  # caller reports the exit code and stderr

        # `/.` copies the CONTENTS of the directory rather than the directory
        # itself, so the database lands at <destination>/… not
        # <destination>/<dirname>/… — which is where every engine looks for it.
        copy_ok, copy_proc = _run(
            ["docker", "cp", f"{name}:{spec.stage_in_container}/.", str(destination.resolve())],
            10,
        )
        if not copy_ok or copy_proc is None or copy_proc.returncode != 0:
            detail = copy_proc.stderr.strip()[-400:] if copy_proc else ""
            log.error(
                "the database downloaded but could not be copied out",
                extra={"database_id": spec.database_id, "stderr": detail},
            )
            return False, None
        return True, proc
    finally:
        # Unconditional: a staging container left running holds a lock on the
        # image and a multi-gigabyte writable layer.
        subprocess.run(
            ["docker", "rm", "-f", name],  # noqa: S607
            capture_output=True,
            text=True,
            check=False,
        )


#: The unprivileged uid the sandbox runs engines as. Kept in step with
#: ``sandbox.Policy.UserIDs()`` on the Go side — if they diverge, a database
#: verified here would still be unreadable at scan time.
SCAN_UID = 65534

#: Engines whose image carries a shell, most preferred first.
#:
#: ⚠ Some engine images are distroless — anchore/grype has no `sh` at all, so
#: neither the chmod nor the readability check can run inside it. Rather than
#: pull an arbitrary utility image (an unpinned image in a supply chain we
#: otherwise verify by digest), a shell is borrowed from an image ALREADY in
#: OSINT/tools.manifest.yaml. Both candidates are Alpine-based.
_SHELL_ENGINE_IDS = ("osv-scanner", "trivy-fs")


def _shell_image(preferred: str) -> str:
    """An image with a shell, for the permission work.

    Prefers the engine's own image so the common case involves nothing extra,
    and falls back to another pinned image when that one is distroless.
    """
    resolver = ManifestResolver()
    for engine_id in _SHELL_ENGINE_IDS:
        image = resolver.image_for(engine_id)
        if image and image.reference == preferred:
            return preferred
    for engine_id in _SHELL_ENGINE_IDS:
        image = resolver.image_for(engine_id)
        if image:
            return image.reference
    return preferred


def _make_world_readable(destination: Path, image: str) -> None:
    """Give every file the read bit and every directory the traverse bit.

    Run inside a container because the host is Windows, where ``os.chmod``
    cannot express POSIX permission bits — the bits that matter here only exist
    on the Linux side of the mount.

    ``a+rX`` (capital X) sets execute only on directories and on files that
    already had it, which is what makes a directory traversable without marking
    a 200 MB archive executable.
    """
    _run(
        [
            "docker",
            "run",
            "--rm",
            "-v",
            f"{destination.resolve()}:/db",
            "--entrypoint",
            "sh",
            _shell_image(image),
            "-c",
            "chmod -R a+rX /db",
        ],
        5,
    )


def _readable_as_scan_user(destination: Path, image: str) -> bool:
    """Prove the scan user can actually read the database.

    ⚠ THIS IS THE CHECK THAT MATTERS, not the chmod above.

    The chmod can silently fail — a shell-less image, a read-only layer, a
    filesystem that does not carry POSIX bits. Verifying as the real uid is the
    only statement worth making, and it is made before the stamp exists.
    """
    ok, proc = _run(
        [
            "docker",
            "run",
            "--rm",
            "--user",
            f"{SCAN_UID}:{SCAN_UID}",
            "-v",
            f"{destination.resolve()}:/db:ro",
            "--entrypoint",
            "sh",
            _shell_image(image),
            "-c",
            # Find one regular file that is NOT the stamp and read a byte of it.
            "f=$(find /db -type f ! -name encorebom-db.json | head -1); "
            '[ -n "$f" ] && head -c 1 "$f" >/dev/null',
        ],
        5,
    )
    if not ok or proc is None:
        return False
    if proc.returncode != 0:
        log.error(
            "the sandbox user cannot read the downloaded database",
            extra={"stderr": proc.stderr.strip()[-300:]},
        )
        return False
    return True


def _downloaded_bytes(path: Path) -> int:
    """Total size of everything except the stamp."""
    total = 0
    for item in path.rglob("*"):
        if item.is_file() and item.name != "encorebom-db.json":
            total += item.stat().st_size
    return total


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m workers.sbom.dbsync",
        description="Provision the vulnerability databases the SBOM engines read.",
    )
    parser.add_argument("database", nargs="*", help=f"one of: {', '.join(sorted(SPECS))}")
    parser.add_argument("--all", action="store_true", help="provision every database")
    parser.add_argument("--force", action="store_true", help="re-download even if present")
    parser.add_argument("--root", type=Path, default=None, help="database root override")
    args = parser.parse_args(argv)

    wanted = sorted(SPECS) if args.all else args.database
    if not wanted:
        parser.error("name a database or pass --all")

    failures = [d for d in wanted if not provision(d, root=args.root, force=args.force)]
    if failures:
        log.error("some databases were not provisioned", extra={"failed": failures})
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
