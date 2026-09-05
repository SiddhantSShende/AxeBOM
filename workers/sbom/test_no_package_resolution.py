"""No engine may run package-manager resolution over customer source.

⚠ CLAUDE.md INVARIANT 7 IS A FLAT PROHIBITION, NOT A RISK ASSESSMENT:

    Never run package-manager resolution that executes user code. No
    `npm install`, no `mvn`, no `gradle`, no `pip install`, no `setup.py`.
    Lockfile and manifest parsing only.

This was found the only way it could be — by watching a real scan. cdxgen's
`--install-deps` defaults to TRUE, so it ran

    npm install --ignore-scripts --no-audit --no-bin-links --git=git --package-lock

inside the sandbox on a clone of expressjs/express. `--ignore-scripts` blocks
the lifecycle-hook vector, so this was not a breach — and the rule still says
no, because a resolver executes resolution logic over manifests an attacker
wrote.

It also cannot work. Engines run `--network=none`, so the install reaches no
registry: it retried and backed off while the scan sat in `running` for over ten
minutes with all nine engine runs still queued behind it.

⚠ THIS TEST GUARDS THE FLAG, NOT THE OBSERVATION. A future cdxgen release that
renames `--no-install-deps`, or a well-meaning removal of "an unnecessary flag",
brings the whole thing back — silently, because the symptom is a slow scan
rather than an error.
"""

from __future__ import annotations

from pathlib import Path

from axebom_shared.adapters.base import ScanTarget
from axebom_shared.sandbox import WorkspaceLayout

from .adapters.cdxgen import CdxgenAdapter


def _layout() -> WorkspaceLayout:
    return WorkspaceLayout(source=Path("/host/src"))


def _target() -> ScanTarget:
    return ScanTarget(
        scan_id="01900000-0000-7000-8000-0000000000s1",
        job_id="01900000-0000-7000-8000-0000000000j1",
        kind="git",
        workspace=Path("/host"),
    )


def test_cdxgen_never_installs_dependencies() -> None:
    argv = CdxgenAdapter().build_argv(_target(), _layout())

    assert "--no-install-deps" in argv, (
        "cdxgen's --install-deps defaults to TRUE. Without --no-install-deps it "
        "runs `npm install` over the customer's source inside the sandbox, which "
        "CLAUDE.md invariant 7 forbids outright — and which cannot succeed under "
        "--network=none, so it stalls the whole scan instead of failing.\n"
        f"argv was: {argv}"
    )
    # And the flag must not be negated back by its own opposite appearing later:
    # cdxgen takes the LAST occurrence, so `--install-deps` after it wins.
    assert "--install-deps" not in argv, f"--install-deps re-enables it: {argv}"


def test_cdxgen_does_not_reach_the_network_for_licences() -> None:
    """The same stall class, already guarded — asserted so it stays guarded."""
    env = CdxgenAdapter().extra_env(_layout())
    assert env.get("FETCH_LICENSE") == "false", (
        "cdxgen enriches licences over the network unless this is false; inside a "
        "--network=none sandbox it stalls on every component until its own timeout"
    )
