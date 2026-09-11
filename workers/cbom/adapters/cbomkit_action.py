"""cbomkit-action — cryptography used in SOURCE CODE (Java and Python).

⚠ THE ENGINE THAT READS CODE. cbomkit-theia finds key and certificate FILES;
this finds `Cipher.getInstance("AES/CBC/PKCS5Padding")`, `MessageDigest
.getInstance("SHA-256")` and their pyca/cryptography equivalents, with file and
line. It is sonar-cryptography's detection rules (cbomkit-lib 1.3.0 wrapping
sonar-cryptography-plugin 1.7.0) run as a library over SonarSource's own AST
parsers — NO SonarQube server (research, 2026-09-11; PQCA architecture notes).

⚠ WHAT IT CANNOT SEE, and every report says so:
  - Java is scanned WITHOUT A BUILD, because invariant 7 forbids running maven
    or gradle over customer code. A call whose algorithm arrives through a
    variable or a wrapper is invisible: on jjwt every RSA/EC call passes a
    variable, and none was found.
  - Where the code names no key size, it reports an engine DEFAULT:
    `AES/CBC/PKCS5Padding` with no size came back as AES-128.
  - Go is NOT scanned. Its Go scanner executes a native helper from the scratch
    directory, which the sandbox mounts noexec, and it then fails SILENTLY (exit
    0, nothing found). C# is marked "not yet meant for active usage" upstream.
    Both are recorded as languages with no engine, never as "clean".
  - The keys it reports are keys the code GENERATES at runtime, not keys in the
    repository; the normalizer never flags them as found in source.

Invocation measured against the digest-pinned image under AxeBOM's exact sandbox
flags (2026-09-11): the image's own CMD asks for a 16 GB heap, over the sandbox's
4 GB, so the JVM is started here with 3 GB; the result is a file, so it is
`cat`-ed to stdout, the only channel out of a read-only sandbox.
"""

from __future__ import annotations

from typing import Any

from axebom_shared.adapters.base import Capabilities, GenerateResult, ResultStatus, ScanTarget
from axebom_shared.adapters.summary import count_cyclonedx, summarize
from axebom_shared.sandbox import SandboxResult, WorkspaceLayout

from ...sbom.adapters.common import SandboxedAdapter
from ..normalize.extractors import EXTRACTORS
from ._source import source_coverage

#: The languages scanned. Go and C# are deliberately absent — see the module docstring.
LANGUAGES = ("java", "python")

#: Discovery surfaces, by the file extensions that mean one is present.
SOURCE_SUFFIXES: dict[str, tuple[str, ...]] = {
    "java-source": (".java",),
    "python-source": (".py",),
}

CAPABILITIES = Capabilities(
    engine_id="cbomkit-action",
    families=("cbom",),
    source_kinds=("git", "upload"),
    produces=("crypto_assets",),
    native_format="cyclonedx-json-1.6",
    ecosystems=tuple(SOURCE_SUFFIXES),
    default_weight=4,
)

_JAR = "/cbomkit-action/CBOMkit-action.jar"


class CBOMkitActionAdapter(SandboxedAdapter):
    """Runs cbomkit-action's scanner over a source tree."""

    media_type = "application/vnd.cyclonedx+json; version=1.6"
    #: No vulnerability database: this discovers, it does not match advisories.
    requires_db_version = False

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(CAPABILITIES, **kwargs)

    def entrypoint(self) -> list[str] | None:
        """A shell, so the JVM can be sized and its output file read back."""
        return ["sh"]

    def extra_env(self, layout: WorkspaceLayout) -> dict[str, str]:
        scratch = layout.container_scratch
        return {
            # The scanner reads the repository from GITHUB_WORKSPACE.
            "GITHUB_WORKSPACE": layout.container_source,
            "CBOMKIT_LANGUAGES": ",".join(LANGUAGES),
            # Source-only: a build would run the customer's build scripts.
            "CBOMKIT_JAVA_REQUIRE_BUILD": "false",
            # One consolidated document; per-module files add nothing we read.
            "CBOMKIT_GENERATE_MODULE_CBOMS": "false",
            "CBOMKIT_OUTPUT_DIR": f"{scratch}/cbom",
            "HOME": f"{scratch}/home",
        }

    def build_argv(self, target: ScanTarget, layout: WorkspaceLayout) -> list[str]:
        scratch = layout.container_scratch
        # Every path is under the tmpfs scratch mount — the only writable place
        # in the sandbox; the JVM's own temp files go there too.
        script = (
            f"mkdir -p {scratch}/cbom {scratch}/home {scratch}/jvm-temp && "
            f"java -Xmx3g -XX:-UsePerfData -Djava.io.tmpdir={scratch}/jvm-temp -jar {_JAR} 1>&2 && "
            f"cat {scratch}/cbom/cbom.json"
        )
        return ["-c", script]

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
                    "message": "cbomkit-action returned a document that is not a JSON object",
                }
            )
            return base

        assets, diagnostics = EXTRACTORS["cbomkit-action"](payload)
        base.diagnostics.extend(diagnostics)
        base.summary = summarize(self.capabilities, count_cyclonedx(payload))

        present, uncovered = source_coverage(target.workspace, SOURCE_SUFFIXES)
        base.ecosystems_covered = present
        base.ecosystems_uncovered = uncovered
        base.diagnostics.append(source_scan_limits())

        stderr = result.stderr or ""
        if "Cannot run program" in stderr:
            # The silent-failure signature measured for its Go scanner. Go is not
            # enabled, so this should never fire — if it does, a scanner ran
            # nothing and the zero below would be a lie.
            base.status = ResultStatus.PARTIAL
            base.diagnostics.append(
                {
                    "severity": "warn",
                    "code": "ENGINE_PARTIAL_ECOSYSTEM",
                    "message": "cbomkit-action could not start one of its language scanners",
                    "hint": "its results for that language are missing, not empty",
                }
            )
            return base

        if not assets:
            if present:
                base.status = ResultStatus.PARTIAL
                base.diagnostics.append(self.zero_result_diagnostic("cryptographic API calls"))
            else:
                base.status = ResultStatus.SUCCEEDED
                base.diagnostics.append(
                    {
                        "severity": "info",
                        "code": "ENGINE_NO_SOURCE_FOR_ENGINE",
                        "message": "no Java or Python source in this tree; nothing for cbomkit-action to read",
                    }
                )
            return base

        base.status = ResultStatus.SUCCEEDED
        return base


def source_scan_limits() -> dict[str, Any]:
    """The limits every cbomkit-action result carries, in the product's voice."""
    return {
        "severity": "info",
        "code": "ENGINE_SOURCE_ONLY_SCAN",
        "message": (
            "Java and Python were scanned from source without a build; Go and C# were not scanned"
        ),
        "hint": (
            "a cryptographic call whose algorithm is passed through a variable or a "
            "wrapper is not visible without a build, and where the code names no key "
            "size the engine reports its default (e.g. AES-128)"
        ),
    }
