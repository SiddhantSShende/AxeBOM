"""CBOM engine adapters.

    cbomkit-theia   directories and container-image tarballs: certificates,
                    keys, secrets, OpenSSL config and java.security policy.
                    Reads FILES, never source code.
    cbomkit-action  crypto API use in Java and Python source, with file and
                    line — sonar-cryptography's rules embedded via cbomkit-lib,
                    no SonarQube server. Source-only (no build).
    cdxgen-cbom     crypto API use in JavaScript/TypeScript source, via cdxgen's
                    `cbom` preset on the already-pinned cdxgen image.

Named in OSINT/tools.manifest.yaml and deliberately NOT run:

    cbomkit             a clone-and-scan SERVICE: it clones and resolves purls
                        itself, which needs network and credentials; Disabled in
                        the orchestrator's registry with that reason.
    sonar-cryptography  as a SonarQube plugin it needs a server; its rules run
                        here embedded in cbomkit-action instead.
"""

from .cbomkit_action import CBOMkitActionAdapter
from .cbomkit_theia import CBOMkitTheiaAdapter
from .cdxgen_cbom import CdxgenCBOMAdapter

__all__ = ["CBOMkitActionAdapter", "CBOMkitTheiaAdapter", "CdxgenCBOMAdapter"]
