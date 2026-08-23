"""CBOM engine adapters.

Cryptographic discovery. One engine is wired today:

    cbomkit-theia   directories and container images; certificates, keys,
                    secrets and java.security policy -> CycloneDX 1.6 with
                    cryptoProperties

Two more are named in OSINT/tools.manifest.yaml and deliberately have no
adapter:

    cbomkit             a managed clone-and-scan SERVICE with its own viewer,
                        not a CLI this worker can invoke; enabled: false
    sonar-cryptography  a SonarQube PLUGIN, so it needs a SonarQube server
                        (~4 GB). Deferred past MVP with a stated reason —
                        cbomkit-theia covers CBOM discovery without it.

This file was empty, so CBOMkitTheiaAdapter was importable only by its full
module path and was registered nowhere.
"""

from .cbomkit_theia import CBOMkitTheiaAdapter

__all__ = ["CBOMkitTheiaAdapter"]
