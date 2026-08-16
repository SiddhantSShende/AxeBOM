# ADR-0002 — Pinned release artifacts, never source builds

**Status:** Accepted · 2026-08-16

## Context

The original plan cloned twelve scanner repositories into `OSINT/` and built them from source (`go build ./cmd/syft`, Gradle for Dependency-Check, mage for Trivy).

## Decision

**Download pinned release binaries and container images, verified by SHA256 and cosign signature. Pin images by digest, never by tag.** Clone source only where no binary distribution exists, into gitignored `OSINT/src/`, for reference.

`OSINT/tools.manifest.yaml` is the machine-readable pin. `encorebom toolctl sync` — a Go subcommand, cross-platform, no bash — fetches and verifies.

**Java-based tools run container-only, never installed locally.**

## Rationale

**Version metadata is injected at release time.** syft and grype inject version via goreleaser `ldflags`; a source build reports `unknown`. For grype this can break vulnerability-DB schema-compatibility checks outright.

**For a compliance product, provenance is the product.** The assertion a customer pays for is "this SBOM was produced by syft v1.19.1 against grype-db vintage 2026-08-15." A local build off `main` cannot make that assertion credibly.

**Heterogeneous toolchains do not build here.** The primary dev machine has **Java 1.8**; Dependency-Check needs 11+, cbomkit needs 17+. Container-only for Java defuses this permanently rather than adding a JDK-management problem to every developer's setup.

**Supply chain.** Trivy's distribution channel was compromised **twice in March 2026**. Building from source does not help — it moves trust from a signed artifact to an unsigned branch. Verification does help, and requires a pinned artifact to verify.

**Nested git.** Twelve repositories inside the working tree creates nested-repo ambiguity and an unclonable monorepo.

## Consequences

Fast, reproducible, offline-capable setup. Every engine's exact version and digest lands in `scan.provenance_manifest`.

Runtime resolution is **container → local binary → `unavailable`**. A missing or unverifiable engine records itself as unavailable and appears in the report's Engine Coverage section; it **never fails the whole scan**. Losing one engine costs that engine's coverage, visibly.

If `cosign` is absent, verification degrades to checksum-only **with a loud warning** — in `toolctl sync` output and in the provenance manifest. Never silently.

Upgrading a tool becomes a deliberate act: change the manifest, run the contract tests, refresh affected golden fixtures, review the diffs. That friction is correct — an engine upgrade changes reported numbers, and somebody should look.
