# ADR-0008 — The fetcher materializes source exactly once and holds the only credentials

**Status:** Accepted · 2026-08-16

## Context

A scan runs several engines over the same source. The obvious implementation has each worker clone the repository itself.

## Decision

**A dedicated fetcher job runs first**, inside the sandbox. It clones or downloads, records `commit_sha`, and uploads a content-addressed archive to object storage. Only then does the orchestrator fan out engine jobs, each pointing at that archive.

**Only the fetcher holds git credentials.** `ScanJobV1` has no credential field, and never will.

## Rationale

### Correctness

Six engines cloning the same branch independently can land on **six different commits**. A push between the first and last clone produces a single report describing a codebase that never existed — components from one commit, vulnerabilities matched against another. The failure is silent, non-reproducible, and appears in a compliance artifact.

Pinning `commit_sha` once and having every engine read the same bytes removes the class of bug entirely.

### Security

This is the larger benefit. Engine containers execute third-party scanners over untrusted user code — that is remote code execution by design. If those containers also held a git token, a scanner compromise or a malicious repository exploiting a scanner would yield **access to the customer's source repositories**.

With this design, compromising a scanner yields the code it was already scanning. Nothing else. No token, no other tenant's data, no lateral movement.

> If you find yourself wanting to add a credential to `ScanJobV1`, the design has gone wrong. Route the work through the fetcher instead.

The fetcher is small, does one thing, and is the only component that needs the SSRF hardening in `05-SECURITY-MODEL.md §4` — scheme allowlist, `GIT_ALLOW_PROTOCOL=https` to kill `ext::`, connection-time private-IP blocking, hooks and symlinks disabled, archive size and inflation caps. Concentrating that surface in one auditable component is far better than spreading it across five workers.

### Efficiency

One clone instead of N. For a large monorepo that is minutes and gigabytes per scan.

## Consequences

An extra job and one round-trip of latency before engines start. Acceptable: engines then run concurrently against a local archive rather than serially against the network.

Object storage holds `workspaces/<scan_id>/source.tar.zst`, content-addressed by sha256 so an identical commit across scans deduplicates. Lifecycle rules expire these on a shorter schedule than raw scan artifacts — the source archive is a working file; the raw artifacts are compliance evidence.

`scan.scans.source_commit_sha` is **written exactly once** and is immutable thereafter. It appears in `provenance_manifest` and in every report.

Requires ADR-0004: one engine per job is what makes fan-out-after-fetch a natural shape rather than an awkward one.
