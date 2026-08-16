# ADR-0001 — Eight Go services and five Python workers, not a modular monolith

**Status:** Accepted · 2026-08-16

## Context

EncoreBOM is greenfield, built by an AI coding agent one phase per session with **fresh context each time**. The proposed architecture is 8 Go services + 5 Python workers — 13 deployables — before a single line exists.

The alternative considered seriously was a modular monolith: one Go binary with hard package boundaries per domain, plus one Python worker with an adapter registry. Three deployables instead of thirteen.

## Decision

**Eight Go services and five Python workers, as specified.** The user was presented with the trade-off explicitly and reaffirmed the microservices split.

## The argument that was made against it

Worth recording, because it is the risk this ADR accepts rather than solves.

It is not that microservices are bad. It is that **when the developer has no persistent memory across sessions, the compiler is the only reliable memory.** A cross-cutting change — adding a field to the auth context, say — is, in a monolith, enumerated exhaustively by `go build`. Across 13 trees, it is enumerated by discipline. An agent will get 11 of 13 right in session 4, and the other two will surface in session 9 as a tenancy leak.

The benefits ledger, honestly assessed at this stage: independent deploy — no, one team. Independent scale — only the scanners, and they are already separate. Fault isolation — partially, and a 3-way split gets most of it. Tech heterogeneity — yes, but a monolith preserves it too (Go API + Python scanners). Team autonomy — there is no second team.

The costs paid on day one: 13 Dockerfiles, 13 config/health/auth/tracing/queue wirings, 13 CI jobs, and a distributed-transaction tax on operations that a monolith does in one `BEGIN` — project registration touches auth, project and classification.

## Consequences

Roughly **3–4 additional weeks** of plumbing before the first feature ships, and a standing coherence risk.

Four mitigations, all landing in **Phase 0** because each is worthless if added later:

1. **Service generator.** Adding a service is one command. Hand-writing the thirteenth service's boilerplate is where drift starts.
2. **Schema-per-service, no cross-schema JOINs in SQL.** Cross-domain joins happen in Go. This is the one discipline that keeps services genuinely separable; it costs nothing today and cannot be retrofitted once a hundred queries assume otherwise.
3. **Import-boundary lint (`depguard`) in CI.** Mechanical, fails the build, survives context loss. **Disabling it is an ADR-level decision, not a convenience.**
4. **CI on windows-latest and ubuntu-latest from day one**, so platform drift surfaces immediately.

Shared types live in `libs/go-shared` and `proto/`. Cross-service calls go through generated clients with contract tests in CI — the mechanical guard that replaces what a monolith gives for free.

## Revisiting

If session-to-session coherence becomes the dominant cost — symptoms: repeated partial cross-cutting changes, contract drift between services, plumbing consuming more time than features — collapsing the 8 Go services into one binary is mechanical **provided mitigation 2 has been honoured**. The package boundaries already exist; only the transport changes.

Collapsing the five Python workers into one image with an adapter registry is worth doing regardless, and is cheap: they share ~90% of their logic (fetch → run tool → parse → upload → emit) and differ only in adapter selection.
