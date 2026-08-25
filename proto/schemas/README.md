# Published envelope schemas

The three envelopes that cross a process boundary, as JSON Schema.

These are **generated from the Go types** in `libs/go-shared/events` by
`axebom schema gen`, so they cannot drift from what the code actually
publishes. `docs/02-CONTRACTS.md` §4–§6 remains the SSOT for intent; these
files are the machine-readable form.

## Why publish them at all

A worker in another language — the Python scan workers — needs to produce a
`ScanResultV1` that the Go orchestrator accepts. Without a published schema that
agreement lives in prose, and prose does not fail a build.

## The one rule that governs their evolution

> **Unknown fields are ignored, never fatal.**

Every schema sets `additionalProperties: true`. A newer publisher must be able
to add a field without breaking every older consumer — otherwise the schema can
never gain a field without a synchronised deploy of thirteen services.

This is deliberately the OPPOSITE of the HTTP handlers, which use
`DisallowUnknownFields`. A typo'd field in a user's API request is a mistake to
report; an unrecognized field in a queue message is a newer publisher.

## Regenerating

```
go run ./cmd/axebom schema gen
```
