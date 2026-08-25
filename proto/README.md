# proto/

Single source of truth for anything crossing a process boundary. See `docs/02-CONTRACTS.md`.

## Status

Empty by design. Phase 6 adds the scan envelopes; Phase 3 and later add gRPC service definitions as each service acquires a caller.

The `buf.yaml` / `buf.gen.yaml` config exists from Phase 0 so the breaking-change gate is wired up **before** there is anything to break. A compatibility check added after the first consumer ships is one that has already failed once.

## Layout (as it fills in)

```
proto/
  axebom/scan/v1/       job.proto  event.proto  result.proto     ← Phase 6
  axebom/project/v1/    project.proto                            ← Phase 4
  axebom/auth/v1/       auth.proto                               ← Phase 3
  schemas/                 generated JSON Schemas for the envelopes ← Phase 6
  gen/{go,python}/         generated code — gitignored
```

## Rules

- **Versioned packages**: `axebom.scan.v1`. A breaking change means `v2`, with both consumed in parallel for at least one release.
- **Additive changes never bump the version.** Consumers must ignore unknown fields — that is what makes additive evolution safe.
- **Never reuse a field number or a field name with a different meaning.** Reserve them instead.
- Generated code is **not committed**. `task proto:gen` regenerates it; `gen/` is gitignored.
- `buf breaking` runs in CI against the main branch. Breaking a published contract fails the build rather than a consumer.

## Envelopes

`ScanJobV1`, `ScanEventV1` and `ScanResultV1` are specified in full in `docs/02-CONTRACTS.md` §4–§6. That document is the SSOT; the `.proto` files implement it.

One field that will look like an omission and is not: **`ScanJobV1` has no credential field, and never will.** Only the fetcher holds credentials (ADR-0008), so a worker receiving a job needs nothing secret. If a change appears to require one, the design has gone wrong.
