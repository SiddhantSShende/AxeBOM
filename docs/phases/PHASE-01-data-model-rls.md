# Phase 1 — Data model, migrations, RLS

**Estimated: 2 weeks** · Depends on Phase 0.

## Read first

1. `CLAUDE.md` — invariants 1, 2, 3, 6, 11
2. `docs/STATE.md`
3. **`docs/01-DATA-MODEL.md` — in full.** This phase implements it.
4. `docs/reference/certin-v2.0.yaml` — skim the structure; you will generate from it
5. `docs/ADR/0006-rls-tenancy.md`, `docs/ADR/0007-profile-driven-compliance.md`

## Goal

Every table, every RLS policy, the connection wrapper that makes RLS work, seed data, and codegen from the compliance profile.

Two things here are effectively impossible to retrofit and are the reason this phase precedes auth: **RLS** (ADR-0006) and **schema-per-service with no cross-schema JOINs** (ADR-0001 mitigation 2).

## Preconditions

```
task verify      # green
task dev         # postgres healthy
```

## Out of scope

No business logic, no HTTP handlers, no auth (Phase 3). Tables for later phases are created now — the schema is designed whole, even though most of it stays unused for months. Widening a live schema later is far more expensive than creating an unused table today.

## Deliverables

```
migrations/{auth,project,scan,normalize,report,campaign,comment,notify}/NNNN_*.sql

libs/go-shared/platform/db/
  pool.go        pgxpool with per-tenant SET LOCAL
  tenant.go      WithTenant(ctx, tenantID) — the ONLY way to get a connection
  rls_test.go    TestRLSCoverage
  migrate.go     goose wrapper

libs/go-shared/model/
  generated_certin.go     from certin-v2.0.yaml — DO NOT hand-edit
  certinid.go             CERT-In identifier derivation (hand-written, golden-tested)

libs/py-shared/encorebom_shared/model/generated_certin.py

cmd/encorebom/
  db.go          migrate | reset | seed
  profile.go     lint | gen

seed/dev/*.sql   TWO tenants
```

## Contracts to honour

- **`01-DATA-MODEL.md` is the SSOT.** If a column is needed that is not there, add it to that document in the same change.
- **`certin-v2.0.yaml` drives codegen.** Never hardcode a field count anywhere — render it from the profile.
- **RLS pattern exactly as specified**: `ENABLE` + **`FORCE`**, `USING` + `WITH CHECK`, `SET LOCAL` not `SET`, app role non-superuser and non-`BYPASSRLS`.

## Steps

1. Create the eight schemas and the non-superuser app role. **Assert at startup that the role is not superuser and lacks `BYPASSRLS`** — a privilege grant silently disables every policy, and this is the check that catches it.
2. Write migrations per `01-DATA-MODEL.md`, in dependency order. **Every tenant-scoped table gets its RLS policy in the same migration** — not a follow-up.
3. Write the connection wrapper. `WithTenant` issues `SET LOCAL app.current_tenant_id` at transaction start. Make an unwrapped query **fail closed** — `current_setting` raising is the desired behaviour, not a bug to paper over.
4. Write `TestRLSCoverage`: enumerate every table in tenant schemas via `pg_tables`, assert `FORCE ROW LEVEL SECURITY` and at least one policy. **This test must fail today if you add a table without a policy**, so add one temporarily and confirm it does.
5. Write `profile gen`: parse the YAML, emit Go structs and Python models. `field_status` is a typed map keyed by profile field id.
6. Write `profile lint` implementing the seven checks in `06-COMPLIANCE-PROFILES.md §8`.
7. Write `certinid.go` per `03-NORMALIZER-SPEC.md §6`. Golden-test it against the exact Table 6 example on PDF p.26.
8. Seed **two** tenants with overlapping project names — isolation bugs are invisible with one tenant.
9. Partition `normalize.findings` and `normalize.components` by `bom_document_id` hash, 16 partitions.
10. Update `docs/STATE.md`.

## Test requirements

- `TestRLSCoverage` — every tenant table.
- **Cross-tenant negative suite**: as tenant A, `SELECT` a tenant-B row by id returns zero rows. `UPDATE` affects zero rows. `INSERT` with tenant B's id violates `WITH CHECK`.
- A query outside `WithTenant` fails, and fails with a legible error.
- Connection-pool reuse does not leak `app.current_tenant_id` between transactions — this is the specific reason for `SET LOCAL`, so test it explicitly.
- `profile lint` fails on a deliberately-broken profile copy (wrong count, duplicate id, missing status).
- Generated Go and Python models agree on field names and count.
- `certinid` matches the Table 6 example byte for byte.
- Migrations are reversible in dev: `up`, `down`, `up` is clean.

## Exit criteria

```
task db:reset && task db:seed
task test:rls                # TestRLSCoverage passes
task profile:lint            # 134 ids, 17 counts, 0 assumed
task profile:gen && task verify
go test ./libs/go-shared/platform/db -run TestCrossTenant -v
```

## Before you finish

Update `docs/STATE.md`: schemas created, table count, anything in `01-DATA-MODEL.md` that changed during implementation (and update that document too — it is the SSOT, not a historical record).
