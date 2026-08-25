# ADR-0006 — Postgres Row-Level Security for tenancy

**Status:** Accepted · 2026-08-16

## Context

AxeBOM is multi-tenant and the data is unusually sensitive: a tenant's BOM is a complete dependency inventory including unpatched vulnerabilities. A cross-tenant leak hands a competitor an attack plan.

The default approach is `WHERE tenant_id = ?` in every query, usually wrapped in a repository layer.

## Decision

**Isolation is enforced in Postgres with Row-Level Security**, keyed on an `app.current_tenant_id` session variable set by the connection wrapper in `libs/go-shared/platform/db`.

```sql
ALTER TABLE project.projects ENABLE ROW LEVEL SECURITY;
ALTER TABLE project.projects FORCE  ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON project.projects
  USING      (tenant_id = current_setting('app.current_tenant_id')::uuid)
  WITH CHECK (tenant_id = current_setting('app.current_tenant_id')::uuid);
```

Four details, each a hole if missed:

1. **`FORCE`** — without it the table owner bypasses the policy, and the migration role usually *is* the owner.
2. **The application role must not be superuser and must not have `BYPASSRLS`.** A superuser connection silently disables every policy. Asserted at startup.
3. **`SET LOCAL`, not `SET`** — so the setting cannot leak across a pooled connection to another tenant's request.
4. **`tenant_id` comes from the verified JWT** — never a header, query parameter, or body field.

Cross-tenant access returns **404, not 403** — a 403 confirms the resource exists.

`TestRLSCoverage` enumerates every table in tenant schemas and fails on any without `FORCE` and a policy. A migration adding a tenant-scoped table without a policy is incomplete.

## Rationale

`WHERE tenant_id = ?` works ninety-nine times and fails once. One forgotten clause — a new endpoint, a debug helper, an admin report, a `JOIN` written late — is the breach. There is no mechanical guard: the code compiles, the tests pass, the query returns rows.

RLS makes the safe path the default and the unsafe path require deliberate effort. Even a hand-written query in a migration or a support script is filtered.

**This is why it must be Phase 1.** Retrofitting RLS onto a hundred existing queries means auditing every one for whether it already filtered correctly, and the audit is exactly the error-prone work RLS exists to eliminate.

## Consequences

A small performance cost — the policy predicate is appended to every query. Mitigated by having `tenant_id` first in composite indexes, which is the right index order anyway.

Every transaction must issue `SET LOCAL app.current_tenant_id`. The connection wrapper does this; a query outside a wrapped transaction **fails closed** (`current_setting` raises) rather than returning all rows. Fail-closed is the whole point.

Background jobs and the normalizer set the tenant explicitly from the scan record. Genuinely cross-tenant operations — platform metrics, the alias graph — live in non-tenant schemas and are reviewed individually.

Combined with the 404-not-403 rule, an attacker enumerating UUIDs learns nothing about what exists.
