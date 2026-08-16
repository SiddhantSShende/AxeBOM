# Phase 3 — Auth, tenancy, RBAC

**Estimated: 1.5 weeks** · Depends on Phases 0, 1.

## Read first

1. `CLAUDE.md` — invariant 6
2. `docs/STATE.md`
3. **`docs/05-SECURITY-MODEL.md` §2 (tenancy), §6 (RBAC), §7 (secrets)**
4. `docs/01-DATA-MODEL.md` §1 (schema `auth`)
5. `docs/02-CONTRACTS.md` §8 (REST), §9 (errors)

## Goal

Users sign in via GitHub SSO or local account, land in a tenant with a role, and every request carries a verified tenant context that reaches Postgres RLS.

## Preconditions

```
task db:reset && task test:rls    # RLS must already work
```

GitHub OAuth app registered; `GITHUB_CLIENT_ID`/`SECRET` in `.env`. Callback `http://localhost:5173/auth/github/callback`, scopes `read:user user:email` (add `repo` only if private repos are in scope for Phase 4).

## Out of scope

SAML/OIDC (Phase 16), MFA, API keys, project logic (Phase 4).

## Deliverables

```
services/auth/
  handler/    register login refresh logout me
              github_authorize github_callback
              invite_create invite_accept
  service/    user tenant membership session
  store/
  token/      JWT issue + verify, refresh rotation

services/gateway/middleware/
  auth.go     verify JWT -> context
  tenant.go   context -> app.current_tenant_id
  authz.go    THE MATRIX
  ratelimit.go

libs/go-shared/authz/
  matrix.go   (role, resource, action) -> allow
  matrix_test.go
```

## Contracts to honour

- **`tenant_id` comes from the verified JWT only** — never a header, query parameter, or body field.
- **Cross-tenant access returns 404, not 403.** A 403 confirms the resource exists.
- **Authorization is a middleware matrix**, not scattered `if role ==` checks. A new endpoint without a matrix entry must **fail the test rather than default to allow**.
- Passwords: argon2id. Refresh tokens: store the **hash** only.
- Every auth event writes `auth.audit_log`, which is append-only (no `UPDATE`/`DELETE` grant).

## Steps

1. JWT issue/verify. Claims: `sub`, `tenant_id`, `role`, `exp`, `jti`. Access 15 min, refresh 30 days with rotation and reuse detection.
2. Local register/login with argon2id.
3. GitHub OAuth: authorize → callback → exchange → fetch user + primary verified email. **Key on `github_user_id` (numeric), not `github_login`** — logins are renameable and reassignable, so keying on them lets an attacker inherit an account.
4. First signup creates a tenant with the user as `owner`. Subsequent signups join by invite.
5. Invite flow: create with role, email a token, accept binds membership. Tokens expire.
6. Gateway middleware chain: request id → recovery → logging → rate limit → auth → tenant → authz.
7. `tenant.go` calls `db.WithTenant` so RLS is active for the whole request. **A handler must not be able to get an unscoped connection** — that is the property to design for, not merely to test.
8. Implement the `05-SECURITY-MODEL.md §6` matrix exactly.
9. Frontend: login (GitHub + email), signup, invite accept, tenant context, role-aware navigation.
10. Update `docs/STATE.md`.

## Test requirements

- **`TestAuthzMatrix`** asserts every (role, resource, action) triple. Registering a route without a matrix entry fails the test.
- **Cross-tenant**: user in tenant A requesting a tenant-B resource gets **404**, and the audit log records the attempt.
- Expired access token → `AUTH_TOKEN_EXPIRED`; refresh works; a **reused** refresh token revokes the session family.
- GitHub callback with a mismatched `state` is rejected (CSRF).
- A renamed GitHub login still resolves to the same user via `github_user_id`.
- Password hashes are argon2id with sane parameters and never logged.
- Rate limit returns 429 with `Retry-After`.
- Audit log rows written for login, failed login, invite, role change; **`UPDATE`/`DELETE` on it are denied to the app role.**

## Exit criteria

```
go test ./libs/go-shared/authz -run TestAuthzMatrix -v
go test ./services/auth/... -run TestCrossTenant -v
task verify
```

Manual: sign up with GitHub → tenant created, role `owner` → invite a second user as `viewer` → confirm the viewer's navigation lacks admin routes and a direct URL to an admin route is refused.

## Before you finish

Update `docs/STATE.md`: auth flows working, roles enforced, and any matrix entry you deferred (with the reason).
