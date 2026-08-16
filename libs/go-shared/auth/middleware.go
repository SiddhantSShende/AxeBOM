package auth

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/encorebom/encorebom/libs/go-shared/authz"
	"github.com/encorebom/encorebom/libs/go-shared/platform/ctxkey"
	"github.com/encorebom/encorebom/libs/go-shared/platform/errs"
)

// HTTP middleware: authenticate, scope, authorize.
//
// The chain order is not arbitrary:
//
//	Authenticate -> (tenant is now in context) -> Authorize -> handler
//
// Authenticate puts a VERIFIED tenant into the context. Everything downstream
// — including db.WithTenantFromContext, which feeds Postgres RLS — reads it
// from there and from nowhere else. A header or query parameter would let the
// caller choose their own tenant.

// Authenticate verifies the bearer token and populates the request context.
//
// It does NOT decide what the caller may do; Authorize does that. Splitting
// them keeps "who are you" separate from "may you", so a handler cannot
// accidentally satisfy the second by only doing the first.
func Authenticate(issuer *Issuer, now func() time.Time) func(http.Handler) http.Handler {
	if now == nil {
		now = time.Now
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token, err := bearerToken(r)
			if err != nil {
				errs.Write(w, r, err)
				return
			}

			claims, err := issuer.VerifyAccess(token, now())
			if err != nil {
				errs.Write(w, r, err)
				return
			}

			ctx := r.Context()
			ctx = ctxkey.WithTenantID(ctx, claims.TenantID)
			ctx = ctxkey.WithUserID(ctx, claims.Subject)
			ctx = ctxkey.WithRole(ctx, string(claims.Role))
			ctx = ctxkey.WithSessionID(ctx, claims.SessionID)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// bearerToken extracts the credential.
//
// ONLY the Authorization header. Not a query parameter: query strings are
// written to access logs, proxy logs, browser history and Referer headers, so
// a token there leaks into places nobody audits.
func bearerToken(r *http.Request) (string, error) {
	h := r.Header.Get("Authorization")
	if h == "" {
		return "", errs.New(errs.AuthTokenInvalid, "missing Authorization header")
	}
	const prefix = "Bearer "
	if len(h) <= len(prefix) || !strings.EqualFold(h[:len(prefix)], prefix) {
		return "", errs.New(errs.AuthTokenInvalid, "Authorization header must be a Bearer token")
	}
	token := strings.TrimSpace(h[len(prefix):])
	if token == "" {
		return "", errs.New(errs.AuthTokenInvalid, "empty Bearer token")
	}
	return token, nil
}

// Authorize enforces one matrix cell.
//
// Mount per route so the permission is declared next to the handler it guards:
//
//	mux.Handle("POST /projects", auth.Authorize(authz.ResourceProject, authz.ActionCreate)(h))
//
// A route with no Authorize wrapper is a route with no authorization, which is
// why TestRouteCoverage enumerates the mux and fails on any unguarded path.
func Authorize(resource authz.Resource, action authz.Action) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			role, err := roleFromContext(r.Context())
			if err != nil {
				errs.Write(w, r, err)
				return
			}

			d := authz.Allow(role, resource, action)
			if !d.Allowed {
				errs.Write(w, r, errs.New(errs.PermRoleInsufficient, d.Reason).
					WithDetail(errs.Detail{
						"resource": string(resource),
						"action":   string(action),
						"role":     string(role),
					}))
				return
			}

			// The handler must still check the resource itself — currently only
			// report download, against visibility. Marking it in the context is
			// how a handler that forgets becomes findable rather than silent.
			if d.NeedsResourceCheck {
				next.ServeHTTP(w, r.WithContext(
					context.WithValue(r.Context(), needsResourceCheckKey{}, true)))
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

type needsResourceCheckKey struct{}

// NeedsResourceCheck reports whether the matrix deferred part of the decision
// to the handler.
func NeedsResourceCheck(ctx context.Context) bool {
	v, _ := ctx.Value(needsResourceCheckKey{}).(bool)
	return v
}

func roleFromContext(ctx context.Context) (authz.Role, error) {
	raw := ctxkey.Role(ctx)
	if raw == "" {
		// Reaching Authorize without a role means the route was mounted without
		// Authenticate. That is a wiring bug, and it must fail closed.
		return "", errs.New(errs.AuthTenantContextMiss,
			"no authenticated role in context — the route is missing the Authenticate middleware")
	}
	role, err := authz.ParseRole(raw)
	if err != nil {
		return "", errs.New(errs.AuthTokenInvalid, "unknown role in context")
	}
	return role, nil
}

// RequireTenant is a guard for handlers that touch tenant-scoped data.
//
// The database ALSO fails closed via RLS, so this is not the only defence — it
// exists to turn an obscure "unrecognized configuration parameter" from
// Postgres into a clear statement that the request bypassed auth middleware.
func RequireTenant(ctx context.Context) (string, error) {
	tenantID, ok := ctxkey.TenantID(ctx)
	if !ok || tenantID == "" {
		return "", errs.New(errs.AuthTenantContextMiss,
			"no tenant in context; the request did not pass authentication")
	}
	return tenantID, nil
}

// NotFoundForCrossTenant is the canonical response for a resource that exists
// but belongs to another tenant.
//
// 404, NEVER 403. A 403 confirms the resource exists, which lets an attacker
// enumerating UUIDs learn which are real. In practice RLS makes this mostly
// automatic — the row simply is not returned — but any handler that discovers
// a cross-tenant reference by other means must answer the same way.
func NotFoundForCrossTenant(code errs.Code, resource string) *errs.Error {
	return errs.Newf(code, "no such %s", resource)
}
