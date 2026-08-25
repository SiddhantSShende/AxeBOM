package oidcauth

import (
	"net/http"
	"strings"

	"github.com/axebom/axebom/libs/go-shared/auth"
	"github.com/axebom/axebom/libs/go-shared/authz"
	"github.com/axebom/axebom/libs/go-shared/platform/ctxkey"
	"github.com/axebom/axebom/libs/go-shared/platform/db"
	"github.com/axebom/axebom/libs/go-shared/platform/errs"
)

// HeaderOrg lets a caller who belongs to more than one organisation say which
// one this request acts in.
//
// ⚠ IT IS A HINT, NOT A GRANT. The org named here is only honoured when the
// VERIFIED token already carries a role in it. A header that could select a
// tenant on its own would be the whole tenancy boundary, handed to the client.
const HeaderOrg = "X-AxeBOM-Org"

// HeaderServiceTenant lets one of our own components act for a named tenant.
//
// ⚠ HONOURED ONLY FOR A VERIFIED SERVICE PRINCIPAL, never for a person.
//
// A machine token's resource owner is the machine's own organisation, not the
// customer it is working for — the fetcher cloning Acme's repository is
// authenticated as `svc-fetcher`, which lives in the AxeBOM organisation. It
// has to be able to say which tenant the work belongs to.
//
// This is the same trust boundary the hand-rolled auth service already had:
// MintService(name, tenantID) let any of our components mint a token for any
// tenant. The difference is that it is now explicit, on the request, and
// testable — TestTenantHeaderIsIgnoredForHumans proves a person's token
// carrying this header changes nothing.
const HeaderServiceTenant = "X-AxeBOM-Tenant"

// WSSubprotocol is the subprotocol a browser client offers first and the
// server echoes back.
//
// RFC 6455 requires the server to select one of the protocols the client
// offered; a server that stays silent makes a conforming browser FAIL the
// connection. So the client offers this alongside its credential, and the
// handler selects this one.
const WSSubprotocol = "axebom.v1"

// WSBearerPrefix carries the access token on a WebSocket handshake.
//
// ⚠ THIS EXISTS BECAUSE THE BROWSER WebSocket API CANNOT SET A HEADER, AND IT
// IS NOT A LOOPHOLE IN THE "NEVER FROM THE QUERY STRING" RULE.
//
// `new WebSocket(url, protocols)` is the only place a browser lets a caller put
// anything of their own on the handshake, and it lands in the
// Sec-WebSocket-Protocol REQUEST HEADER. The reason a token must not travel in
// a URL is that URLs are logged, sent in Referer, and kept in history — none of
// which is true of a header. This is the same mechanism the Kubernetes API
// server uses for exactly this problem.
//
// The value is a JWT, whose alphabet is base64url plus '.', all valid header
// token characters, so no extra encoding is needed.
// #nosec G101 -- a WebSocket subprotocol PREFIX, not a credential. The token
// is appended to it at call time and never appears in this file.
const WSBearerPrefix = "axebom.bearer."

// ServiceSubjectPrefix marks a machine principal in ctxkey.UserID.
//
// Kept identical to the retired auth.ServicePrefix so auth.RequireService and
// its 404-not-403 behaviour on GET /v1/projects/{id}/source keep working
// unchanged. A UUID contains no colon, so the two id spaces cannot collide.
const ServiceSubjectPrefix = "service:"

// APIKeySubjectPrefix marks an API-key principal in ctxkey.UserID.
//
// The key's plaintext id segment, never the key itself — the same "readable
// enough to attribute, not enough to use" property KeyID exists for.
const APIKeySubjectPrefix = "apikey:"

// Authenticate verifies the bearer token and populates the request context.
//
// ⚠ THE ctxkey WRITES ARE THE WHOLE POINT OF THIS PACKAGE.
// db.WithTenantFromContext reads ctxkey.TenantID and nothing else, and that is
// what feeds app.current_tenant_id and therefore every RLS policy in the
// product. Everything above them exists to make those values trustworthy.
//
// pool is required only for API-key verification — a pre-tenant lookup with
// the same shape as login (migrations/auth/0002) — never touched by the JWT
// or service-token paths below.
func Authenticate(v *Verifier, r Resolver, pool *db.Pool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			token, err := bearerToken(req)
			if err != nil {
				errs.Write(w, req, err)
				return
			}

			// ⚠ CHECKED BEFORE JWT VERIFICATION, NOT AFTER IT FAILS. An API key
			// is recognisable by its prefix (apikey.go's whole point — secret
			// scanners and this middleware both rely on it), so there is no
			// ambiguity to resolve by trying one format and falling back.
			if strings.HasPrefix(token, auth.KeyPrefix) {
				ctx, err := authenticateAPIKey(req.Context(), pool, token)
				if err != nil {
					errs.Write(w, req, err)
					return
				}
				next.ServeHTTP(w, req.WithContext(ctx))
				return
			}

			id, err := v.Verify(req.Context(), token)
			if err != nil {
				errs.Write(w, req, err)
				return
			}

			ctx := req.Context()

			if id.Service {
				tenantID := strings.TrimSpace(req.Header.Get(HeaderServiceTenant))
				if tenantID == "" {
					errs.Write(w, req, errs.New(errs.AuthTenantContextMiss,
						"a service principal must name the tenant it is acting for"))
					return
				}
				ctx = ctxkey.WithTenantID(ctx, tenantID)
				ctx = ctxkey.WithUserID(ctx, ServiceSubjectPrefix+serviceName(id))
				// Analyst, matching the retired MintService. A service
				// principal can run a scan and read a project; it cannot manage
				// members or delete a tenant, and nothing it does needs that.
				ctx = ctxkey.WithRole(ctx, string(authz.RoleAnalyst))
				next.ServeHTTP(w, req.WithContext(ctx))
				return
			}

			orgID, role, err := id.TenantFor(strings.TrimSpace(req.Header.Get(HeaderOrg)))
			if err != nil {
				errs.Write(w, req, err)
				return
			}

			principal, err := r.Resolve(ctx, ResolveRequest{
				OrgID:         orgID,
				OrgName:       id.HomeOrgName,
				Subject:       id.Subject,
				Email:         id.Email,
				EmailVerified: id.EmailVerified,
				Name:          id.Name,
				Role:          role,
			})
			if err != nil {
				errs.Write(w, req, errs.Wrap(err, errs.InternalUnexpected,
					"the account could not be resolved"))
				return
			}

			ctx = ctxkey.WithTenantID(ctx, principal.TenantID)
			ctx = ctxkey.WithUserID(ctx, principal.UserID)
			ctx = ctxkey.WithRole(ctx, string(principal.Role))
			// The JWT id, which is per-token. There is no server-side session
			// to revoke — ZITADEL owns sessions now — so this exists for
			// correlation in logs, not for revocation.
			ctx = ctxkey.WithSessionID(ctx, id.Subject)

			next.ServeHTTP(w, req.WithContext(ctx))
		})
	}
}

// serviceName is the machine user's client id, used for the ctxkey subject.
func serviceName(id *Identity) string {
	if id.Name != "" {
		return id.Name
	}
	return id.Subject
}

// bearerToken reads the credential from the Authorization header ONLY.
//
// ⚠ NEVER FROM THE QUERY STRING. A token in a URL lands in access logs, in
// Referer headers and in browser history, and every one of those is a place a
// credential outlives the request that carried it.
func bearerToken(r *http.Request) (string, error) {
	h := r.Header.Get("Authorization")
	if h == "" {
		// A WebSocket handshake from a browser cannot carry an Authorization
		// header. Only then, and only on a real upgrade, is the subprotocol
		// consulted — so an ordinary request cannot smuggle a credential in
		// through a header that no other code path reads.
		if tok := wsBearerToken(r); tok != "" {
			return tok, nil
		}
		return "", errs.New(errs.AuthTokenInvalid, "no bearer token")
	}
	const prefix = "Bearer "
	if len(h) <= len(prefix) || !strings.EqualFold(h[:len(prefix)], prefix) {
		return "", errs.New(errs.AuthTokenInvalid, "the Authorization header is not a bearer token")
	}
	token := strings.TrimSpace(h[len(prefix):])
	if token == "" {
		return "", errs.New(errs.AuthTokenInvalid, "the bearer token is empty")
	}
	return token, nil
}

// wsBearerToken reads the access token from the offered subprotocols.
//
// Returns "" for anything that is not a WebSocket upgrade offering the
// credential subprotocol, so the caller falls through to the ordinary
// "no bearer token" answer.
func wsBearerToken(r *http.Request) string {
	if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		return ""
	}
	// The header may be repeated as well as comma-separated; both forms are
	// legal and browsers have shipped both.
	for _, header := range r.Header.Values("Sec-WebSocket-Protocol") {
		for _, offered := range strings.Split(header, ",") {
			offered = strings.TrimSpace(offered)
			if after, ok := strings.CutPrefix(offered, WSBearerPrefix); ok {
				return after
			}
		}
	}
	return ""
}
