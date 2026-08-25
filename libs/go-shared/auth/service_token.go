package auth

import (
	"fmt"
	"strings"
	"time"

	"net/http"

	"github.com/axebom/axebom/libs/go-shared/authz"
	"github.com/axebom/axebom/libs/go-shared/platform/ctxkey"
	"github.com/axebom/axebom/libs/go-shared/platform/errs"
)

// ServicePrefix marks a subject as a service rather than a person.
//
// ⚠ IT IS A RESERVED PREFIX, AND USER IDS ARE UUIDs. A user id can never begin
// with "service:" — uuid has no colon — so there is no way for a person to be
// mistaken for a service or the reverse. If user ids ever stop being uuids,
// this assumption has to be re-examined rather than inherited.
const ServicePrefix = "service:"

// ServiceTokenTTL is how long a service token lives.
//
// ⚠ MUCH SHORTER THAN A USER'S ACCESS TOKEN, AND MINTED PER CALL. A service
// token is a bearer credential that acts inside a tenant with no human behind
// it, so the only thing bounding the damage from one that leaks — into a log,
// a crash dump, an error message forwarded to a third party — is how quickly it
// stops working. Two minutes covers a scan-creation round trip with room for a
// retry, and nothing else.
const ServiceTokenTTL = 2 * time.Minute

// MintService issues a short-lived token for one service acting inside one
// tenant.
//
// ⚠ THE TENANT IS AN ARGUMENT, NOT A WILDCARD. There is no "all tenants"
// service token, and there must not be: the campaign scheduler reads campaigns
// across tenants through a narrow SECURITY DEFINER function, then acts inside
// each tenant separately. A token that skipped tenancy would make the scheduler
// the one component whose compromise reads everything — which is precisely what
// RLS exists to prevent.
//
// ⚠ THE ROLE IS ANALYST, NOT ADMIN OR OWNER. It is the minimum that holds
// (scan, run), which is all any current caller needs. Widening it because a new
// call fails is the wrong fix; the right one is to ask whether that call should
// be made by a service at all.
func (i *Issuer) MintService(name, tenantID string) (string, error) {
	if name == "" {
		return "", errs.New(errs.ValidationFieldRequired,
			"a service token needs the name of the calling service")
	}
	if strings.Contains(name, ":") {
		// The subject is `service:<name>`; a colon inside the name would make
		// the parse ambiguous and could let one service impersonate another.
		return "", errs.Newf(errs.ValidationFieldInvalid,
			"service name %q contains a colon", name)
	}
	if tenantID == "" {
		return "", errs.New(errs.ValidationFieldRequired,
			"a service token must name the tenant it acts inside; there is no cross-tenant token")
	}

	claims := Claims{
		Subject:  ServicePrefix + name,
		TenantID: tenantID,
		Role:     authz.RoleAnalyst,
		// No session id: a service token cannot be revoked by logging somebody
		// out, and pretending otherwise by inventing one would suggest a
		// revocation path that does not exist. The short TTL is the control.
		IssuedAt: time.Now().UTC().Unix(),
		Expires:  time.Now().UTC().Add(ServiceTokenTTL).Unix(),
		JTI:      newJTI(),
		Issuer:   i.cfg.Issuer,
	}

	token, err := i.signClaims(claims)
	if err != nil {
		return "", fmt.Errorf("mint service token for %s: %w", name, err)
	}
	return token, nil
}

// IsService reports whether a subject is a service principal.
func IsService(subject string) bool { return strings.HasPrefix(subject, ServicePrefix) }

// ServiceName returns the service behind a subject, or "" for a person.
func ServiceName(subject string) string {
	if !IsService(subject) {
		return ""
	}
	return strings.TrimPrefix(subject, ServicePrefix)
}

// RequireService rejects any caller that is not a service principal.
//
// # Why a permission check is not enough
//
// Some data must reach another SERVICE and must never reach a PERSON, however
// privileged. The repository source lookup is the case that forced this: it
// returns `credential_ref`, a Vault path, and a Vault path is a READ PRIMITIVE
// — the holder of a token scoped to the mount can exchange it for the secret.
//
// Guarding that route with `project:read` would hand every owner and analyst in
// the tenant a path to their own repository credential through the public API.
// The public connections endpoint deliberately returns only
// `has_credential: bool` for exactly this reason, and an internal route that
// undid that would be a regression wearing an authorization check.
//
// Mount INSIDE Authenticate and alongside Authorize, never instead of either:
// this narrows who may call, it does not decide what they may do.
func RequireService(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		subject := ctxkey.UserID(r.Context())
		if subject == "" {
			// No subject means the route was mounted without Authenticate.
			// A wiring bug, and it must fail closed rather than fall through.
			errs.Write(w, r, errs.New(errs.AuthTenantContextMiss,
				"no authenticated subject in context — the route is missing the Authenticate middleware"))
			return
		}
		if !IsService(subject) {
			// 404, not 403. A 403 confirms the endpoint exists and is worth
			// probing; this route is not part of the public surface and should
			// not look like one.
			errs.Write(w, r, errs.New(errs.NotFoundResource, "no such endpoint"))
			return
		}
		next.ServeHTTP(w, r)
	})
}
