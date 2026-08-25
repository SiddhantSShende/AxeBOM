// Package oidcauth verifies ZITADEL access tokens and turns them into the
// request context the rest of AxeBOM already expects.
//
// It replaces the hand-rolled HS256 issuer in libs/go-shared/auth. The four
// context keys it writes are unchanged, so db.WithTenantFromContext,
// auth.RequireTenant (47 call sites) and authz.Allow (44 mount sites) are
// untouched by the change of identity provider.
//
// ---------------------------------------------------------------------------
// WHY LOCAL VERIFICATION AND NOT INTROSPECTION
//
// ZITADEL's own advice is to call the introspection endpoint and not care what
// the token looks like. That is right for one API. Here it would put a
// synchronous call to the identity provider in front of every request to seven
// services, so a slow IdP becomes a slow product and an unreachable IdP becomes
// a total outage.
//
// Instead the SPA's application is configured to issue JWTs, and each service
// verifies the signature against a cached JWKS. The cost is that a revoked
// token stays valid until it expires, and the compensating control is the
// token lifetime: ZITADEL_OIDC_DEFAULTACCESSTOKENLIFETIME is 15 minutes rather
// than the 12-hour default. That number IS the revocation window, and it is
// the reason it was changed.
package oidcauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/axebom/axebom/libs/go-shared/authz"
	"github.com/axebom/axebom/libs/go-shared/platform/errs"

	"github.com/zitadel/oidc/v3/pkg/client/rp"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
)

// Claim names ZITADEL uses.
//
// ⚠ THE ORG CLAIM IS `...user:resourceowner:id`, NOT `...org:id`.
// `urn:zitadel:iam:org:id:{id}` is a SCOPE that pins a login to one
// organisation; it is not a claim and never appears in a token. Reaching for
// the obvious-looking name yields an empty tenant on every request.
const (
	ClaimOrgID    = "urn:zitadel:iam:user:resourceowner:id"
	ClaimOrgName  = "urn:zitadel:iam:user:resourceowner:name"
	ClaimRolesFmt = "urn:zitadel:iam:org:project:%s:roles"
)

// ServiceRoleKey marks a machine user. Mirrors iam.ServiceRoleKey; duplicated
// rather than imported so the request path does not depend on the provisioner.
const ServiceRoleKey = "service"

// Config configures verification.
type Config struct {
	// Issuer is the PUBLIC issuer, exactly as it appears in the `iss` claim.
	//
	// ⚠ ZITADEL DERIVES THE ISSUER FROM THE REQUEST HOST. A token minted
	// through the reverse proxy on :5173 carries `http://localhost:5173`; the
	// same call made directly to the container on :58080 carries
	// `http://localhost:58080`, and the two do not interoperate. Whatever mints
	// tokens must reach ZITADEL the way the browser does — see ServiceTokens.
	Issuer string

	// JWKSURL is where the signing keys are fetched from, and it is separate
	// from Issuer on purpose: services live inside the compose network and
	// cannot resolve the public origin, but they must still validate `iss`
	// against it. Defaults to Issuer + /oauth/v2/keys.
	JWKSURL string

	// ProjectID is the expected audience. A token minted for another project
	// is a valid ZITADEL token and must still be refused here.
	ProjectID string

	// HTTPClient fetches JWKS. Optional.
	HTTPClient *http.Client
}

// Verifier validates access tokens against ZITADEL's published keys.
type Verifier struct {
	cfg      Config
	verifier *op.AccessTokenVerifier
	rolesKey string
}

// NewVerifier builds a verifier with a remote, cached key set.
func NewVerifier(cfg Config) (*Verifier, error) {
	if cfg.Issuer == "" {
		return nil, errors.New("oidcauth: no issuer configured (ZITADEL_ISSUER)")
	}
	if cfg.ProjectID == "" {
		return nil, errors.New("oidcauth: no project id configured (ZITADEL_PROJECT_ID)")
	}
	cfg.Issuer = strings.TrimRight(cfg.Issuer, "/")
	if cfg.JWKSURL == "" {
		cfg.JWKSURL = cfg.Issuer + "/oauth/v2/keys"
	}
	httpClient := cfg.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 10 * time.Second}
	}

	// ⚠ THE KEY SET IS FETCHED FROM A PRIVATE ADDRESS BUT MUST PRESENT THE
	// PUBLIC HOST. ZITADEL picks the instance from the Host header, so a plain
	// GET to http://zitadel-api:8080/oauth/v2/keys answers 404 "Instance not
	// found" — and a verifier that cannot fetch keys refuses EVERY token with
	// "the access token could not be verified", which reads as a client fault
	// across the whole fleet. See the publicHost transport.
	httpClient, err := withPublicHost(httpClient, cfg.Issuer, cfg.JWKSURL)
	if err != nil {
		return nil, err
	}

	keys := rp.NewRemoteKeySet(httpClient, cfg.JWKSURL)
	return &Verifier{
		cfg:      cfg,
		verifier: op.NewAccessTokenVerifier(cfg.Issuer, keys),
		rolesKey: fmt.Sprintf(ClaimRolesFmt, cfg.ProjectID),
	}, nil
}

// Identity is everything a verified token asserts.
type Identity struct {
	Subject       string
	Email         string
	EmailVerified bool
	Name          string

	// HomeOrgID is the organisation that OWNS the user record. It is not
	// necessarily the tenant the request is acting in — a consultant with a
	// role in two customers has one home organisation and two roles.
	HomeOrgID   string
	HomeOrgName string

	// Roles maps organisation id to the role held there. An organisation
	// appearing under several role keys keeps the HIGHEST, because a token
	// carrying both `viewer` and `admin` for one tenant means the user is an
	// admin, and taking the first match would make the result depend on map
	// iteration order.
	Roles map[string]authz.Role

	// Service is true when the caller is one of our own components rather than
	// a person. Kept distinct from the four product roles: a service principal
	// is a different KIND of caller, not a more privileged person.
	Service bool
}

// Verify checks the signature, issuer, audience and expiry, then extracts the
// ZITADEL claims.
func (v *Verifier) Verify(ctx context.Context, raw string) (*Identity, error) {
	claims, err := op.VerifyAccessToken[*oidc.AccessTokenClaims](ctx, raw, v.verifier)
	if err != nil {
		// ⚠ EXPIRY IS THE ONE FAILURE MODE WORTH NAMING, AND NAMING IT LEAKS
		// NOTHING.
		//
		// Everything else stays a single opaque code so a caller cannot probe
		// which part of a forged token was wrong. Expiry is different on both
		// counts. It leaks nothing — the client is holding the token and can
		// read `exp` itself — and the library only reaches the expiry check
		// AFTER the signature and the issuer have already passed, so this code
		// can only ever describe a token we genuinely minted.
		//
		// It has to be distinguishable because the client's correct response
		// differs: an expired token means renew and retry, an invalid one means
		// sign in again. Collapsing the two sends a user with a fifteen-minute
		// token back through a full login every fifteen minutes.
		if errors.Is(err, oidc.ErrExpired) {
			return nil, errs.New(errs.AuthTokenExpired, "the access token has expired")
		}
		// Never echo the underlying library message: it varies with the
		// failure mode and would let a caller probe which part was wrong.
		return nil, errs.New(errs.AuthTokenInvalid, "the access token could not be verified")
	}

	// ⚠ AUDIENCE IS CHECKED HERE, NOT BY THE LIBRARY.
	//
	// op.VerifyAccessToken validates the signature, the issuer and the clock.
	// It does NOT check that this token was minted for us. Without this, a
	// token issued to any other application on the same ZITADEL instance is
	// accepted — which is a cross-application privilege escalation on a single
	// shared IdP.
	if !hasAudience(claims.Audience, v.cfg.ProjectID) {
		return nil, errs.New(errs.AuthTokenInvalid,
			"the access token was not issued for this application")
	}

	id := &Identity{
		Subject: claims.Subject,
		// ⚠ email AND name MAY BE ABSENT, and that is normal.
		//
		// They reach an ACCESS token only when the profile/email scopes were
		// requested and the application asserts user info into it. A machine
		// user has neither. Absence is handled rather than treated as an error:
		// the local projection then creates a user keyed on the subject, which
		// is correct — the subject is the identifier that matters.
		Email:         stringClaim(claims.Claims, "email"),
		EmailVerified: boolClaim(claims.Claims, "email_verified"),
		Name:          stringClaim(claims.Claims, "name"),
		HomeOrgID:     stringClaim(claims.Claims, ClaimOrgID),
		HomeOrgName:   stringClaim(claims.Claims, ClaimOrgName),
		Roles:         map[string]authz.Role{},
	}

	for roleKey, orgs := range rolesClaim(claims.Claims, v.rolesKey) {
		if roleKey == ServiceRoleKey {
			id.Service = true
			continue
		}
		role := authz.Role(strings.ToLower(roleKey))
		if !role.Valid() {
			continue
		}
		for orgID := range orgs {
			if cur, ok := id.Roles[orgID]; !ok || authz.RoleAtLeast(role, cur) {
				id.Roles[orgID] = role
			}
		}
	}

	if id.Subject == "" {
		return nil, errs.New(errs.AuthTokenInvalid, "the access token has no subject")
	}
	return id, nil
}

// TenantFor picks the organisation this request acts in.
//
// ⚠ AMBIGUITY IS AN ERROR, NOT A GUESS. A user holding roles in two tenants who
// names neither would otherwise get whichever organisation the map happened to
// yield first — different on every request, and silently the wrong tenant's
// data half the time. The client is told to choose.
func (id *Identity) TenantFor(preferred string) (orgID string, role authz.Role, err error) {
	if preferred != "" {
		if r, ok := id.Roles[preferred]; ok {
			return preferred, r, nil
		}
		return "", "", errs.New(errs.PermNoRoleInOrg,
			"you do not have a role in the requested organisation")
	}
	switch len(id.Roles) {
	case 0:
		return "", "", errs.New(errs.PermNoRoleInOrg,
			"this account has no role in any organisation of this application")
	case 1:
		for o, r := range id.Roles {
			return o, r, nil
		}
	}
	if r, ok := id.Roles[id.HomeOrgID]; ok {
		return id.HomeOrgID, r, nil
	}
	return "", "", errs.New(errs.AuthOrgAmbiguous,
		"this account belongs to more than one organisation; select one")
}

// AudienceScope is the reserved ZITADEL scope that puts a project id into the
// `aud` claim of the token it mints.
//
// ⚠ THE BROWSER MUST REQUEST THIS OR EVERY TOKEN IT GETS IS REFUSED HERE.
//
// Verify insists the project id appears in the audience, because without that
// check any token minted for any other application on the same ZITADEL instance
// would be accepted — a cross-application escalation on a shared IdP. The scope
// below is how a client asks for an audience it is entitled to; it is the
// matching half of hasAudience, and the two are kept adjacent so neither can be
// changed without the other being read.
func AudienceScope(projectID string) string {
	return "urn:zitadel:iam:org:project:id:" + projectID + ":aud"
}

// OrgScope pins a login to one organisation.
//
// It is offered for completeness — the SPA selects its organisation with the
// HeaderOrg request header instead, which needs no redirect and is checked
// against the roles the token already carries. See Identity.TenantFor.
func OrgScope(orgID string) string {
	return "urn:zitadel:iam:org:id:" + orgID
}

// ---------------------------------------------------------------- claim help

func hasAudience(aud []string, want string) bool {
	for _, a := range aud {
		if a == want {
			return true
		}
	}
	return false
}

func boolClaim(m map[string]any, key string) bool {
	b, _ := m[key].(bool)
	return b
}

func stringClaim(m map[string]any, key string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}

// rolesClaim decodes ZITADEL's roles claim.
//
// ⚠ THE SHAPE IS AN OBJECT, NOT AN ARRAY: { roleKey: { orgId: orgDomain } }.
// ZITADEL's own documentation renders it both ways on different pages; this is
// the shape a real token actually carries, confirmed against a live instance.
// The inner map is what makes it multi-tenant — the same role key held in two
// organisations appears once with two entries.
func rolesClaim(m map[string]any, key string) map[string]map[string]string {
	out := map[string]map[string]string{}
	raw, ok := m[key]
	if !ok {
		return out
	}
	// Round-tripping through JSON is deliberate: the claim arrives as nested
	// map[string]any and hand-asserting two levels of that is where a typo
	// silently yields no roles at all.
	b, err := json.Marshal(raw)
	if err != nil {
		return out
	}
	_ = json.Unmarshal(b, &out)
	return out
}
