// Package authconfig publishes the handful of values a browser needs before it
// can start an OIDC login.
//
// ---------------------------------------------------------------------------
// WHY THIS IS AN ENDPOINT AND NOT A BUILD-TIME CONSTANT
//
// The obvious alternative is a VITE_ variable compiled into the bundle. It is
// wrong here for one practical reason: the client id and the project id are
// produced by `axebom iam bootstrap` and differ per ZITADEL instance, so
// baking them in means the frontend image is no longer environment-neutral —
// one image per deployment, rebuilt whenever identity is re-provisioned. The
// failure mode when they drift is also unusually bad: the SPA redirects to a
// login it cannot complete, and the message the user sees comes from ZITADEL
// and names neither value.
//
// Serving them instead costs one small request at startup and makes the SPA
// correct by construction in every environment.
//
// Nothing here is a secret. The client id belongs to a PKCE public client that
// holds no secret at all; the issuer is the address the browser is already
// talking to; the project id appears in the audience of every token the user
// receives. The claim names are published so the SPA never hardcodes a ZITADEL
// URN — libs/go-shared/oidcauth remains the only place those strings are
// written down.
package authconfig

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/axebom/axebom/libs/go-shared/oidcauth"
	"github.com/axebom/axebom/libs/go-shared/platform/config"
	"github.com/axebom/axebom/libs/go-shared/platform/errs"
)

// Document is what GET /v1/auth/config answers.
type Document struct {
	// Issuer is the public OIDC issuer. The SPA runs discovery against it.
	Issuer string `json:"issuer"`

	// ClientID identifies the browser application.
	ClientID string `json:"client_id"`

	// ProjectID is the audience every token must carry, and the key of the
	// roles claim. The SPA needs it to read its own roles out of the ID token.
	ProjectID string `json:"project_id"`

	// Scopes is the exact scope set to request. Served rather than assembled
	// client-side because AudienceScope is not optional — see below.
	Scopes []string `json:"scopes"`

	// RolesClaim and OrgClaim are the ZITADEL claim names, so the SPA can read
	// which organisations it holds a role in without hardcoding a URN.
	RolesClaim string `json:"roles_claim"`
	OrgClaim   string `json:"org_claim"`

	// OrgHeader is the request header that selects an organisation for a user
	// who holds roles in more than one.
	OrgHeader string `json:"org_header"`
}

// Build assembles the document from service configuration.
func Build(cfg config.OIDC) Document {
	return Document{
		Issuer:    cfg.Issuer,
		ClientID:  cfg.SPAClientID,
		ProjectID: cfg.ProjectID,
		Scopes: []string{
			"openid", "profile", "email",
			// ⚠ NOT OPTIONAL. Without it ZITADEL mints a token whose audience
			// is the client id alone, and every service refuses it because the
			// project id is missing — a login that succeeds and an application
			// that 401s on its first request.
			oidcauth.AudienceScope(cfg.ProjectID),
			// offline_access — a refresh token, and a considered trade.
			//
			// Against it: a refresh token is renewable credential material the
			// browser has to keep, and anywhere JavaScript can read it, an XSS
			// can take it. The SPA bounds that by storing it in SESSION storage
			// — one tab, discarded when the tab closes — rather than
			// localStorage, which survives a browser restart.
			//
			// For it: the alternative is renewing through a hidden iframe
			// against ZITADEL's session cookie, and ZITADEL's own guidance for
			// single-page applications is the refresh token instead. Building
			// on the iframe would put a fifteen-minute session at the mercy of
			// an instance setting (iframe embedding is off by default) and of
			// every browser that treats a framed document as third-party.
			//
			// Fifteen minutes is the access token's life either way; this only
			// decides whether renewal is silent or a full redirect.
			"offline_access",
		},
		RolesClaim: fmt.Sprintf(oidcauth.ClaimRolesFmt, cfg.ProjectID),
		OrgClaim:   oidcauth.ClaimOrgID,
		OrgHeader:  oidcauth.HeaderOrg,
	}
}

// Handler serves the document.
//
// Unauthenticated by necessity: it is what a caller reads in order to obtain a
// credential, so requiring one would be circular.
func Handler(cfg config.OIDC) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// A half-configured gateway must say so here rather than let the SPA
		// redirect to an authorize URL with an empty client_id and receive a
		// ZITADEL error page that names neither variable.
		if cfg.ProjectID == "" || cfg.SPAClientID == "" {
			errs.Write(w, r, errs.New(errs.InternalDependency,
				"identity is not provisioned: ZITADEL_PROJECT_ID and "+
					"ZITADEL_SPA_CLIENT_ID are unset, which `axebom iam bootstrap` writes"))
			return
		}

		// no-store, not a max-age: an operator who re-provisions identity must
		// not have to wait out a cache before anyone can log in again. The
		// document is a few hundred bytes, fetched once per application load.
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(Build(cfg))
	}
}
