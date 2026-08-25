package main

import (
	"net/http"

	"github.com/axebom/axebom/libs/go-shared/platform/httpx"
	"github.com/axebom/axebom/services/gateway/internal/authconfig"
	"github.com/axebom/axebom/services/gateway/internal/proxy"
	"github.com/axebom/axebom/services/gateway/internal/signup"
)

// registerRoutes mounts this service's HTTP surface.
//
// GENERATED SCAFFOLD, then hand-edited. The generator writes this file only if
// it does not already exist, so your routes survive a re-run.
//
// The gateway owns no endpoints of its own. Every pattern here forwards to the
// service that owns it; the table lives in internal/proxy.
//
// # Why each prefix is mounted four times
//
// ServeMux matches the literal request path, and a prefix reaches the gateway
// in four shapes:
//
//	/v1/projects        exact      — GET list, POST create
//	/v1/projects/       subtree    — GET /v1/projects/{id}
//	/api/v1/projects    exact      — the browser prefixes every call with /api
//	/api/v1/projects/   subtree
//
// The /api form exists because the frontend needs one unambiguous prefix for
// the Vite dev proxy to match. Vite's changeOrigin rewrites the Host header,
// not the path, so the prefix arrives intact and the proxy strips it.
//
// Registering only the subtree form would be worse than incomplete: ServeMux
// answers the exact path with a 301 to the trailing-slash form, and a browser
// turns a redirected POST into a GET, so creating a project would silently
// become a list.
//
// The "/" catch-all in main.go still answers anything unmatched, so an unknown
// route keeps the error shape from docs/02-CONTRACTS.md §9.
func registerRoutes(mux *http.ServeMux, d *deps) {
	forward := d.router.Handler(httpx.NotFound)

	for _, prefix := range d.router.Prefixes() {
		mux.HandleFunc(prefix, forward)
		mux.HandleFunc(prefix+"/", forward)
		mux.HandleFunc(proxy.APIPrefix+prefix, forward)
		mux.HandleFunc(proxy.APIPrefix+prefix+"/", forward)
	}

	// The one endpoint the gateway answers itself.
	//
	// It tells a browser where to log in, so it cannot require being logged in,
	// and it cannot be proxied to a service that only talks to authenticated
	// callers. See internal/authconfig for why it is served rather than
	// compiled into the bundle.
	//
	// ⚠ MORE SPECIFIC THAN THE /v1/auth SUBTREE ABOVE, AND THAT IS WHAT MAKES
	// IT REACHABLE. ServeMux prefers the most specific pattern, so this wins
	// over the proxy's registration and keeps winning after the auth service is
	// removed and that prefix disappears entirely.
	identity := authconfig.Handler(d.cfg.OIDC)
	mux.HandleFunc("GET /v1/auth/config", identity)
	mux.HandleFunc("GET "+proxy.APIPrefix+"/v1/auth/config", identity)

	// Self-service organisation signup — see internal/signup for why this
	// lives here rather than behind ZITADEL's own (disabled) registration.
	// Unauthenticated for the same reason /v1/auth/config is: it is how a
	// visitor OBTAINS an account, so it cannot require one.
	createOrg := signup.Handler(d.iam, d.cfg.OIDC.ProjectID)
	mux.HandleFunc("POST /v1/auth/signup", createOrg)
	mux.HandleFunc("POST "+proxy.APIPrefix+"/v1/auth/signup", createOrg)
}
