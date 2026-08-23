package main

import (
	"net/http"

	"github.com/encorebom/encorebom/libs/go-shared/platform/httpx"
	"github.com/encorebom/encorebom/services/gateway/internal/proxy"
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
}
