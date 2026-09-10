// Package proxy fans an incoming request out to the service that owns it.
//
// The gateway is the only component a browser talks to. Everything behind it
// is reached through this table and nothing else.
//
// # Why a table and not discovery
//
// Upstream addresses come from configuration, never from the request. A base
// URL taken from a header or a database row turns every proxied call into an
// SSRF against our own network, and the gateway is the one process every
// request passes through. config.Services carries the same warning.
//
// # Why prefixes are matched on a boundary
//
// A naive strings.HasPrefix("/v1/projects") also matches "/v1/projectsX".
// Today no such route exists, so the bug would be invisible; the day someone
// adds "/v1/projections" it silently routes to the project service. matchPrefix
// requires the next character to be "/" or end-of-path.
//
// # Why /api is stripped here
//
// The browser calls "/api/v1/projects" — the frontend prefixes every request so
// the Vite dev proxy has something unambiguous to match on. Services mount
// "/v1/projects". Vite's changeOrigin rewrites the Host header, not the path,
// so if the gateway did not strip "/api" every proxied request would 404.
package proxy

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/axebom/axebom/libs/go-shared/platform/config"
	"github.com/axebom/axebom/libs/go-shared/platform/ctxkey"
	"github.com/axebom/axebom/libs/go-shared/platform/errs"
)

// APIPrefix is the prefix the browser adds and the gateway removes.
const APIPrefix = "/api"

// Upstream is one proxied service.
type Upstream struct {
	Name  string
	URL   *url.URL
	proxy *httputil.ReverseProxy
}

// route binds a path prefix to the service that owns it.
type route struct {
	prefix   string
	upstream *Upstream
}

// Router matches request paths to upstreams.
type Router struct {
	routes    []route
	upstreams []*Upstream
	log       *slog.Logger
}

// New builds the routing table from configuration.
//
// Every URL is parsed ONCE, here. A malformed upstream must stop the process at
// startup — discovering it on the first proxied request means the failure
// surfaces as a 500 to a user rather than as a boot error to an operator.
func New(svc config.Services, log *slog.Logger) (*Router, error) {
	if log == nil {
		log = slog.Default()
	}

	// Order matters only for correctness of overlapping prefixes; matchPrefix
	// makes the listed prefixes unambiguous, so this reads as documentation of
	// the service boundary rather than as a precedence puzzle.
	specs := []struct {
		name    string
		raw     string
		prefixe []string
	}{
		{"auth", svc.Auth, []string{"/v1/auth", "/v1/api-keys", "/v1/audit-log"}},
		{"project", svc.Project, []string{"/v1/projects", "/v1/github", "/v1/hbom", "/v1/qbom"}},
		// ⚠ `/v1/aibom` MOVED OFF project, AND THE PREFIX IS UNCHANGED ON PURPOSE.
		//
		// The browser already called `/v1/aibom/{projectId}/form`; that path now
		// reaches the service that owns the data instead of the one that happened
		// to hold the handler. A prefix claimed by two upstreams is refused by the
		// loop below, so this could not have been added without removing it above
		// — which is what makes the move visible rather than ambiguous.
		{"aibom", svc.AIBOM, []string{"/v1/aibom"}},
		{"scan-orchestrator", svc.ScanOrchestrator, []string{"/v1/scans", "/v1/vex"}},
		// "/shared/{token}" is deliberately unauthenticated — it is the public
		// side of a share link — and it does NOT live under /v1.
		{"report", svc.Report, []string{"/v1/reports", "/v1/shares", "/shared", "/v1/csaf"}},
		{"campaign", svc.Campaign, []string{"/v1/campaigns"}},
		{"comment", svc.Comment, []string{"/v1/comments"}},
		{"notification", svc.Notification, []string{"/v1/notifications"}},
	}

	r := &Router{log: log}
	seen := map[string]string{}

	for _, s := range specs {
		if strings.TrimSpace(s.raw) == "" {
			return nil, fmt.Errorf("upstream %q has no URL configured", s.name)
		}
		u, err := url.Parse(s.raw)
		if err != nil {
			return nil, fmt.Errorf("upstream %q: parse %q: %w", s.name, s.raw, err)
		}
		if u.Scheme != "http" && u.Scheme != "https" {
			return nil, fmt.Errorf("upstream %q: scheme must be http or https, got %q", s.name, u.Scheme)
		}
		if u.Host == "" {
			return nil, fmt.Errorf("upstream %q: no host in %q", s.name, s.raw)
		}

		up := &Upstream{Name: s.name, URL: u}
		up.proxy = newReverseProxy(up, log)
		r.upstreams = append(r.upstreams, up)

		for _, p := range s.prefixe {
			if owner, dup := seen[p]; dup {
				return nil, fmt.Errorf("prefix %q claimed by both %q and %q", p, owner, s.name)
			}
			seen[p] = s.name
			r.routes = append(r.routes, route{prefix: p, upstream: up})
		}
	}

	return r, nil
}

// Upstreams exposes the configured services, for health registration.
func (r *Router) Upstreams() []*Upstream { return r.upstreams }

// Prefixes lists every path prefix the router can serve.
//
// The caller mounts these on its mux. Deriving them from the same table the
// router matches on is what stops a prefix being routable but unmounted (a
// 404 from the mux that never reaches the proxy) or mounted but unroutable
// (a 404 from the proxy that the mux happily accepted).
func (r *Router) Prefixes() []string {
	out := make([]string, 0, len(r.routes))
	for _, rt := range r.routes {
		out = append(out, rt.prefix)
	}
	return out
}

// Handler returns the fan-out handler.
//
// It is mounted on "/" and therefore sees every request that the health
// endpoints did not claim. Anything it cannot route falls through to notFound,
// which keeps the error contract identical to an unknown route on a service.
func (r *Router) Handler(notFound http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		path := strings.TrimSuffix(strings.TrimPrefix(req.URL.Path, APIPrefix), "/")
		if path == "" {
			path = "/"
		}
		up := r.lookup(path)
		if up == nil {
			notFound(w, req)
			return
		}
		up.proxy.ServeHTTP(w, req)
	}
}

func (r *Router) lookup(path string) *Upstream {
	for _, rt := range r.routes {
		if matchPrefix(path, rt.prefix) {
			return rt.upstream
		}
	}
	return nil
}

// matchPrefix reports whether path is prefix or a child of it.
//
// "/v1/projects"        matches "/v1/projects"
// "/v1/projects/abc"    matches "/v1/projects"
// "/v1/projectsummary"  does NOT
func matchPrefix(path, prefix string) bool {
	if !strings.HasPrefix(path, prefix) {
		return false
	}
	rest := path[len(prefix):]
	return rest == "" || rest[0] == '/'
}

// newReverseProxy builds the per-upstream proxy.
func newReverseProxy(up *Upstream, log *slog.Logger) *httputil.ReverseProxy {
	target := up.URL

	return &httputil.ReverseProxy{
		// Rewrite, not Director. Rewrite CLEARS any inbound X-Forwarded-* before
		// SetXForwarded repopulates them from the real connection, so a client
		// cannot forge its own apparent source address. Director leaves inbound
		// values in place and appends to them.
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.Out.URL.Scheme = target.Scheme
			pr.Out.URL.Host = target.Host

			// Strip the browser-side /api prefix from BOTH forms of the path.
			//
			// ⚠ THIS USED TO CLEAR RawPath, AND THAT MADE EVERY PURL-SHAPED KEY
			// IN A PATH UNREACHABLE THROUGH THE GATEWAY.
			//
			// `URL.Path` is DECODED and `URL.RawPath` is the escaped original,
			// kept only when the two differ. Clearing RawPath was aimed at a real
			// problem — it wins over Path when they disagree, so leaving the
			// un-stripped original would send the upstream `/api/v1/...` — but it
			// solved it by discarding the escaping.
			//
			// The effect: `GET /api/v1/projects/{id}/dependencies/purl%3Apkg%3Apypi%2Flangchain%400.3.7`
			// arrived at the upstream as `.../dependencies/purl:pkg:pypi/langchain@0.3.7`,
			// where the decoded `%2F` is now a REAL separator — three path segments
			// where the route pattern has one, so ServeMux answered 404. Verified
			// live: the same request against the project service directly matched
			// the route (401, unauthenticated) and through the gateway did not.
			// Every component key is a purl, so the SBOM dependency-detail
			// endpoint could not be reached for any real component.
			//
			// `/api` contains no escapes, so trimming the same literal prefix from
			// both forms keeps them consistent — which is what RawPath's contract
			// actually requires — and preserves `%2F` all the way to the upstream.
			pr.Out.URL.Path = strings.TrimPrefix(pr.In.URL.Path, APIPrefix)
			if raw := pr.In.URL.RawPath; raw != "" {
				pr.Out.URL.RawPath = strings.TrimPrefix(raw, APIPrefix)
			} else {
				pr.Out.URL.RawPath = ""
			}

			// Send the upstream its own Host. Services do not vary on Host
			// today, but forwarding the browser's makes any future virtual
			// hosting silently wrong.
			pr.Out.Host = target.Host

			// ⚠ CARRY THE REQUEST ID ACROSS THE HOP, OR ONE FAILURE HAS TWO IDS
			// AND THE ONE THE USER CAN SEE FINDS ONLY HALF OF IT.
			//
			// httpx.RequestID mints an id per service and honours an inbound
			// X-Request-ID, but the gateway's own id lived only in its context
			// and its RESPONSE header — never on the outbound request. So the
			// upstream minted a second, unrelated id, logged everything under
			// that one, and put THAT one in the error envelope the browser
			// renders. Searching the gateway's log for the id a user quotes
			// therefore returned nothing, and the two halves of a single
			// request could not be joined by any field they shared.
			//
			// Set on pr.Out only. pr.In's header is the client's and may be
			// absent or forged; httpx.RequestID upstream sanitises and length-
			// caps whatever arrives before it reaches a log line.
			if id := ctxkey.RequestID(pr.In.Context()); id != "" {
				pr.Out.Header.Set("X-Request-ID", id)
			}

			pr.SetXForwarded()
		},

		// -1 flushes each write immediately. Required for the scan-progress
		// WebSocket and for any future SSE; with the default, a streaming
		// response is buffered until the handler returns, which for a
		// long-lived stream means never.
		FlushInterval: -1,

		Transport: &http.Transport{
			Proxy: nil, // never honour HTTP_PROXY for internal hops
			DialContext: (&net.Dialer{
				Timeout:   5 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			MaxIdleConns:          200,
			MaxIdleConnsPerHost:   32,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   5 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			// No ResponseHeaderTimeout: /v1/scans/{id}/progress is a WebSocket
			// and a report render can legitimately take minutes. The per-request
			// write timeout in the shared chain bounds the rest.
		},

		ErrorHandler: func(w http.ResponseWriter, req *http.Request, err error) {
			// A cancelled client is not a gateway fault and must not be logged
			// as one — a user navigating away would otherwise page someone.
			if errors.Is(err, context.Canceled) {
				return
			}
			log.ErrorContext(req.Context(), "upstream unreachable",
				"upstream", up.Name,
				"target", target.String(),
				"path", req.URL.Path,
				"error", err)
			errs.Write(w, req, errs.New(errs.InternalDependency,
				fmt.Sprintf("the %s service is unreachable", up.Name)))
		},
	}
}

// Probe reports whether the upstream answers its liveness endpoint.
//
// Registered as a NON-CRITICAL check. The gateway can still serve the routes
// whose upstreams are healthy, and taking it out of the load balancer because
// one service is restarting would turn a partial outage into a total one.
func (u *Upstream) Probe(ctx context.Context) error {
	target := u.URL.JoinPath("healthz").String()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return fmt.Errorf("%s: %w", u.Name, err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("%s: %w", u.Name, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: healthz returned %d", u.Name, resp.StatusCode)
	}
	return nil
}
