package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/axebom/axebom/libs/go-shared/platform/config"
	"github.com/axebom/axebom/libs/go-shared/platform/httpx"
)

// testServices points every upstream at one URL unless overridden.
func testServices(base string) config.Services {
	return config.Services{
		Auth:             base,
		Project:          base,
		ScanOrchestrator: base,
		Report:           base,
		Campaign:         base,
		Comment:          base,
		Notification:     base,
		AIBOM:            base,
	}
}

func TestMatchPrefixRequiresASegmentBoundary(t *testing.T) {
	// The bug this guards against is silent: "/v1/projectsummary" routed to the
	// project service returns that service's 404, which is indistinguishable
	// from the endpoint simply not existing yet.
	tests := []struct {
		path   string
		prefix string
		want   bool
	}{
		{"/v1/projects", "/v1/projects", true},
		{"/v1/projects/", "/v1/projects", true},
		{"/v1/projects/abc", "/v1/projects", true},
		{"/v1/projects/abc/uploads", "/v1/projects", true},
		{"/v1/projectsummary", "/v1/projects", false},
		{"/v1/projectsX", "/v1/projects", false},
		{"/v1/project", "/v1/projects", false},
		{"/v2/projects", "/v1/projects", false},
		{"", "/v1/projects", false},
	}

	for _, tt := range tests {
		t.Run(tt.path+"|"+tt.prefix, func(t *testing.T) {
			if got := matchPrefix(tt.path, tt.prefix); got != tt.want {
				t.Errorf("matchPrefix(%q, %q) = %v, want %v", tt.path, tt.prefix, got, tt.want)
			}
		})
	}
}

func TestRoutesReachTheOwningService(t *testing.T) {
	// Each upstream reports its own name, so the assertion is "which service
	// received it", not merely "something answered".
	var servers = map[string]*httptest.Server{}
	for _, name := range []string{"auth", "project", "scan", "report", "campaign", "comment", "notify", "aibom"} {
		servers[name] = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Echo the path the upstream actually saw, to prove /api was stripped.
			w.Header().Set("X-Seen-Path", r.URL.Path)
			_, _ = io.WriteString(w, name)
		}))
		t.Cleanup(servers[name].Close)
	}

	svc := config.Services{
		Auth:             servers["auth"].URL,
		Project:          servers["project"].URL,
		ScanOrchestrator: servers["scan"].URL,
		Report:           servers["report"].URL,
		Campaign:         servers["campaign"].URL,
		Comment:          servers["comment"].URL,
		Notification:     servers["notify"].URL,
		AIBOM:            servers["aibom"].URL,
	}

	r, err := New(svc, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	mux := http.NewServeMux()
	forward := r.Handler(httpx.NotFound)
	for _, prefix := range r.Prefixes() {
		mux.HandleFunc(prefix, forward)
		mux.HandleFunc(prefix+"/", forward)
		mux.HandleFunc(APIPrefix+prefix, forward)
		mux.HandleFunc(APIPrefix+prefix+"/", forward)
	}
	mux.HandleFunc("/", httpx.NotFound)

	gw := httptest.NewServer(mux)
	t.Cleanup(gw.Close)

	tests := []struct {
		name     string
		path     string
		wantSvc  string
		wantPath string
	}{
		{"auth login", "/v1/auth/login", "auth", "/v1/auth/login"},
		{"project list", "/v1/projects", "project", "/v1/projects"},
		{"project by id", "/v1/projects/abc", "project", "/v1/projects/abc"},
		{"github repos", "/v1/github/repos", "project", "/v1/github/repos"},
		{"hbom", "/v1/hbom/preview", "project", "/v1/hbom/preview"},
		{"qbom", "/v1/qbom/proj-1/form", "project", "/v1/qbom/proj-1/form"},
		// ⚠ `/v1/aibom` REACHES ITS OWN SERVICE NOW, NOT project. The browser
		// path is unchanged; the upstream behind it is not. A prefix claimed by
		// two upstreams is refused at construction, so this row and the absence
		// of `/v1/aibom` from project's list are one fact stated twice.
		{"aibom form", "/v1/aibom/proj-1/form", "aibom", "/v1/aibom/proj-1/form"},
		{"scans", "/v1/scans/abc/engine-runs", "scan", "/v1/scans/abc/engine-runs"},
		{"reports", "/v1/reports", "report", "/v1/reports"},
		{"shares", "/v1/shares/tok", "report", "/v1/shares/tok"},
		{"public share", "/shared/tok", "report", "/shared/tok"},
		{"campaigns", "/v1/campaigns", "campaign", "/v1/campaigns"},
		{"notifications", "/v1/notifications/events", "notify", "/v1/notifications/events"},

		// The /api form is what the browser actually sends. The upstream must
		// see the path WITHOUT it.
		{"api auth", "/api/v1/auth/login", "auth", "/v1/auth/login"},
		{"api project list", "/api/v1/projects", "project", "/v1/projects"},
		{"api project by id", "/api/v1/projects/abc", "project", "/v1/projects/abc"},
		{"api scans", "/api/v1/scans/abc", "scan", "/v1/scans/abc"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := http.Get(gw.URL + tt.path)
			if err != nil {
				t.Fatalf("GET %s: %v", tt.path, err)
			}
			defer func() { _ = resp.Body.Close() }()

			body, _ := io.ReadAll(resp.Body)
			if got := strings.TrimSpace(string(body)); got != tt.wantSvc {
				t.Errorf("GET %s reached %q, want %q", tt.path, got, tt.wantSvc)
			}
			if got := resp.Header.Get("X-Seen-Path"); got != tt.wantPath {
				t.Errorf("GET %s: upstream saw %q, want %q", tt.path, got, tt.wantPath)
			}
		})
	}
}

func TestExactPathIsNotRedirected(t *testing.T) {
	// ServeMux answers "/v1/projects" with a 301 to "/v1/projects/" if only the
	// subtree pattern is registered. A browser downgrades a redirected POST to
	// a GET, so "create project" would silently become "list projects" — a
	// data-losing bug that returns 200.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, r.Method)
	}))
	t.Cleanup(upstream.Close)

	r, err := New(testServices(upstream.URL), nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	mux := http.NewServeMux()
	forward := r.Handler(httpx.NotFound)
	for _, prefix := range r.Prefixes() {
		mux.HandleFunc(prefix, forward)
		mux.HandleFunc(prefix+"/", forward)
		mux.HandleFunc(APIPrefix+prefix, forward)
		mux.HandleFunc(APIPrefix+prefix+"/", forward)
	}
	gw := httptest.NewServer(mux)
	t.Cleanup(gw.Close)

	// A client that refuses to follow redirects, so a 301 is visible.
	client := &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	for _, path := range []string{"/v1/projects", "/api/v1/projects"} {
		t.Run(path, func(t *testing.T) {
			resp, err := client.Post(gw.URL+path, "application/json", strings.NewReader("{}"))
			if err != nil {
				t.Fatalf("POST %s: %v", path, err)
			}
			defer func() { _ = resp.Body.Close() }()

			if resp.StatusCode == http.StatusMovedPermanently {
				t.Fatalf("POST %s was redirected — the method would be downgraded to GET", path)
			}
			body, _ := io.ReadAll(resp.Body)
			if got := strings.TrimSpace(string(body)); got != http.MethodPost {
				t.Errorf("upstream saw method %q, want POST", got)
			}
		})
	}
}

func TestUnknownRouteFallsThroughToNotFound(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(upstream.Close)

	r, err := New(testServices(upstream.URL), nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/nonexistent", nil)
	r.Handler(httpx.NotFound)(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "json") {
		t.Errorf("content-type = %q, want JSON — the error contract requires it", ct)
	}
}

func TestUnreachableUpstreamReturnsTheTaxonomyError(t *testing.T) {
	// A dead upstream must produce a coded error naming the service, not Go's
	// default plain-text "502 Bad Gateway", which breaks the error contract and
	// tells an operator nothing about which service is down.
	dead := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	deadURL := dead.URL
	dead.Close() // nothing is listening now

	r, err := New(testServices(deadURL), nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/projects", nil)
	r.Handler(httpx.NotFound)(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "INTERNAL_DEPENDENCY_UNAVAILABLE") {
		t.Errorf("body %q does not carry the taxonomy code", body)
	}
	if !strings.Contains(body, "project") {
		t.Errorf("body %q does not name the failing upstream", body)
	}
}

func TestAuthorizationHeaderReachesTheUpstream(t *testing.T) {
	// The gateway verifies tokens but does not consume them — the owning
	// service re-verifies and derives the tenant. Dropping the header here
	// would make every proxied request anonymous.
	var got string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(upstream.Close)

	r, err := New(testServices(upstream.URL), nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	gw := httptest.NewServer(r.Handler(httpx.NotFound))
	t.Cleanup(gw.Close)

	req, _ := http.NewRequest(http.MethodGet, gw.URL+"/v1/projects", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if got != "Bearer test-token" {
		t.Errorf("upstream saw Authorization %q, want the bearer token", got)
	}
}

func TestForgedForwardedHeaderIsReplaced(t *testing.T) {
	// SetXForwarded overwrites rather than appends. If a client could prepend
	// its own X-Forwarded-For, it would choose its own rate-limit bucket — that
	// is, opt out of rate limiting.
	var got string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("X-Forwarded-For")
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(upstream.Close)

	r, err := New(testServices(upstream.URL), nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	gw := httptest.NewServer(r.Handler(httpx.NotFound))
	t.Cleanup(gw.Close)

	req, _ := http.NewRequest(http.MethodGet, gw.URL+"/v1/projects", nil)
	req.Header.Set("X-Forwarded-For", "1.2.3.4")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if strings.Contains(got, "1.2.3.4") {
		t.Errorf("forged X-Forwarded-For survived as %q — a client can pick its own limiter bucket", got)
	}
}

func TestMisconfiguredUpstreamFailsAtConstruction(t *testing.T) {
	tests := []struct {
		name string
		svc  config.Services
	}{
		{"empty url", func() config.Services { s := testServices("http://x:1"); s.Auth = ""; return s }()},
		{"no scheme", func() config.Services { s := testServices("http://x:1"); s.Report = "localhost:8094"; return s }()},
		{"bad scheme", func() config.Services { s := testServices("http://x:1"); s.Project = "ftp://x:1"; return s }()},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := New(tt.svc, nil); err == nil {
				t.Fatal("New succeeded on a misconfigured upstream; it must fail at boot")
			}
		})
	}
}

func TestEveryUpstreamIsProbeable(t *testing.T) {
	// Guards the health registration: a service added to the routing table but
	// missing from Upstreams() would never be probed, and /readyz would report
	// healthy while a route was dead.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(upstream.Close)

	r, err := New(testServices(upstream.URL), nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if len(r.Upstreams()) != 8 {
		t.Errorf("got %d upstreams, want 8 — every proxied service must be probeable", len(r.Upstreams()))
	}
	for _, up := range r.Upstreams() {
		if err := up.Probe(t.Context()); err != nil {
			t.Errorf("probe %s: %v", up.Name, err)
		}
	}
}

// TestAPercentEncodedSlashSurvivesTheProxy.
//
// ⚠ EVERY COMPONENT KEY IS A PURL, AND EVERY PURL CONTAINS A SLASH.
//
// `purl:pkg:pypi/langchain@0.3.7` reaches a route pattern like
// `/v1/projects/{id}/dependencies/{key}` only if the `%2F` stays escaped: a
// decoded slash is a real path separator, so the upstream's ServeMux sees three
// segments where the pattern has one and answers 404.
//
// The Rewrite hook used to clear `URL.RawPath` — aimed at a real problem, since
// RawPath wins over Path when the two disagree — and in doing so threw away the
// escaping. Verified live before the fix: the same request matched the route
// against the project service directly (401) and 404'd through the gateway.
// Every purl-keyed detail endpoint was unreachable.
func TestAPercentEncodedSlashSurvivesTheProxy(t *testing.T) {
	var seen struct {
		escaped string
		decoded string
	}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen.escaped = r.URL.EscapedPath()
		seen.decoded = r.URL.Path
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(upstream.Close)

	r, err := New(testServices(upstream.URL), nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	const key = "purl%3Apkg%3Apypi%2Flangchain%400.3.7"
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/projects/abc/dependencies/"+key, nil)
	r.Handler(httpx.NotFound)(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	// The /api prefix is stripped from BOTH forms, and the escaping is intact.
	want := "/v1/projects/abc/dependencies/" + key
	if seen.escaped != want {
		t.Errorf("upstream saw escaped path %q, want %q", seen.escaped, want)
	}
	// And the upstream can still decode it to the key the caller meant.
	if got := "purl:pkg:pypi/langchain@0.3.7"; !strings.HasSuffix(seen.decoded, got) {
		t.Errorf("upstream decoded path %q, want it to end with %q", seen.decoded, got)
	}
}

// ⚠ THE ID THE USER CAN SEE MUST FIND BOTH HALVES OF THEIR REQUEST.
//
// httpx.RequestID mints an id per service and honours an inbound X-Request-ID.
// The gateway's own id lived only in its context and its RESPONSE header and
// was never put on the outbound hop, so the upstream minted a second,
// unrelated one — logged everything under that, and returned THAT one in the
// error envelope the browser renders. Searching the gateway's log for the id a
// user quotes found nothing, and no shared field joined the two log lines.
func TestTheRequestIDCrossesTheHop(t *testing.T) {
	var got string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("X-Request-ID")
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(upstream.Close)

	r, err := New(testServices(upstream.URL), nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Through httpx.RequestID, which is what assigns the id in the real chain.
	gw := httptest.NewServer(httpx.RequestID(r.Handler(httpx.NotFound)))
	t.Cleanup(gw.Close)

	resp, err := http.Get(gw.URL + "/v1/projects")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	// The response header is the id the caller is told to quote. The upstream
	// must have logged under the same one.
	want := resp.Header.Get("X-Request-ID")
	if want == "" {
		t.Fatal("the gateway returned no request id at all")
	}
	if got != want {
		t.Errorf("upstream saw request id %q, caller was given %q", got, want)
	}
}
