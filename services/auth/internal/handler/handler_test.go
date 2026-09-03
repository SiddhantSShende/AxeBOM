package handler_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/axebom/axebom/libs/go-shared/auth"
	"github.com/axebom/axebom/libs/go-shared/platform/config"
	"github.com/axebom/axebom/libs/go-shared/platform/db"
	"github.com/axebom/axebom/services/auth/internal/handler"
	"github.com/axebom/axebom/services/auth/internal/service"
	"github.com/axebom/axebom/services/auth/internal/store"
)

// HTTP-surface tests: cookies, CSRF state, body limits — not identity.
//
// Most need no database, because the request is rejected before any business
// logic runs. The OAuth state tests DO need one: a mismatched state is audited
// as a possible CSRF attempt, and that write is the behaviour worth proving.

// newHandler builds a handler with NO service, for cases that must be rejected
// at the transport layer. If one of these ever reaches the service it will
// panic on the nil pointer — which is the correct outcome, because a request
// reaching business logic here would mean the guard did not run.
func newHandler(gh *service.GitHubClient) *handler.Handler {
	return handler.New(nil, gh, handler.Config{})
}

// newHandlerWithCfg is newHandler with a caller-supplied Config, for the few
// tests that assert on GitHubRedirectURL/GitHubConnectRedirectURL — fields
// that moved here from service.GitHubConfig once one GitHubClient started
// backing two flows with two different callback URLs.
func newHandlerWithCfg(gh *service.GitHubClient, cfg handler.Config) *handler.Handler {
	return handler.New(nil, gh, cfg)
}

// newLiveHandler builds a fully wired handler against the dev database.
func newLiveHandler(t *testing.T, gh *service.GitHubClient) *handler.Handler {
	t.Helper()
	if os.Getenv("SKIP_DB_TESTS") != "" {
		t.Skip("SKIP_DB_TESTS is set")
	}

	cfg, err := config.LoadService("auth")
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	pool, err := db.Open(t.Context(), cfg.Postgres)
	if err != nil {
		t.Skipf("database unavailable (%v) — run `task dev && task db:reset`", err)
	}
	t.Cleanup(pool.Close)

	issuer, err := auth.NewIssuer(auth.TokenConfig{
		SigningKey: []byte("test-signing-key-that-is-long-enough-to-pass-validation"),
		Issuer:     "axebom-test",
		AccessTTL:  15 * time.Minute,
		RefreshTTL: 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("issuer: %v", err)
	}

	svc := service.New(service.Config{Store: store.New(pool), Issuer: issuer})
	return handler.New(svc, gh, handler.Config{})
}

// ---------------------------------------------------------------------------
// Cookie attributes
// ---------------------------------------------------------------------------

// The refresh token is a long-lived credential. Every attribute here is doing
// a job, and the ZERO-VALUE config must produce the safe combination — that is
// the whole reason the field is AllowInsecureCookies rather than SecureCookies.
func TestRefreshCookieIsSafeByDefault(t *testing.T) {
	h := newLiveHandler(t, service.NewGitHubClient(service.GitHubConfig{}))

	rec := httptest.NewRecorder()
	h.Register(rec, httptest.NewRequest(http.MethodPost, "/v1/auth/register",
		strings.NewReader(`{"email":"cookie-`+uniqueSuffix()+
			`@example.test","password":"correct-horse-battery-staple",`+
			`"name":"Cookie Test","tenant_name":"Cookie Test Org"}`)))

	if rec.Code != http.StatusCreated {
		t.Fatalf("register: status = %d, body = %s", rec.Code, rec.Body.String())
	}

	var found bool
	for _, c := range rec.Result().Cookies() {
		if c.Name != "axebom_refresh" {
			continue
		}
		found = true

		if !c.HttpOnly {
			t.Error("refresh cookie is readable from JavaScript, so an XSS can steal it")
		}
		if !c.Secure {
			t.Error("refresh cookie has no Secure attribute, so it travels over plain http")
		}
		if c.SameSite != http.SameSiteStrictMode {
			t.Errorf("SameSite = %v, want Strict — the refresh endpoint should never "+
				"be reachable from another site", c.SameSite)
		}
		if c.Path != "/v1/auth" {
			t.Errorf("Path = %q, want /v1/auth so the credential is not attached "+
				"to every API call", c.Path)
		}
	}
	if !found {
		t.Fatal("no refresh cookie was set")
	}

	// And the refresh token must NOT also appear in the body, or the HttpOnly
	// cookie protects nothing.
	if strings.Contains(rec.Body.String(), "refresh_token") {
		t.Error("the response body carries a refresh token, defeating the HttpOnly cookie")
	}
}

func uniqueSuffix() string {
	return strconv.FormatInt(time.Now().UnixNano(), 36)
}

// ---------------------------------------------------------------------------
// OAuth CSRF
// ---------------------------------------------------------------------------

// Without a state check an attacker starts an OAuth flow with THEIR GitHub
// account, sends the victim the callback URL, and the victim's browser ends up
// holding a session for the attacker's identity. Everything the victim then
// uploads lands in an account the attacker controls.
func TestGitHubCallbackRejectsAMissingState(t *testing.T) {
	h := newHandler(service.NewGitHubClient(service.GitHubConfig{
		ClientID: "id", ClientSecret: "secret",
	}))

	req := httptest.NewRequest(http.MethodGet, "/v1/auth/github/callback?code=abc&state=attacker", nil)
	// No state cookie: the browser never started this flow.
	rec := httptest.NewRecorder()
	h.GitHubCallback(rec, req)

	if rec.Code == http.StatusFound || rec.Code == http.StatusOK {
		t.Fatalf("a callback with no state cookie was accepted (status %d)", rec.Code)
	}
	assertErrorCode(t, rec, "AUTH_STATE_MISMATCH")
}

func TestGitHubCallbackRejectsAMismatchedState(t *testing.T) {
	h := newLiveHandler(t, service.NewGitHubClient(service.GitHubConfig{
		ClientID: "id", ClientSecret: "secret",
	}))

	req := httptest.NewRequest(http.MethodGet, "/v1/auth/github/callback?code=abc&state=attacker-value", nil)
	req.AddCookie(&http.Cookie{Name: "axebom_oauth_state", Value: "the-real-value"})
	rec := httptest.NewRecorder()
	h.GitHubCallback(rec, req)

	if rec.Code == http.StatusFound || rec.Code == http.StatusOK {
		t.Fatalf("a callback whose state did not match the cookie was accepted (status %d)", rec.Code)
	}
}

// The state must be single-use. If the cookie survives a failed attempt, a
// leaked callback URL can be replayed.
func TestGitHubCallbackClearsTheStateCookie(t *testing.T) {
	h := newLiveHandler(t, service.NewGitHubClient(service.GitHubConfig{
		ClientID: "id", ClientSecret: "secret",
	}))

	req := httptest.NewRequest(http.MethodGet, "/v1/auth/github/callback?code=abc&state=x", nil)
	req.AddCookie(&http.Cookie{Name: "axebom_oauth_state", Value: "y"})
	rec := httptest.NewRecorder()
	h.GitHubCallback(rec, req)

	var cleared bool
	for _, c := range rec.Result().Cookies() {
		if c.Name == "axebom_oauth_state" && c.MaxAge < 0 {
			cleared = true
		}
	}
	if !cleared {
		t.Error("the OAuth state cookie survived a failed callback and can be replayed")
	}
}

func TestGitHubAuthorizeSetsAStateCookieAndRedirects(t *testing.T) {
	h := newHandlerWithCfg(service.NewGitHubClient(service.GitHubConfig{
		ClientID: "client-id", ClientSecret: "secret",
	}), handler.Config{GitHubRedirectURL: "https://axebom.test/v1/auth/github/callback"})

	rec := httptest.NewRecorder()
	h.GitHubAuthorize(rec, httptest.NewRequest(http.MethodGet, "/v1/auth/github/authorize", nil))

	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", rec.Code)
	}

	var state string
	for _, c := range rec.Result().Cookies() {
		if c.Name == "axebom_oauth_state" {
			state = c.Value
			if !c.HttpOnly {
				t.Error("the state cookie is readable from JavaScript")
			}
			// Lax, not Strict: the callback is a cross-site redirect from
			// github.com, and Strict would withhold the cookie entirely —
			// every sign-in would fail its own state check.
			if c.SameSite != http.SameSiteLaxMode {
				t.Errorf("SameSite = %v, want Lax or the OAuth redirect drops the cookie", c.SameSite)
			}
			// ⚠ MUST BE /api-PREFIXED — see connectStatePath's identical
			// guard (github_connect_test.go) for why: a real browser only
			// ever requests this service through nginx's/Vite's /api/
			// proxy, so a Path scoped to the bare internal /v1/... route is
			// never a prefix of what the browser actually requests and the
			// cookie is silently withheld on every real callback.
			if c.Path != "/api/v1/auth/github" {
				t.Errorf("Path = %q, want /api/v1/auth/github", c.Path)
			}
		}
	}
	if state == "" {
		t.Fatal("no state cookie was set")
	}

	loc := rec.Header().Get("Location")
	if !strings.Contains(loc, "state="+state) {
		t.Errorf("the redirect does not carry the cookie's state: %s", loc)
	}
	if !strings.HasPrefix(loc, "https://github.com/login/oauth/authorize") {
		t.Errorf("unexpected redirect target: %s", loc)
	}
	// Account linking must not request repository access.
	if strings.Contains(loc, "repo") {
		t.Errorf("the sign-in flow requests repository scope: %s", loc)
	}
	// The configured LOGIN callback, not the connect one — this is the
	// regression this test guards: redirect_uri now travels per-call rather
	// than living fixed on the GitHubClient.
	if !strings.Contains(loc, "redirect_uri=https%3A%2F%2Faxebom.test%2Fv1%2Fauth%2Fgithub%2Fcallback") {
		t.Errorf("redirect_uri is missing or wrong: %s", loc)
	}
}

func TestGitHubAuthorizeFailsWhenNotConfigured(t *testing.T) {
	h := newHandler(service.NewGitHubClient(service.GitHubConfig{}))

	rec := httptest.NewRecorder()
	h.GitHubAuthorize(rec, httptest.NewRequest(http.MethodGet, "/v1/auth/github/authorize", nil))

	if rec.Code == http.StatusFound {
		t.Error("an unconfigured GitHub flow redirected the user anyway")
	}
}

// ---------------------------------------------------------------------------
// GitHub "connect" — the repo-scoped flow, distinct from sign-in
// ---------------------------------------------------------------------------
//
// Mirrors the login CSRF tests above almost exactly, on purpose: it is the
// same state-cookie defence reused for a second flow, and a divergence here
// is exactly the kind of thing that survives review because "it's basically
// the same as login" reads as covered when it silently isn't.

// CompleteGitHubConnect's state check runs before it ever touches the
// service's store (unlike CompleteGitHubLogin, which audits a mismatch) — so,
// unlike the login equivalents below, these need no live database: a nil
// *service.Service is a valid receiver as long as the method never
// dereferences it, and the state check returns before that would happen.
func TestGitHubConnectCallbackRejectsAMissingState(t *testing.T) {
	h := newHandler(service.NewGitHubClient(service.GitHubConfig{
		ClientID: "id", ClientSecret: "secret",
	}))

	req := httptest.NewRequest(http.MethodGet,
		"/v1/auth/github/connect/callback?code=abc&state=attacker", nil)
	// No state cookie: the browser never started this flow.
	rec := httptest.NewRecorder()
	h.GitHubConnectCallback(rec, req)

	if rec.Code == http.StatusFound || rec.Code == http.StatusOK {
		t.Fatalf("a connect callback with no state cookie was accepted (status %d)", rec.Code)
	}
	assertErrorCode(t, rec, "AUTH_STATE_MISMATCH")
}

func TestGitHubConnectCallbackRejectsAMismatchedState(t *testing.T) {
	h := newHandler(service.NewGitHubClient(service.GitHubConfig{
		ClientID: "id", ClientSecret: "secret",
	}))

	req := httptest.NewRequest(http.MethodGet,
		"/v1/auth/github/connect/callback?code=abc&state=attacker-value", nil)
	req.AddCookie(&http.Cookie{Name: "axebom_oauth_connect_state", Value: "the-real-value"})
	rec := httptest.NewRecorder()
	h.GitHubConnectCallback(rec, req)

	if rec.Code == http.StatusFound || rec.Code == http.StatusOK {
		t.Fatalf("a connect callback whose state did not match the cookie was accepted (status %d)",
			rec.Code)
	}
}

// The state must be single-use here too: if the cookie survives a failed
// attempt, a leaked popup callback URL can be replayed.
func TestGitHubConnectCallbackClearsTheStateCookie(t *testing.T) {
	h := newHandler(service.NewGitHubClient(service.GitHubConfig{
		ClientID: "id", ClientSecret: "secret",
	}))

	req := httptest.NewRequest(http.MethodGet, "/v1/auth/github/connect/callback?code=abc&state=x", nil)
	req.AddCookie(&http.Cookie{Name: "axebom_oauth_connect_state", Value: "y"})
	rec := httptest.NewRecorder()
	h.GitHubConnectCallback(rec, req)

	var cleared bool
	for _, c := range rec.Result().Cookies() {
		if c.Name == "axebom_oauth_connect_state" && c.MaxAge < 0 {
			cleared = true
		}
	}
	if !cleared {
		t.Error("the connect OAuth state cookie survived a failed callback and can be replayed")
	}
}

// ⚠ THE ISOLATION PROOF.
//
// Login and connect are two independent OAuth attempts that can be in flight
// in the same browser at once (a user mid-registration, in another tab,
// signed out and back in). A shared cookie name or path would let one flow's
// callback consume the other's state — accepting a connect callback as a
// completed login, or vice versa.
func TestGitHubConnectStateCookieIsIsolatedFromLoginStateCookie(t *testing.T) {
	h := newHandlerWithCfg(service.NewGitHubClient(service.GitHubConfig{
		ClientID: "client-id", ClientSecret: "secret",
	}), handler.Config{
		GitHubRedirectURL:        "https://axebom.test/v1/auth/github/callback",
		GitHubConnectRedirectURL: "https://axebom.test/v1/auth/github/connect/callback",
	})

	loginRec := httptest.NewRecorder()
	h.GitHubAuthorize(loginRec, httptest.NewRequest(http.MethodGet, "/v1/auth/github/authorize", nil))
	connectRec := httptest.NewRecorder()
	h.GitHubConnectAuthorize(connectRec,
		httptest.NewRequest(http.MethodGet, "/v1/auth/github/connect/authorize", nil))

	loginCookie := findCookie(t, loginRec, "axebom_oauth_state")
	connectCookie := findCookie(t, connectRec, "axebom_oauth_connect_state")

	if loginCookie.Name == connectCookie.Name {
		t.Fatal("login and connect share a state cookie name")
	}
	if loginCookie.Value == connectCookie.Value {
		t.Error("login and connect minted the same state value — one flow's callback " +
			"could complete the other's")
	}
	if loginCookie.Path == connectCookie.Path {
		t.Errorf("login and connect share a cookie path (%q) — either flow's callback "+
			"would receive both cookies", loginCookie.Path)
	}
}

func findCookie(t *testing.T, rec *httptest.ResponseRecorder, name string) *http.Cookie {
	t.Helper()
	for _, c := range rec.Result().Cookies() {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("no %q cookie was set", name)
	return nil
}

func TestGitHubConnectAuthorizeSetsAStateCookieAndRedirectsWithRepoScope(t *testing.T) {
	h := newHandlerWithCfg(service.NewGitHubClient(service.GitHubConfig{
		ClientID: "client-id", ClientSecret: "secret",
	}), handler.Config{
		GitHubConnectRedirectURL: "https://axebom.test/v1/auth/github/connect/callback",
	})

	rec := httptest.NewRecorder()
	h.GitHubConnectAuthorize(rec,
		httptest.NewRequest(http.MethodGet, "/v1/auth/github/connect/authorize", nil))

	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", rec.Code)
	}

	c := findCookie(t, rec, "axebom_oauth_connect_state")
	if !c.HttpOnly {
		t.Error("the connect state cookie is readable from JavaScript")
	}
	if c.SameSite != http.SameSiteLaxMode {
		t.Errorf("SameSite = %v, want Lax or the OAuth redirect drops the cookie", c.SameSite)
	}
	// ⚠ MUST BE /api-PREFIXED. Only nginx's (and the Vite dev proxy's) /api/
	// location routes a real browser's request to the gateway — a Path
	// scoped to this service's own internal /v1/... route is never a prefix
	// of what the browser actually requests, so the browser would never send
	// this cookie back on the real callback (RFC 6265 §5.1.4), and the
	// connect flow would fail AUTH_STATE_MISMATCH on every real attempt
	// despite passing every test that talks to the handler directly.
	if c.Path != "/api/v1/auth/github/connect" {
		t.Errorf("Path = %q, want /api/v1/auth/github/connect", c.Path)
	}

	loc := rec.Header().Get("Location")
	if !strings.Contains(loc, "state="+c.Value) {
		t.Errorf("the redirect does not carry the cookie's state: %s", loc)
	}
	if !strings.HasPrefix(loc, "https://github.com/login/oauth/authorize") {
		t.Errorf("unexpected redirect target: %s", loc)
	}
	// ⚠ THE POINT OF THIS WHOLE FLOW: repo scope, which the login flow
	// deliberately never requests.
	if !strings.Contains(loc, "scope=repo") {
		t.Errorf("the connect flow does not request repository scope: %s", loc)
	}
	if !strings.Contains(loc,
		"redirect_uri=https%3A%2F%2Faxebom.test%2Fv1%2Fauth%2Fgithub%2Fconnect%2Fcallback") {
		t.Errorf("redirect_uri is missing or wrong: %s", loc)
	}
}

func TestGitHubConnectAuthorizeFailsWhenNotConfigured(t *testing.T) {
	h := newHandler(service.NewGitHubClient(service.GitHubConfig{}))

	rec := httptest.NewRecorder()
	h.GitHubConnectAuthorize(rec,
		httptest.NewRequest(http.MethodGet, "/v1/auth/github/connect/authorize", nil))

	if rec.Code == http.StatusFound {
		t.Error("an unconfigured GitHub connect flow redirected the user anyway")
	}
}

// The callback must never set the AxeBOM refresh cookie — this flow mints no
// session, however it completes.
func TestGitHubConnectCallbackNeverSetsARefreshCookie(t *testing.T) {
	h := newHandler(service.NewGitHubClient(service.GitHubConfig{
		ClientID: "id", ClientSecret: "secret",
	}))

	req := httptest.NewRequest(http.MethodGet,
		"/v1/auth/github/connect/callback?code=abc&state=attacker", nil)
	rec := httptest.NewRecorder()
	h.GitHubConnectCallback(rec, req)

	for _, c := range rec.Result().Cookies() {
		if c.Name == "axebom_refresh" {
			t.Fatal("the connect callback set an AxeBOM session cookie")
		}
	}
}

// ---------------------------------------------------------------------------
// Request handling
// ---------------------------------------------------------------------------

func TestRefreshWithoutATokenIsRejected(t *testing.T) {
	h := newHandler(service.NewGitHubClient(service.GitHubConfig{}))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/refresh", strings.NewReader("{}"))
	h.Refresh(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

// A typo'd field silently becoming its zero value is worse than an error: a
// registration with a mistyped `tenant_name` would create a nameless org.
func TestUnknownJSONFieldsAreRejected(t *testing.T) {
	h := newHandler(service.NewGitHubClient(service.GitHubConfig{}))

	rec := httptest.NewRecorder()
	h.Register(rec, httptest.NewRequest(http.MethodPost, "/v1/auth/register",
		strings.NewReader(`{"email":"a@b.test","password":"correct-horse-battery","tenantName":"Typo"}`)))

	// 422, not 400: docs/02-CONTRACTS.md §9 fixes every VALIDATION_ code at
	// Unprocessable Entity, and the taxonomy is the contract.
	if rec.Code != http.StatusUnprocessableEntity {
		t.Errorf("status = %d, want 422 for an unknown field", rec.Code)
	}
	assertErrorCode(t, rec, "VALIDATION_BODY_MALFORMED")
}

func TestMalformedJSONIsRejected(t *testing.T) {
	h := newHandler(service.NewGitHubClient(service.GitHubConfig{}))

	rec := httptest.NewRecorder()
	h.Login(rec, httptest.NewRequest(http.MethodPost, "/v1/auth/login",
		strings.NewReader(`{"email": `)))

	if rec.Code != http.StatusUnprocessableEntity {
		t.Errorf("status = %d, want 422", rec.Code)
	}
}

// A handler that touches tenant data without middleware must fail closed, not
// operate on an empty tenant id.
func TestTenantScopedHandlersFailClosedWithoutAuthentication(t *testing.T) {
	h := newHandler(service.NewGitHubClient(service.GitHubConfig{}))

	for name, fn := range map[string]http.HandlerFunc{
		"logout":        h.Logout,
		"me":            h.Me,
		"create invite": h.CreateInvite,
	} {
		t.Run(name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			fn(rec, httptest.NewRequest(http.MethodPost, "/x", strings.NewReader("{}")))

			if rec.Code == http.StatusOK || rec.Code == http.StatusNoContent {
				t.Errorf("status = %d; the handler ran with no tenant in context", rec.Code)
			}
		})
	}
}

func assertErrorCode(t *testing.T, rec *httptest.ResponseRecorder, want string) {
	t.Helper()
	var body struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("response is not the canonical error shape: %v (%s)", err, rec.Body.String())
	}
	if body.Error.Code != want {
		t.Errorf("code = %q, want %q", body.Error.Code, want)
	}
}
