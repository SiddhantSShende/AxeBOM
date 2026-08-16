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

	"github.com/encorebom/encorebom/libs/go-shared/auth"
	"github.com/encorebom/encorebom/libs/go-shared/platform/config"
	"github.com/encorebom/encorebom/libs/go-shared/platform/db"
	"github.com/encorebom/encorebom/services/auth/internal/handler"
	"github.com/encorebom/encorebom/services/auth/internal/service"
	"github.com/encorebom/encorebom/services/auth/internal/store"
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
		Issuer:     "encorebom-test",
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
		if c.Name != "encorebom_refresh" {
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
	req.AddCookie(&http.Cookie{Name: "encorebom_oauth_state", Value: "the-real-value"})
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
	req.AddCookie(&http.Cookie{Name: "encorebom_oauth_state", Value: "y"})
	rec := httptest.NewRecorder()
	h.GitHubCallback(rec, req)

	var cleared bool
	for _, c := range rec.Result().Cookies() {
		if c.Name == "encorebom_oauth_state" && c.MaxAge < 0 {
			cleared = true
		}
	}
	if !cleared {
		t.Error("the OAuth state cookie survived a failed callback and can be replayed")
	}
}

func TestGitHubAuthorizeSetsAStateCookieAndRedirects(t *testing.T) {
	h := newHandler(service.NewGitHubClient(service.GitHubConfig{
		ClientID: "client-id", ClientSecret: "secret",
		RedirectURL: "https://encorebom.test/v1/auth/github/callback",
	}))

	rec := httptest.NewRecorder()
	h.GitHubAuthorize(rec, httptest.NewRequest(http.MethodGet, "/v1/auth/github/authorize", nil))

	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", rec.Code)
	}

	var state string
	for _, c := range rec.Result().Cookies() {
		if c.Name == "encorebom_oauth_state" {
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
