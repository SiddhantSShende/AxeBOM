package service_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/axebom/axebom/libs/go-shared/platform/errs"
	"github.com/axebom/axebom/services/auth/internal/service"
)

// GitHub OAuth tests against a FAKE GitHub.
//
// GitHubConfig exposes APIBase and AuthBase so the flow can be exercised
// end-to-end without network access — which also means these tests assert on
// our handling of GitHub's actual response shapes, including the ones that are
// easy to get wrong (a 200 carrying an error body, a private email).

// fakeGitHub serves the three endpoints the flow touches.
type fakeGitHub struct {
	userID   int64
	login    string
	name     string
	email    string
	verified bool

	// tokenError, when set, is returned as GitHub's error BODY with status 200
	// — which is what GitHub actually does for a bad code.
	tokenError string
}

func (f *fakeGitHub) start(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()

	mux.HandleFunc("/login/oauth/access_token", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if f.tokenError != "" {
			// Status 200 with an error body: the status alone is not enough
			// to detect failure, which is the trap this fake exists to test.
			_ = json.NewEncoder(w).Encode(map[string]string{
				"error":             f.tokenError,
				"error_description": "the code is bad",
			})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"access_token": "gho_faketoken"})
	})

	mux.HandleFunc("/user", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		body := map[string]any{"id": f.userID, "login": f.login, "name": f.name}
		if f.verified {
			// A public profile email.
			body["email"] = f.email
		}
		_ = json.NewEncoder(w).Encode(body)
	})

	mux.HandleFunc("/user/emails", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode([]map[string]any{
			{"email": f.email, "primary": true, "verified": f.verified},
		})
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func (f *fakeGitHub) client(t *testing.T) *service.GitHubClient {
	t.Helper()
	srv := f.start(t)
	return service.NewGitHubClient(service.GitHubConfig{
		ClientID: "test-client", ClientSecret: "test-secret",
		RedirectURL: "https://axebom.test/v1/auth/github/callback",
		APIBase:     srv.URL, AuthBase: srv.URL,
		HTTPClient: srv.Client(),
	})
}

// uniqueGitHubID keeps runs from colliding on the unique index.
func uniqueGitHubID() int64 { return time.Now().UnixNano() % 1_000_000_000 }

// ⚠ THE RENAME TEST.
//
// GitHub logins are renameable, and a released login can be claimed by someone
// else. Keying identity on the login would mean (a) a user who renames loses
// their account, and worse (b) whoever claims the freed name inherits it.
func TestRenamedGitHubLoginStillResolvesToTheSameUser(t *testing.T) {
	f := newFixture(t)
	existing, email := register(t, f, "GitHub Rename Org")

	githubID := uniqueGitHubID()
	if err := f.store.LinkGitHubIdentity(t.Context(), existing.UserID, githubID, "old-login"); err != nil {
		t.Fatalf("link: %v", err)
	}

	// The user renames on GitHub. Same numeric id, new login, and — to make
	// the test sharp — a different email too.
	gh := &fakeGitHub{
		userID: githubID, login: "brand-new-login",
		name: "Renamed User", email: "renamed-" + email, verified: true,
	}

	const state = "matching-state-value"
	pair, err := f.svc.CompleteGitHubLogin(t.Context(), gh.client(t),
		"code", state, state, service.RequestMeta{})
	if err != nil {
		t.Fatalf("github login after rename: %v", err)
	}

	if pair.UserID != existing.UserID {
		t.Errorf("resolved to user %q, want %q — identity followed the login, not the numeric id",
			pair.UserID, existing.UserID)
	}
	if pair.TenantID != existing.TenantID {
		t.Errorf("tenant = %q, want %q", pair.TenantID, existing.TenantID)
	}

	// The new login is recorded for display.
	u, err := f.store.FindUserByGitHubID(t.Context(), githubID)
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if u.GitHubLogin != "brand-new-login" {
		t.Errorf("github_login = %q, want the updated login", u.GitHubLogin)
	}
}

// The state parameter is the CSRF defence for the whole flow.
func TestGitHubLoginRejectsAMismatchedState(t *testing.T) {
	f := newFixture(t)
	gh := (&fakeGitHub{
		userID: uniqueGitHubID(), login: "someone",
		email: uniqueEmail(t), verified: true,
	}).client(t)

	_, err := f.svc.CompleteGitHubLogin(t.Context(), gh,
		"code", "state-from-the-attacker", "state-we-issued", service.RequestMeta{})
	if err == nil {
		t.Fatal("a callback with a mismatched state was accepted")
	}
	if !errs.Is(err, errs.AuthStateMismatch) {
		t.Errorf("code = %v, want AUTH_STATE_MISMATCH", err)
	}
}

// An unverified address is one the user merely typed. Accepting it would let
// anyone claim an address they do not control — and email is how invitations
// and account linking are matched.
func TestGitHubLoginRefusesAnUnverifiedEmail(t *testing.T) {
	f := newFixture(t)
	gh := (&fakeGitHub{
		userID: uniqueGitHubID(), login: "unverified-person",
		email: uniqueEmail(t), verified: false,
	}).client(t)

	const state = "s"
	_, err := f.svc.CompleteGitHubLogin(t.Context(), gh, "code", state, state, service.RequestMeta{})
	if err == nil {
		t.Fatal("a GitHub account with no verified email was allowed to sign in")
	}
}

// GitHub answers a bad code with HTTP 200 and an error body, so checking the
// status alone would treat a rejected sign-in as successful.
func TestGitHubTokenErrorBodyIsDetectedDespiteStatus200(t *testing.T) {
	f := newFixture(t)
	gh := (&fakeGitHub{
		userID: uniqueGitHubID(), login: "x", email: uniqueEmail(t), verified: true,
		tokenError: "bad_verification_code",
	}).client(t)

	const state = "s"
	_, err := f.svc.CompleteGitHubLogin(t.Context(), gh, "code", state, state, service.RequestMeta{})
	if err == nil {
		t.Fatal("a rejected authorization code was treated as a successful sign-in")
	}
	if !errs.Is(err, errs.AuthProviderError) {
		t.Errorf("code = %v, want AUTH_PROVIDER_ERROR", err)
	}
}

func TestGitHubLoginRequiresACode(t *testing.T) {
	f := newFixture(t)
	gh := (&fakeGitHub{
		userID: uniqueGitHubID(), login: "x", email: uniqueEmail(t), verified: true,
	}).client(t)

	const state = "s"
	if _, err := f.svc.CompleteGitHubLogin(t.Context(), gh, "", state, state,
		service.RequestMeta{}); err == nil {
		t.Fatal("a callback with no authorization code was accepted")
	}
}

// A GitHub user whose verified email matches an existing local account is
// LINKED to it, not given a second identity for the same person.
func TestGitHubLoginLinksToAnExistingAccountByVerifiedEmail(t *testing.T) {
	f := newFixture(t)
	existing, email := register(t, f, "GitHub Link Org")

	githubID := uniqueGitHubID()
	gh := (&fakeGitHub{
		userID: githubID, login: "linkable", name: "Linked User",
		email: email, verified: true,
	}).client(t)

	const state = "s"
	pair, err := f.svc.CompleteGitHubLogin(t.Context(), gh, "code", state, state, service.RequestMeta{})
	if err != nil {
		t.Fatalf("github login: %v", err)
	}
	if pair.UserID != existing.UserID {
		t.Errorf("a second account was created for the same person: %q vs %q",
			pair.UserID, existing.UserID)
	}

	u, err := f.store.FindUserByGitHubID(t.Context(), githubID)
	if err != nil {
		t.Fatalf("the GitHub identity was not linked: %v", err)
	}
	if u.ID != existing.UserID {
		t.Errorf("linked to the wrong user: %q", u.ID)
	}
}

// A GitHub user with no local account and no invitation belongs to no tenant.
// They must not silently get one — that would let anyone with a GitHub account
// create tenants by signing in.
func TestGitHubLoginWithNoMembershipIsRefused(t *testing.T) {
	f := newFixture(t)
	gh := (&fakeGitHub{
		userID: uniqueGitHubID(), login: "stranger",
		name: "A Stranger", email: uniqueEmail(t), verified: true,
	}).client(t)

	const state = "s"
	_, err := f.svc.CompleteGitHubLogin(t.Context(), gh, "code", state, state, service.RequestMeta{})
	if err == nil {
		t.Fatal("a GitHub user with no membership was issued a session")
	}
}
