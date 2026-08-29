package service

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/axebom/axebom/libs/go-shared/auth"
	"github.com/axebom/axebom/libs/go-shared/authz"
	"github.com/axebom/axebom/libs/go-shared/platform/errs"
	"github.com/axebom/axebom/services/auth/internal/store"
)

// GitHub OAuth (Authorization Code flow).
//
// Two rules govern everything here:
//
//  1. IDENTITY IS THE NUMERIC USER ID, never the login. GitHub logins can be
//     renamed, and a released login can be claimed by someone else. Keying on
//     the login would let whoever claims a freed username inherit the account.
//
//  2. THE STATE PARAMETER IS NOT OPTIONAL. Without it an attacker starts a
//     flow with their own GitHub account, sends the victim the callback URL,
//     and the victim's session ends up bound to the attacker's identity — so
//     everything the victim then uploads lands in an account the attacker
//     controls. It is the CSRF defence for the whole flow.

// GitHubConfig configures the OAuth client.
//
// ⚠ NO RedirectURL FIELD, DELIBERATELY. This one client now backs two flows
// with two different registered callback URLs (login vs. connect), so a
// single fixed redirect on the client would be a lie for whichever flow
// didn't set it. Each caller passes its own to AuthorizeEndpoint/exchangeCode
// instead — see handler.Config's GitHubRedirectURL/GitHubConnectRedirectURL.
type GitHubConfig struct {
	ClientID     string
	ClientSecret string

	// APIBase and AuthBase are overridable so tests can point at a local
	// server, and so GitHub Enterprise is supported.
	APIBase  string
	AuthBase string

	HTTPClient *http.Client
}

// GitHubClient talks to GitHub's OAuth and user APIs.
type GitHubClient struct {
	cfg GitHubConfig
	hc  *http.Client
}

// NewGitHubClient builds a client. A zero ClientID disables the flow, which is
// the correct default for a self-hosted install that does not use GitHub.
func NewGitHubClient(cfg GitHubConfig) *GitHubClient {
	if cfg.APIBase == "" {
		cfg.APIBase = "https://api.github.com"
	}
	if cfg.AuthBase == "" {
		cfg.AuthBase = "https://github.com"
	}
	hc := cfg.HTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: 15 * time.Second}
	}
	return &GitHubClient{cfg: cfg, hc: hc}
}

// Enabled reports whether GitHub sign-in is configured.
func (g *GitHubClient) Enabled() bool {
	return g != nil && g.cfg.ClientID != "" && g.cfg.ClientSecret != ""
}

// AuthorizeEndpoint is the URL a browser should be sent to.
//
// redirectURL and scope are supplied by the caller rather than fixed on the
// client, because this one App now backs two flows that must never be
// confused: BeginGitHubLogin asks for `read:user user:email` — enough to
// identify the user, and nothing more — while BeginGitHubConnect asks for
// `repo`, to read a project's repositories, and lands on a different callback
// path. GitHub OAuth Apps support multiple registered callback URLs, so both
// live under the same ClientID/ClientSecret without a second app
// registration.
func (g *GitHubClient) AuthorizeEndpoint(state, redirectURL, scope string) string {
	q := url.Values{
		"client_id":    {g.cfg.ClientID},
		"redirect_uri": {redirectURL},
		"scope":        {scope},
		"state":        {state},
	}
	return g.cfg.AuthBase + "/login/oauth/authorize?" + q.Encode()
}

// githubUser is the subset of GitHub's user payload we consume.
type githubUser struct {
	ID    int64  `json:"id"` // ← the durable identity
	Login string `json:"login"`
	Name  string `json:"name"`
	Email string `json:"email"`
}

// exchangeCode swaps an authorization code for an access token.
//
// redirectURL must be EXACTLY what was sent to AuthorizeEndpoint for this
// flow — GitHub rejects a mismatch — so it travels through the same way
// AuthorizeEndpoint's did rather than being re-read from g.cfg, which now
// serves two different callback paths.
func (g *GitHubClient) exchangeCode(ctx context.Context, code, redirectURL string) (string, error) {
	form := url.Values{
		"client_id":     {g.cfg.ClientID},
		"client_secret": {g.cfg.ClientSecret},
		"code":          {code},
		"redirect_uri":  {redirectURL},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		g.cfg.AuthBase+"/login/oauth/access_token", strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := g.hc.Do(req)
	if err != nil {
		return "", errs.Wrap(err, errs.AuthProviderError, "could not reach GitHub")
	}
	defer func() { _ = resp.Body.Close() }()

	// Cap the read: an upstream that streams forever must not exhaust memory.
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", errs.Wrap(err, errs.AuthProviderError, "could not read GitHub response")
	}

	var out struct {
		AccessToken      string `json:"access_token"`
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return "", errs.Wrap(err, errs.AuthProviderError, "GitHub returned an unreadable response")
	}
	// GitHub answers 200 with an error BODY for a bad code, so the status is
	// not sufficient on its own.
	if out.Error != "" {
		return "", errs.Newf(errs.AuthProviderError, "GitHub rejected the sign-in: %s", out.Error)
	}
	if out.AccessToken == "" {
		return "", errs.New(errs.AuthProviderError, "GitHub did not return an access token")
	}
	return out.AccessToken, nil
}

// fetchUser reads the authenticated user, resolving a verified email.
func (g *GitHubClient) fetchUser(ctx context.Context, token string) (githubUser, error) {
	var u githubUser
	if err := g.get(ctx, token, "/user", &u); err != nil {
		return githubUser{}, err
	}
	if u.ID == 0 {
		return githubUser{}, errs.New(errs.AuthProviderError, "GitHub did not return a user id")
	}

	if u.Email == "" {
		// The profile email is empty when the user keeps it private, so ask
		// the emails endpoint.
		var emails []struct {
			Email    string `json:"email"`
			Primary  bool   `json:"primary"`
			Verified bool   `json:"verified"`
		}
		if err := g.get(ctx, token, "/user/emails", &emails); err == nil {
			for _, e := range emails {
				// VERIFIED ONLY. An unverified address is one the user merely
				// typed — accepting it would let someone claim an address they
				// do not control, and email is how invitations are matched.
				if e.Primary && e.Verified {
					u.Email = e.Email
					break
				}
			}
		}
	}
	if u.Email == "" {
		return githubUser{}, errs.New(errs.AuthProviderError,
			"no verified email address is available on this GitHub account")
	}
	return u, nil
}

func (g *GitHubClient) get(ctx context.Context, token, path string, into any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, g.cfg.APIBase+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := g.hc.Do(req)
	if err != nil {
		return errs.Wrap(err, errs.AuthProviderError, "could not reach GitHub")
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return errs.Newf(errs.AuthProviderError, "GitHub returned %d for %s", resp.StatusCode, path)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(into)
}

// ---------------------------------------------------------------------------
// Service-level flow
// ---------------------------------------------------------------------------

// BeginGitHubLogin mints the CSRF state the caller must store and echo back.
func (s *Service) BeginGitHubLogin(gh *GitHubClient, redirectURL string) (authorizeURL, state string, err error) {
	if !gh.Enabled() {
		return "", "", errs.New(errs.AuthProviderError, "GitHub sign-in is not configured")
	}
	state, err = auth.NewOAuthState()
	if err != nil {
		return "", "", err
	}
	return gh.AuthorizeEndpoint(state, redirectURL, "read:user user:email"), state, nil
}

// CompleteGitHubLogin finishes the flow.
//
// wantState comes from the cookie set at authorize time; gotState from the
// query string. They MUST match — see rule 2 at the top of this file.
func (s *Service) CompleteGitHubLogin(ctx context.Context, gh *GitHubClient,
	code, gotState, wantState, redirectURL string, meta RequestMeta,
) (TokenPair, error) {
	if err := auth.VerifyOAuthState(gotState, wantState); err != nil {
		s.audit(ctx, store.AuthEvent{
			Action:   "auth.github.state_mismatch",
			Metadata: map[string]any{"note": "OAuth state did not match; possible CSRF"},
			IP:       meta.IP, UserAgent: meta.UserAgent,
		})
		return TokenPair{}, err
	}
	if code == "" {
		return TokenPair{}, errs.New(errs.ValidationFieldRequired, "missing authorization code")
	}

	accessToken, err := gh.exchangeCode(ctx, code, redirectURL)
	if err != nil {
		return TokenPair{}, err
	}
	ghUser, err := gh.fetchUser(ctx, accessToken)
	if err != nil {
		return TokenPair{}, err
	}

	user, err := s.resolveGitHubUser(ctx, ghUser)
	if err != nil {
		return TokenPair{}, err
	}

	membership, err := s.selectMembership(ctx, user.ID, "")
	if err != nil {
		return TokenPair{}, err
	}

	_ = s.store.TouchLastLogin(ctx, user.ID)
	s.audit(ctx, store.AuthEvent{
		TenantID: membership.TenantID, ActorID: user.ID, Action: "auth.login",
		Metadata: map[string]any{
			"provider":       "github",
			"github_user_id": strconv.FormatInt(ghUser.ID, 10),
		},
		IP: meta.IP, UserAgent: meta.UserAgent,
	})

	return s.issueFor(ctx, user.ID, membership.TenantID, membership.TenantName, membership.Role, meta)
}

// ---------------------------------------------------------------------------
// GitHub "connect" — a repo-scoped flow that is NOT sign-in
// ---------------------------------------------------------------------------
//
// BeginGitHubConnect/CompleteGitHubConnect exist because CompleteGitHubLogin's
// `repo` access was deliberately never requested (see AuthorizeEndpoint's
// comment) — a project's "Connect GitHub" button needs a token scoped to read
// repositories, which is a different consent than "let AxeBOM know who you
// are". The two must stay separable: this pair mints no AxeBOM session,
// resolves no local user, and writes nothing to the database. It hands back
// the raw GitHub token and nothing else — the caller (an authenticated
// project-registration request) is what decides what to do with it.

// BeginGitHubConnect mints the CSRF state for the connect flow.
func (s *Service) BeginGitHubConnect(gh *GitHubClient, redirectURL string) (authorizeURL, state string, err error) {
	if !gh.Enabled() {
		return "", "", errs.New(errs.AuthProviderError, "GitHub is not configured")
	}
	state, err = auth.NewOAuthState()
	if err != nil {
		return "", "", err
	}
	return gh.AuthorizeEndpoint(state, redirectURL, "repo"), state, nil
}

// CompleteGitHubConnect exchanges the code for a repo-scoped access token.
//
// ⚠ NO SESSION. NO USER LOOKUP. NO DATABASE WRITE.
//
// Everything CompleteGitHubLogin does past this point — resolveGitHubUser,
// selectMembership, issueFor — is what a LOGIN needs and a source connection
// must not touch: this token is not an AxeBOM identity, and treating it as
// one would let a repo-scoped consent silently establish (or worse, hijack) a
// signed-in session.
func (s *Service) CompleteGitHubConnect(ctx context.Context, gh *GitHubClient,
	code, gotState, wantState, redirectURL string,
) (string, error) {
	if err := auth.VerifyOAuthState(gotState, wantState); err != nil {
		return "", err
	}
	if code == "" {
		return "", errs.New(errs.ValidationFieldRequired, "missing authorization code")
	}
	return gh.exchangeCode(ctx, code, redirectURL)
}

// resolveGitHubUser finds or links the local account.
//
// Lookup order is deliberate:
//
//  1. by GitHub numeric id  — the account is already linked; a rename here is
//     just a profile update, and the user keeps access.
//  2. by email              — an existing local account: LINK it rather than
//     creating a duplicate identity for one person.
//  3. create                — genuinely new.
func (s *Service) resolveGitHubUser(ctx context.Context, gh githubUser) (store.User, error) {
	user, err := s.store.FindUserByGitHubID(ctx, gh.ID)
	if err == nil {
		if user.GitHubLogin != gh.Login {
			// They renamed themselves on GitHub. Record the new login for
			// display; the numeric id is what actually identified them.
			_ = s.store.UpdateGitHubLogin(ctx, user.ID, gh.Login)
		}
		return user, nil
	}
	if !errors.Is(err, store.ErrNotFound) {
		return store.User{}, err
	}

	email := normalizeEmail(gh.Email)
	user, err = s.store.FindUserByEmail(ctx, email)
	if err == nil {
		// Linking is safe ONLY because the email came back verified from
		// GitHub — see fetchUser. Linking on an unverified address would let
		// anyone claim any account by typing its email into GitHub.
		if err := s.store.LinkGitHubIdentity(ctx, user.ID, gh.ID, gh.Login); err != nil {
			return store.User{}, err
		}
		user.GitHubUserID, user.GitHubLogin = gh.ID, gh.Login
		return user, nil
	}
	if !errors.Is(err, store.ErrNotFound) {
		return store.User{}, err
	}

	return s.store.CreateUser(ctx, store.CreateUserParams{
		Email:        email,
		Name:         firstNonEmpty(gh.Name, gh.Login),
		GitHubLogin:  gh.Login,
		GitHubUserID: gh.ID,
		AuthProvider: "github",
		// No password hash: this account signs in through GitHub only.
	})
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

// RoleOrDefault parses a role string, falling back to the least privilege.
func RoleOrDefault(s string) authz.Role {
	if r, err := authz.ParseRole(s); err == nil {
		return r
	}
	return authz.RoleViewer
}
