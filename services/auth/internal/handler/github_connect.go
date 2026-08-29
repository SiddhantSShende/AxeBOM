package handler

import (
	"net/http"
	"time"

	"github.com/axebom/axebom/libs/go-shared/platform/errs"
)

// GitHub "connect" — a repo-scoped OAuth flow distinct from account sign-in.
//
// ⚠ THIS NEVER TOUCHES AN AXEBOM SESSION.
//
// GitHubAuthorize/GitHubCallback (handler.go) resolve or create an AxeBOM
// user and set a refresh cookie — that is a LOGIN. The project wizard's
// "Connect GitHub" button needs something else: a repo-scoped GitHub token to
// hand to the repo picker (GET /v1/github/repos) and, from an already
// authenticated request, to POST /v1/projects/{id}/connections. Reusing the
// login flow's machinery (same GitHubClient, same state-cookie CSRF pattern,
// same fragment-delivery trick) is safe precisely because this handler stops
// short of everything CompleteGitHubLogin does after the token exchange: no
// resolveGitHubUser, no issueFor, no cookie naming an AxeBOM identity —
// service.CompleteGitHubConnect hands back the token and nothing else.

// connectStateCookie is DISTINCT from stateCookie (handler.go) and scoped to
// a different path, so the two flows' in-flight state can never collide if a
// user somehow has both a login and a connect attempt in progress at once.
const (
	connectStateCookie = "axebom_oauth_connect_state"
	connectStatePath   = "/v1/auth/github/connect"
)

// GitHubConnectAuthorize handles GET /v1/auth/github/connect/authorize.
func (h *Handler) GitHubConnectAuthorize(w http.ResponseWriter, r *http.Request) {
	redirect, state, err := h.svc.BeginGitHubConnect(h.github, h.cfg.GitHubConnectRedirectURL)
	if err != nil {
		errs.Write(w, r, err)
		return
	}

	//nolint:gosec // G124: Secure/HttpOnly/SameSite are set below from h.secure(),
	// which gosec cannot evaluate — same justification as GitHubAuthorize's
	// identical cookie in handler.go.
	http.SetCookie(w, &http.Cookie{
		Name:     connectStateCookie,
		Value:    state,
		Path:     connectStatePath,
		HttpOnly: true,
		Secure:   h.secure(),
		// Lax, not Strict, for the same reason as the login flow's state
		// cookie: the callback arrives as a cross-site redirect from github.com.
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int((10 * time.Minute).Seconds()),
	})

	http.Redirect(w, r, redirect, http.StatusFound)
}

// GitHubConnectCallback handles GET /v1/auth/github/connect/callback.
func (h *Handler) GitHubConnectCallback(w http.ResponseWriter, r *http.Request) {
	want := ""
	if c, err := r.Cookie(connectStateCookie); err == nil {
		want = c.Value
	}
	// Consumed either way: a state that survives one attempt is replayable.
	h.clearCookie(w, connectStateCookie, connectStatePath)

	if want == "" {
		errs.Write(w, r, errs.New(errs.AuthStateMismatch,
			"connect state is missing or expired; please try again"))
		return
	}

	token, err := h.svc.CompleteGitHubConnect(r.Context(), h.github,
		r.URL.Query().Get("code"), r.URL.Query().Get("state"), want,
		h.cfg.GitHubConnectRedirectURL)
	if err != nil {
		errs.Write(w, r, err)
		return
	}

	if h.cfg.FrontendURL != "" {
		// The token travels in the URL FRAGMENT, never a query param — a
		// fragment is never sent to the server, never logged, never in a
		// Referer header. Lands on a small relay route that exists only to
		// forward it to the tab that opened this popup and close itself; see
		// frontend/src/routes/projects/GitHubConnectCallback.tsx.
		//
		//nolint:gosec // G710: gosec's taint analysis flags this because `token`
		// traces back to query-string input, but the redirect's ORIGIN is always
		// the fixed h.cfg.FrontendURL from server config — never attacker input.
		// Only the fragment payload varies, and putting the token there (not a
		// query param) is itself the leak mitigation; see the comment above.
		http.Redirect(w, r,
			h.cfg.FrontendURL+"/projects/github-connect#access_token="+token,
			http.StatusFound)
		return
	}
	errs.WriteJSON(w, http.StatusOK, map[string]string{"access_token": token})
}
