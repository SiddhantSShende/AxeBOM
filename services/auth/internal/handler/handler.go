// Package handler is auth's HTTP surface.
//
// Handlers translate; they do not decide. Every rule that matters lives in
// internal/service, so it can be tested without a server and cannot be
// bypassed by adding a second route.
package handler

import (
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/axebom/axebom/libs/go-shared/auth"
	"github.com/axebom/axebom/libs/go-shared/authz"
	"github.com/axebom/axebom/libs/go-shared/platform/ctxkey"
	"github.com/axebom/axebom/libs/go-shared/platform/errs"
	"github.com/axebom/axebom/services/auth/internal/service"
)

// Handler serves the auth endpoints.
type Handler struct {
	svc    *service.Service
	github *service.GitHubClient
	cfg    Config
}

// Config configures cookie behaviour and redirects.
type Config struct {
	// AllowInsecureCookies drops the Secure attribute.
	//
	// Phrased as an opt-OUT on purpose: the zero value is the safe one. With a
	// `SecureCookies bool` instead, any caller that forgot the field would
	// silently ship refresh tokens over plain http — the failure would be
	// invisible in development, where it works, and catastrophic in
	// production, where it does not.
	//
	// Set it ONLY for local plain-http development, where a Secure cookie is
	// never sent and login therefore cannot work at all.
	AllowInsecureCookies bool

	// FrontendURL is where the OAuth callback lands the browser.
	FrontendURL string
	RefreshTTL  time.Duration

	// GitHubRedirectURL and GitHubConnectRedirectURL are the two callback URLs
	// registered on the same GitHub OAuth App — sign-in and the repo-scoped
	// "connect" flow (see service.GitHubClient.AuthorizeEndpoint) must send
	// GitHub the exact redirect_uri they will call back to, and the two flows
	// use different ones.
	GitHubRedirectURL        string
	GitHubConnectRedirectURL string
}

func New(svc *service.Service, gh *service.GitHubClient, cfg Config) *Handler {
	if cfg.RefreshTTL <= 0 {
		cfg.RefreshTTL = 30 * 24 * time.Hour
	}
	return &Handler{svc: svc, github: gh, cfg: cfg}
}

// secure reports whether cookies carry the Secure attribute.
func (h *Handler) secure() bool { return !h.cfg.AllowInsecureCookies }

// Cookie names.
//
// The refresh token is delivered as an HttpOnly cookie, NOT in the JSON body:
// a body value has to be stored by the SPA somewhere JavaScript can read, and
// therefore somewhere an XSS can steal it. The ACCESS token does go in the
// body — it is short-lived and the SPA keeps it in memory only.
const (
	refreshCookie = "axebom_refresh"
	stateCookie   = "axebom_oauth_state"

	// refreshPath scopes the cookie so it is not attached to every API call.
	// A credential should travel only to the endpoint that consumes it.
	refreshPath = "/v1/auth"
)

// ---------------------------------------------------------------------------
// Request and response bodies
// ---------------------------------------------------------------------------

type registerRequest struct {
	Email      string `json:"email"`
	Password   string `json:"password"`
	Name       string `json:"name"`
	TenantName string `json:"tenant_name"`
}

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	TenantID string `json:"tenant_id,omitempty"`
}

type acceptInviteRequest struct {
	Token    string `json:"token"`
	Password string `json:"password,omitempty"`
	Name     string `json:"name,omitempty"`
}

type inviteRequest struct {
	Email string `json:"email"`
	Role  string `json:"role"`
}

// sessionResponse is what a successful authentication returns.
//
// It carries NO refresh token — that is the cookie's job.
type sessionResponse struct {
	AccessToken string    `json:"access_token"`
	TokenType   string    `json:"token_type"`
	ExpiresAt   time.Time `json:"expires_at"`
	Tenant      tenantDTO `json:"tenant"`
	UserID      string    `json:"user_id"`
	Role        string    `json:"role"`
}

type tenantDTO struct {
	ID   string `json:"id"`
	Name string `json:"name,omitempty"`
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

// Register handles POST /v1/auth/register.
func (h *Handler) Register(w http.ResponseWriter, r *http.Request) {
	var req registerRequest
	if err := decode(r, &req); err != nil {
		errs.Write(w, r, err)
		return
	}

	pair, err := h.svc.Register(r.Context(), service.RegisterParams{
		Email: req.Email, Password: req.Password,
		Name: req.Name, TenantName: req.TenantName,
	}, metaOf(r))
	if err != nil {
		errs.Write(w, r, err)
		return
	}
	h.writeSession(w, r, pair, http.StatusCreated)
}

// Login handles POST /v1/auth/login.
func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if err := decode(r, &req); err != nil {
		errs.Write(w, r, err)
		return
	}

	pair, err := h.svc.Login(r.Context(), service.LoginParams{
		Email: req.Email, Password: req.Password, TenantID: req.TenantID,
	}, metaOf(r))
	if err != nil {
		errs.Write(w, r, err)
		return
	}
	h.writeSession(w, r, pair, http.StatusOK)
}

// Refresh handles POST /v1/auth/refresh.
//
// The token comes from the cookie. A body field is accepted only as a fallback
// for non-browser clients.
func (h *Handler) Refresh(w http.ResponseWriter, r *http.Request) {
	token := ""
	if c, err := r.Cookie(refreshCookie); err == nil {
		token = c.Value
	}
	if token == "" {
		var body struct {
			RefreshToken string `json:"refresh_token"`
		}
		_ = decode(r, &body)
		token = body.RefreshToken
	}
	if token == "" {
		errs.Write(w, r, errs.New(errs.AuthTokenInvalid, "no refresh token supplied"))
		return
	}

	pair, err := h.svc.Refresh(r.Context(), token, metaOf(r))
	if err != nil {
		// On reuse the family is gone, so the stale cookie is worthless and
		// must not linger — otherwise the browser retries with it forever.
		if errs.Is(err, errs.AuthRefreshReused) || errs.Is(err, errs.AuthTokenInvalid) {
			h.clearRefreshCookie(w)
		}
		errs.Write(w, r, err)
		return
	}
	h.writeSession(w, r, pair, http.StatusOK)
}

// Logout handles POST /v1/auth/logout. Requires authentication.
func (h *Handler) Logout(w http.ResponseWriter, r *http.Request) {
	tenantID, err := auth.RequireTenant(r.Context())
	if err != nil {
		errs.Write(w, r, err)
		return
	}
	sessionID := ctxkey.SessionID(r.Context())
	if sessionID == "" {
		errs.Write(w, r, errs.New(errs.AuthTokenInvalid, "token carries no session"))
		return
	}

	if err := h.svc.Logout(r.Context(), tenantID, sessionID,
		ctxkey.UserID(r.Context()), metaOf(r)); err != nil {
		errs.Write(w, r, err)
		return
	}

	h.clearRefreshCookie(w)
	w.WriteHeader(http.StatusNoContent)
}

// Me handles GET /v1/auth/me.
//
// Everything it returns comes from the VERIFIED token, never from the request,
// so it doubles as the client's check that its token still means what it thinks.
func (h *Handler) Me(w http.ResponseWriter, r *http.Request) {
	tenantID, err := auth.RequireTenant(r.Context())
	if err != nil {
		errs.Write(w, r, err)
		return
	}
	errs.WriteJSON(w, http.StatusOK, map[string]any{
		"user_id":   ctxkey.UserID(r.Context()),
		"tenant_id": tenantID,
		"role":      ctxkey.Role(r.Context()),
	})
}

// ---------------------------------------------------------------------------
// GitHub OAuth
// ---------------------------------------------------------------------------

// GitHubAuthorize handles GET /v1/auth/github/authorize.
func (h *Handler) GitHubAuthorize(w http.ResponseWriter, r *http.Request) {
	redirect, state, err := h.svc.BeginGitHubLogin(h.github, h.cfg.GitHubRedirectURL)
	if err != nil {
		errs.Write(w, r, err)
		return
	}

	// The state is kept in an HttpOnly cookie rather than server-side session
	// storage: it is single-use CSRF material, so a stateless carrier is
	// enough and there is nothing to expire out of a table.
	//nolint:gosec // G124: Secure/HttpOnly/SameSite are set below from h.secure(),
	// which gosec cannot evaluate. TestRefreshCookieIsSafeByDefault asserts the
	// resulting attributes on a real response.
	http.SetCookie(w, &http.Cookie{
		Name:     stateCookie,
		Value:    state,
		Path:     "/v1/auth/github",
		HttpOnly: true,
		Secure:   h.secure(),
		// Lax, NOT Strict. The callback arrives as a cross-site redirect from
		// github.com; Strict would withhold the cookie and every sign-in would
		// fail the state check. Lax still blocks the cross-site POST that the
		// CSRF defence is actually about.
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int((10 * time.Minute).Seconds()),
	})

	http.Redirect(w, r, redirect, http.StatusFound)
}

// GitHubCallback handles GET /v1/auth/github/callback.
func (h *Handler) GitHubCallback(w http.ResponseWriter, r *http.Request) {
	want := ""
	if c, err := r.Cookie(stateCookie); err == nil {
		want = c.Value
	}
	// Consume it either way: a state that survives one attempt is replayable.
	h.clearCookie(w, stateCookie, "/v1/auth/github")

	if want == "" {
		errs.Write(w, r, errs.New(errs.AuthStateMismatch,
			"sign-in state is missing or expired; please start again"))
		return
	}

	pair, err := h.svc.CompleteGitHubLogin(r.Context(), h.github,
		r.URL.Query().Get("code"), r.URL.Query().Get("state"), want,
		h.cfg.GitHubRedirectURL, metaOf(r))
	if err != nil {
		errs.Write(w, r, err)
		return
	}

	h.setRefreshCookie(w, pair.RefreshToken)

	if h.cfg.FrontendURL != "" {
		// The access token goes in the FRAGMENT, not the query string. A
		// fragment is never sent to the server and never lands in access logs,
		// proxy logs or Referer headers.
		http.Redirect(w, r,
			h.cfg.FrontendURL+"/auth/callback#access_token="+pair.AccessToken,
			http.StatusFound)
		return
	}
	h.writeSession(w, r, pair, http.StatusOK)
}

// ---------------------------------------------------------------------------
// Invitations
// ---------------------------------------------------------------------------

// CreateInvite handles POST /v1/auth/invitations. Requires authentication.
func (h *Handler) CreateInvite(w http.ResponseWriter, r *http.Request) {
	tenantID, err := auth.RequireTenant(r.Context())
	if err != nil {
		errs.Write(w, r, err)
		return
	}

	var req inviteRequest
	if err := decode(r, &req); err != nil {
		errs.Write(w, r, err)
		return
	}
	role, err := authz.ParseRole(req.Role)
	if err != nil {
		errs.Write(w, r, errs.New(errs.ValidationFieldInvalid, "unknown role"))
		return
	}

	// Nobody may invite above their own level. Without this an Admin could
	// mint an Owner and escalate through a second account.
	actor, err := authz.ParseRole(ctxkey.Role(r.Context()))
	if err != nil || !authz.RoleAtLeast(actor, role) {
		errs.Write(w, r, errs.New(errs.PermRoleInsufficient,
			"you cannot invite somebody to a role above your own"))
		return
	}

	res, err := h.svc.CreateInvite(r.Context(), tenantID, req.Email, role,
		ctxkey.UserID(r.Context()), metaOf(r))
	if err != nil {
		errs.Write(w, r, err)
		return
	}

	errs.WriteJSON(w, http.StatusCreated, map[string]any{
		"invitation_id": res.InvitationID,
		// Returned ONCE. Only its hash is stored, so it cannot be shown again.
		"token":      res.Token,
		"expires_at": res.ExpiresAt,
	})
}

// AcceptInvite handles POST /v1/auth/invitations/accept. Unauthenticated: the
// invitee has no account yet.
func (h *Handler) AcceptInvite(w http.ResponseWriter, r *http.Request) {
	var req acceptInviteRequest
	if err := decode(r, &req); err != nil {
		errs.Write(w, r, err)
		return
	}

	pair, err := h.svc.AcceptInvite(r.Context(), service.AcceptInviteParams{
		Token: req.Token, Password: req.Password, Name: req.Name,
	}, metaOf(r))
	if err != nil {
		errs.Write(w, r, err)
		return
	}
	h.writeSession(w, r, pair, http.StatusOK)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// maxBodyBytes caps request bodies. Without it a client can stream forever and
// exhaust memory before any validation runs.
const maxBodyBytes = 1 << 20 // 1 MiB

func decode(r *http.Request, into any) error {
	dec := json.NewDecoder(io.LimitReader(r.Body, maxBodyBytes))
	// Reject unknown fields: a typo'd `tenant_name` silently becoming empty is
	// worse than an error saying so.
	dec.DisallowUnknownFields()

	if err := dec.Decode(into); err != nil {
		if errors.Is(err, io.EOF) {
			return errs.New(errs.ValidationBodyMalformed, "request body is empty")
		}
		return errs.Wrap(err, errs.ValidationBodyMalformed, "request body is not valid JSON")
	}
	return nil
}

func (h *Handler) writeSession(w http.ResponseWriter, _ *http.Request,
	pair service.TokenPair, status int,
) {
	h.setRefreshCookie(w, pair.RefreshToken)
	errs.WriteJSON(w, status, sessionResponse{
		AccessToken: pair.AccessToken,
		TokenType:   "Bearer",
		ExpiresAt:   pair.ExpiresAt,
		Tenant:      tenantDTO{ID: pair.TenantID, Name: pair.TenantName},
		UserID:      pair.UserID,
		Role:        string(pair.Role),
	})
}

func (h *Handler) setRefreshCookie(w http.ResponseWriter, token string) {
	//nolint:gosec // G124: Secure/HttpOnly/SameSite are set below from h.secure(),
	// which gosec cannot evaluate. TestRefreshCookieIsSafeByDefault asserts the
	// resulting attributes on a real response.
	http.SetCookie(w, &http.Cookie{
		Name:     refreshCookie,
		Value:    token,
		Path:     refreshPath,
		HttpOnly: true, // unreadable from JavaScript, so XSS cannot exfiltrate it
		Secure:   h.secure(),
		SameSite: http.SameSiteStrictMode, // never sent on a cross-site request
		MaxAge:   int(h.cfg.RefreshTTL.Seconds()),
	})
}

func (h *Handler) clearRefreshCookie(w http.ResponseWriter) {
	h.clearCookie(w, refreshCookie, refreshPath)
}

func (h *Handler) clearCookie(w http.ResponseWriter, name, path string) {
	//nolint:gosec // G124: Secure/HttpOnly/SameSite are set below from h.secure(),
	// which gosec cannot evaluate. TestRefreshCookieIsSafeByDefault asserts the
	// resulting attributes on a real response.
	http.SetCookie(w, &http.Cookie{
		Name: name, Value: "", Path: path,
		HttpOnly: true, Secure: h.secure(),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
}

// metaOf extracts the audit context of a request.
func metaOf(r *http.Request) service.RequestMeta {
	return service.RequestMeta{IP: clientIP(r), UserAgent: r.UserAgent()}
}

// clientIP resolves the caller's address.
//
// X-Forwarded-For is used ONLY because this service always sits behind our own
// gateway, which overwrites the header. Trusting it on a directly-exposed
// service would let any client forge its own audit-log address.
func clientIP(r *http.Request) net.IP {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// Left-most entry is the original client.
		if ip := net.ParseIP(strings.TrimSpace(strings.Split(xff, ",")[0])); ip != nil {
			return ip
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	return net.ParseIP(host)
}
