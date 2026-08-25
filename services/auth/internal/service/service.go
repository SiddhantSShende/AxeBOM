// Package service holds auth's business logic.
//
// Handlers do HTTP; this does decisions. The split matters because the
// interesting rules here — reuse detection, enumeration resistance, tenant
// selection — are worth testing without spinning up a server.
package service

import (
	"context"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/axebom/axebom/libs/go-shared/auth"
	"github.com/axebom/axebom/libs/go-shared/authz"
	"github.com/axebom/axebom/libs/go-shared/platform/errs"
	"github.com/axebom/axebom/services/auth/internal/store"
)

// Service implements the auth flows.
type Service struct {
	store     *store.Store
	issuer    *auth.Issuer
	argon     auth.Argon2Params
	now       func() time.Time
	inviteTTL time.Duration
}

// Config configures the service.
type Config struct {
	Store     *store.Store
	Issuer    *auth.Issuer
	Argon     auth.Argon2Params
	Now       func() time.Time
	InviteTTL time.Duration
}

func New(cfg Config) *Service {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.InviteTTL <= 0 {
		cfg.InviteTTL = 7 * 24 * time.Hour
	}
	if cfg.Argon.Memory == 0 {
		cfg.Argon = auth.DefaultArgon2Params()
	}
	return &Service{
		store: cfg.Store, issuer: cfg.Issuer, argon: cfg.Argon,
		now: cfg.Now, inviteTTL: cfg.InviteTTL,
	}
}

// TokenPair is what a successful authentication returns.
type TokenPair struct {
	AccessToken  string
	RefreshToken string
	ExpiresAt    time.Time
	TenantID     string
	TenantName   string
	Role         authz.Role
	UserID       string
}

// RequestMeta is the non-credential context of a request, for the audit log.
type RequestMeta struct {
	IP        net.IP
	UserAgent string
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

var emailPattern = regexp.MustCompile(`^[^@\s]+@[^@\s]+\.[^@\s]+$`)

// MinPasswordLength follows NIST SP 800-63B: length is what matters, and
// composition rules ("one uppercase, one symbol") measurably reduce entropy by
// pushing users toward predictable substitutions.
const MinPasswordLength = 12

// RegisterParams is the input to Register.
type RegisterParams struct {
	Email      string
	Password   string
	Name       string
	TenantName string
}

// Register creates a user, their tenant, and an owner membership.
//
// First signup creates a tenant; subsequent users join by invitation.
func (s *Service) Register(ctx context.Context, p RegisterParams, meta RequestMeta) (TokenPair, error) {
	email := normalizeEmail(p.Email)
	if !emailPattern.MatchString(email) {
		return TokenPair{}, errs.New(errs.ValidationFieldInvalid, "email address is not valid")
	}
	if len(p.Password) < MinPasswordLength {
		return TokenPair{}, errs.Newf(errs.ValidationFieldInvalid,
			"password must be at least %d characters", MinPasswordLength)
	}
	if strings.TrimSpace(p.TenantName) == "" {
		return TokenPair{}, errs.New(errs.ValidationFieldRequired, "organisation name is required")
	}

	// Registration DOES reveal whether an email is taken — it has to, since the
	// user must be told to log in instead. Login deliberately does not.
	if _, err := s.store.FindUserByEmail(ctx, email); err == nil {
		return TokenPair{}, errs.New(errs.ValidationFieldInvalid,
			"an account already exists for this email address")
	} else if !errors.Is(err, store.ErrNotFound) {
		return TokenPair{}, err
	}

	hash, err := auth.HashPassword(p.Password, s.argon)
	if err != nil {
		return TokenPair{}, err
	}

	user, err := s.store.CreateUser(ctx, store.CreateUserParams{
		Email: email, Name: p.Name, PasswordHash: hash, AuthProvider: "local",
	})
	if err != nil {
		return TokenPair{}, err
	}

	tenantID, err := s.store.CreateTenantWithOwner(ctx,
		strings.TrimSpace(p.TenantName), slugify(p.TenantName), user.ID)
	if err != nil {
		return TokenPair{}, err
	}

	s.audit(ctx, store.AuthEvent{
		TenantID: tenantID, ActorID: user.ID, Action: "auth.register",
		Metadata: map[string]any{"provider": "local"},
		IP:       meta.IP, UserAgent: meta.UserAgent,
	})

	return s.issueFor(ctx, user.ID, tenantID, p.TenantName, authz.RoleOwner, meta)
}

// ---------------------------------------------------------------------------
// Login
// ---------------------------------------------------------------------------

// ErrInvalidCredentials is deliberately the SAME error for "no such user" and
// "wrong password". Distinguishing them turns login into an account
// enumerator, which is the more valuable finding for an attacker.
var ErrInvalidCredentials = errs.New(errs.AuthInvalidCreds, "email or password is incorrect")

// LoginParams is the input to Login.
type LoginParams struct {
	Email    string
	Password string
	// TenantID selects among several memberships. Empty picks the first.
	TenantID string
}

// Login authenticates and issues tokens.
func (s *Service) Login(ctx context.Context, p LoginParams, meta RequestMeta) (TokenPair, error) {
	email := normalizeEmail(p.Email)

	user, err := s.store.FindUserByEmail(ctx, email)
	if errors.Is(err, store.ErrNotFound) {
		// Burn comparable CPU so a missing account does not return
		// measurably faster than a real one with a wrong password.
		auth.DummyVerify(s.argon)
		s.audit(ctx, store.AuthEvent{
			Action:   "auth.login.failed",
			Metadata: map[string]any{"reason": "no_such_user", "email": email},
			IP:       meta.IP, UserAgent: meta.UserAgent,
		})
		return TokenPair{}, ErrInvalidCredentials
	}
	if err != nil {
		return TokenPair{}, err
	}

	if user.PasswordHash == "" {
		// An SSO-only account. Same generic error: saying "use GitHub" would
		// confirm the address is registered.
		auth.DummyVerify(s.argon)
		return TokenPair{}, ErrInvalidCredentials
	}
	if err := auth.VerifyPassword(p.Password, user.PasswordHash); err != nil {
		s.audit(ctx, store.AuthEvent{
			ActorID: user.ID, Action: "auth.login.failed",
			Metadata: map[string]any{"reason": "bad_password"},
			IP:       meta.IP, UserAgent: meta.UserAgent,
		})
		return TokenPair{}, ErrInvalidCredentials
	}

	if user.Status != "active" {
		return TokenPair{}, errs.Newf(errs.AuthInvalidCreds, "account is %s", user.Status)
	}

	// Raising argon2 parameters must not lock anyone out: old hashes still
	// verify and are upgraded here, the only moment the plaintext exists.
	if auth.NeedsRehash(user.PasswordHash, s.argon) {
		if h, err := auth.HashPassword(p.Password, s.argon); err == nil {
			_ = s.store.UpdatePasswordHash(ctx, user.ID, h)
		}
	}

	membership, err := s.selectMembership(ctx, user.ID, p.TenantID)
	if err != nil {
		return TokenPair{}, err
	}

	_ = s.store.TouchLastLogin(ctx, user.ID)
	s.audit(ctx, store.AuthEvent{
		TenantID: membership.TenantID, ActorID: user.ID, Action: "auth.login",
		Metadata: map[string]any{"provider": "local"},
		IP:       meta.IP, UserAgent: meta.UserAgent,
	})

	return s.issueFor(ctx, user.ID, membership.TenantID, membership.TenantName, membership.Role, meta)
}

// selectMembership resolves which tenant this session is for.
func (s *Service) selectMembership(ctx context.Context, userID, wantTenant string) (store.Membership, error) {
	memberships, err := s.store.MembershipsForUser(ctx, userID)
	if err != nil {
		return store.Membership{}, err
	}
	if len(memberships) == 0 {
		return store.Membership{}, errs.New(errs.AuthInvalidCreds,
			"this account is not a member of any organisation")
	}

	if wantTenant == "" {
		return memberships[0], nil
	}
	for _, m := range memberships {
		if m.TenantID == wantTenant {
			return m, nil
		}
	}
	// 404-shaped, not 403: confirming the tenant exists would leak it.
	return store.Membership{}, errs.New(errs.NotFoundResource, "no such organisation")
}

// ---------------------------------------------------------------------------
// Refresh — where token theft is detected
// ---------------------------------------------------------------------------

// Refresh rotates a refresh token.
//
// ⚠ REUSE DETECTION IS THE POINT OF THIS FUNCTION.
//
// Tokens rotate: each refresh revokes the presented token and issues a
// successor. So presenting an ALREADY-REVOKED token means two parties hold
// what should have been consumed once — the legitimate client and a thief.
//
// We cannot tell which is which, so the entire family is revoked and both must
// log in again. Forcing a re-login is a far better outcome than leaving an
// attacker holding a valid session.
func (s *Service) Refresh(ctx context.Context, refreshToken string, meta RequestMeta) (TokenPair, error) {
	hash := auth.HashRefreshToken(refreshToken)

	sess, err := s.store.SessionByRefreshHash(ctx, hash)
	if errors.Is(err, store.ErrNotFound) {
		return TokenPair{}, errs.New(errs.AuthTokenInvalid, "refresh token is not valid")
	}
	if err != nil {
		return TokenPair{}, err
	}

	if sess.Revoked() {
		n, revokeErr := s.store.RevokeSessionFamily(ctx, sess.FamilyID)
		s.audit(ctx, store.AuthEvent{
			TenantID: sess.TenantID, ActorID: sess.UserID,
			Action: "auth.refresh.reuse_detected",
			Metadata: map[string]any{
				"family_id":        sess.FamilyID,
				"sessions_revoked": n,
				"revoke_error":     errString(revokeErr),
				"note":             "an already-rotated refresh token was presented; the family was revoked",
			},
			IP: meta.IP, UserAgent: meta.UserAgent,
		})
		return TokenPair{}, errs.New(errs.AuthRefreshReused,
			"this refresh token has already been used. For your security every "+
				"session in this chain has been signed out; please log in again")
	}

	if !sess.ExpiresAt.After(s.now()) {
		return TokenPair{}, errs.New(errs.AuthTokenExpired, "refresh token has expired")
	}

	next, err := s.issuer.RotateRefreshToken(s.now(), sess.FamilyID)
	if err != nil {
		return TokenPair{}, err
	}
	newSessionID, err := s.store.RotateSession(ctx, sess, next.Hash, next.ExpiresAt)
	if err != nil {
		return TokenPair{}, err
	}

	access, claims, err := s.issuer.IssueAccess(s.now(), sess.UserID, sess.TenantID, newSessionID, sess.Role)
	if err != nil {
		return TokenPair{}, err
	}

	return TokenPair{
		AccessToken:  access,
		RefreshToken: next.Plaintext,
		ExpiresAt:    time.Unix(claims.Expires, 0).UTC(),
		TenantID:     sess.TenantID,
		Role:         sess.Role,
		UserID:       sess.UserID,
	}, nil
}

// Logout revokes one session.
func (s *Service) Logout(ctx context.Context, tenantID, sessionID, userID string, meta RequestMeta) error {
	if err := s.store.RevokeSession(ctx, tenantID, sessionID); err != nil {
		return err
	}
	s.audit(ctx, store.AuthEvent{
		TenantID: tenantID, ActorID: userID, Action: "auth.logout",
		IP: meta.IP, UserAgent: meta.UserAgent,
	})
	return nil
}

// ---------------------------------------------------------------------------
// Invitations
// ---------------------------------------------------------------------------

// InviteResult carries the one-time token to email to the invitee.
type InviteResult struct {
	InvitationID string
	Token        string // shown once, never stored
	ExpiresAt    time.Time
}

// CreateInvite issues an invitation to join a tenant.
func (s *Service) CreateInvite(ctx context.Context, tenantID, email string,
	role authz.Role, invitedBy string, meta RequestMeta,
) (InviteResult, error) {
	email = normalizeEmail(email)
	if !emailPattern.MatchString(email) {
		return InviteResult{}, errs.New(errs.ValidationFieldInvalid, "email address is not valid")
	}
	if !role.Valid() {
		return InviteResult{}, errs.New(errs.ValidationFieldInvalid, "unknown role")
	}

	token, err := auth.NewOAuthState() // 256 bits of CSPRNG; same generator
	if err != nil {
		return InviteResult{}, err
	}
	expires := s.now().Add(s.inviteTTL)

	id, err := s.store.CreateInvitation(ctx, tenantID, email, role,
		auth.HashRefreshToken(token), invitedBy, expires)
	if err != nil {
		return InviteResult{}, err
	}

	s.audit(ctx, store.AuthEvent{
		TenantID: tenantID, ActorID: invitedBy, Action: "auth.invite.created",
		// The email is recorded; the TOKEN never is.
		Metadata: map[string]any{"email": email, "role": string(role)},
		IP:       meta.IP, UserAgent: meta.UserAgent,
	})

	return InviteResult{InvitationID: id, Token: token, ExpiresAt: expires}, nil
}

// AcceptInviteParams is the input to AcceptInvite.
type AcceptInviteParams struct {
	Token string
	// Password is required only when the invitee has no account yet.
	Password string
	Name     string
}

// AcceptInvite joins a user to a tenant.
func (s *Service) AcceptInvite(ctx context.Context, p AcceptInviteParams, meta RequestMeta) (TokenPair, error) {
	hash := auth.HashRefreshToken(p.Token)

	inv, err := s.store.InvitationByTokenHash(ctx, hash)
	if errors.Is(err, store.ErrNotFound) {
		return TokenPair{}, errs.New(errs.NotFoundResource, "invitation not found")
	}
	if err != nil {
		return TokenPair{}, err
	}
	if err := inv.Usable(s.now()); err != nil {
		return TokenPair{}, errs.New(errs.ValidationFieldInvalid, err.Error())
	}

	user, err := s.store.FindUserByEmail(ctx, inv.Email)
	switch {
	case errors.Is(err, store.ErrNotFound):
		if len(p.Password) < MinPasswordLength {
			return TokenPair{}, errs.Newf(errs.ValidationFieldInvalid,
				"password must be at least %d characters", MinPasswordLength)
		}
		pwHash, hErr := auth.HashPassword(p.Password, s.argon)
		if hErr != nil {
			return TokenPair{}, hErr
		}
		user, err = s.store.CreateUser(ctx, store.CreateUserParams{
			Email: inv.Email, Name: p.Name, PasswordHash: pwHash, AuthProvider: "local",
		})
		if err != nil {
			return TokenPair{}, err
		}
	case err != nil:
		return TokenPair{}, err
	}

	if _, err := s.store.AcceptInvitation(ctx, hash, user.ID); err != nil {
		return TokenPair{}, errs.Wrap(err, errs.ValidationFieldInvalid,
			"invitation could not be accepted")
	}

	s.audit(ctx, store.AuthEvent{
		TenantID: inv.TenantID, ActorID: user.ID, Action: "auth.invite.accepted",
		Metadata: map[string]any{"role": string(inv.Role)},
		IP:       meta.IP, UserAgent: meta.UserAgent,
	})

	return s.issueFor(ctx, user.ID, inv.TenantID, inv.TenantName, inv.Role, meta)
}

// ---------------------------------------------------------------------------
// Shared
// ---------------------------------------------------------------------------

// issueFor mints a session and its token pair.
func (s *Service) issueFor(ctx context.Context, userID, tenantID, tenantName string,
	role authz.Role, meta RequestMeta,
) (TokenPair, error) {
	refresh, err := s.issuer.NewRefreshToken(s.now())
	if err != nil {
		return TokenPair{}, err
	}

	sessionID, err := s.store.CreateSession(ctx, tenantID, userID,
		refresh.Hash, refresh.FamilyID, refresh.ExpiresAt, meta.UserAgent, meta.IP)
	if err != nil {
		return TokenPair{}, err
	}

	access, claims, err := s.issuer.IssueAccess(s.now(), userID, tenantID, sessionID, role)
	if err != nil {
		return TokenPair{}, err
	}

	return TokenPair{
		AccessToken:  access,
		RefreshToken: refresh.Plaintext,
		ExpiresAt:    time.Unix(claims.Expires, 0).UTC(),
		TenantID:     tenantID,
		TenantName:   tenantName,
		Role:         role,
		UserID:       userID,
	}, nil
}

// audit records an event. A failure here must not fail the request the user
// asked for, but it must be visible — so it is logged rather than swallowed.
func (s *Service) audit(ctx context.Context, e store.AuthEvent) {
	if err := s.store.RecordAuthEvent(ctx, e); err != nil {
		// The audit log is compliance evidence (CERT-In §5.3.6); a write
		// failure is a real problem even when the request itself succeeds.
		fmt.Printf("audit write failed: action=%s err=%v\n", e.Action, err)
	}
}

func normalizeEmail(s string) string { return strings.ToLower(strings.TrimSpace(s)) }

var nonSlug = regexp.MustCompile(`[^a-z0-9]+`)

func slugify(s string) string {
	out := nonSlug.ReplaceAllString(strings.ToLower(strings.TrimSpace(s)), "-")
	out = strings.Trim(out, "-")
	if out == "" {
		out = "org"
	}
	if len(out) > 48 {
		out = out[:48]
	}
	return out
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
