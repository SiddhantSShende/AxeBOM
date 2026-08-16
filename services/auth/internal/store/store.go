// Package store is auth's persistence layer.
//
// It has two distinct kinds of query, and keeping them apart is the point:
//
//	TENANT-SCOPED   go through db.WithTenant, so Postgres RLS filters them.
//	                This is everything after login.
//
//	PRE-TENANT      go through the SECURITY DEFINER functions added in
//	                migrations/auth/0002_login_lookup.sql. Login, refresh and
//	                invite-acceptance all need to DISCOVER a tenant, so they
//	                cannot have one as a precondition.
//
// Every pre-tenant call is narrow by construction — one user id, one token
// hash — because a wide one would be a way to read across tenants.
package store

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/encorebom/encorebom/libs/go-shared/authz"
	"github.com/encorebom/encorebom/libs/go-shared/platform/db"
)

// Store wraps the connection pool.
type Store struct{ pool *db.Pool }

func New(pool *db.Pool) *Store { return &Store{pool: pool} }

// ErrNotFound is returned when a lookup finds nothing.
//
// Callers must NOT distinguish it from a wrong password when answering a login
// request: doing so turns the endpoint into an account enumerator.
var ErrNotFound = errors.New("not found")

// ---------------------------------------------------------------------------
// Users — GLOBAL, not tenant-scoped
// ---------------------------------------------------------------------------

// User mirrors auth.users.
type User struct {
	ID           string
	Email        string
	Name         string
	PasswordHash string
	GitHubLogin  string
	GitHubUserID int64
	AuthProvider string
	Status       string
	LastLoginAt  *time.Time
}

// FindUserByEmail looks up a user by email.
//
// auth.users is global (one identity may belong to several tenants), so this
// is one of the few legitimate unscoped reads. See the exemption registry in
// libs/go-shared/platform/db/rls.go.
func (s *Store) FindUserByEmail(ctx context.Context, email string) (User, error) {
	var u User
	var ghLogin, ghID any
	err := s.pool.Raw().QueryRow(ctx, `
		SELECT id, email, COALESCE(name,''), COALESCE(password_hash,''),
		       github_login, github_user_id, auth_provider, status, last_login_at
		  FROM auth.users
		 WHERE email = $1 AND deleted_at IS NULL`, email).
		Scan(&u.ID, &u.Email, &u.Name, &u.PasswordHash,
			&ghLogin, &ghID, &u.AuthProvider, &u.Status, &u.LastLoginAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return User{}, ErrNotFound
	}
	if err != nil {
		return User{}, fmt.Errorf("find user by email: %w", err)
	}
	u.GitHubLogin, _ = ghLogin.(string)
	if v, ok := ghID.(int64); ok {
		u.GitHubUserID = v
	}
	return u, nil
}

// FindUserByGitHubID looks up by the NUMERIC GitHub id.
//
// Never by login. GitHub logins are renameable and, once released, claimable
// by someone else — keying on the login would let an attacker who claims a
// freed username inherit the account.
func (s *Store) FindUserByGitHubID(ctx context.Context, githubID int64) (User, error) {
	var u User
	var ghLogin any
	err := s.pool.Raw().QueryRow(ctx, `
		SELECT id, email, COALESCE(name,''), COALESCE(password_hash,''),
		       github_login, github_user_id, auth_provider, status, last_login_at
		  FROM auth.users
		 WHERE github_user_id = $1 AND deleted_at IS NULL`, githubID).
		Scan(&u.ID, &u.Email, &u.Name, &u.PasswordHash,
			&ghLogin, &u.GitHubUserID, &u.AuthProvider, &u.Status, &u.LastLoginAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return User{}, ErrNotFound
	}
	if err != nil {
		return User{}, fmt.Errorf("find user by github id: %w", err)
	}
	u.GitHubLogin, _ = ghLogin.(string)
	return u, nil
}

// CreateUserParams is the input to CreateUser.
type CreateUserParams struct {
	Email        string
	Name         string
	PasswordHash string // empty for SSO-only users
	GitHubLogin  string
	GitHubUserID int64
	AuthProvider string
}

// CreateUser inserts a global user.
func (s *Store) CreateUser(ctx context.Context, p CreateUserParams) (User, error) {
	var (
		pw any = p.PasswordHash
		gl any = p.GitHubLogin
		gi any = p.GitHubUserID
	)
	if p.PasswordHash == "" {
		pw = nil
	}
	if p.GitHubLogin == "" {
		gl = nil
	}
	if p.GitHubUserID == 0 {
		gi = nil
	}

	var u User
	err := s.pool.Raw().QueryRow(ctx, `
		INSERT INTO auth.users (email, name, password_hash, github_login,
		                        github_user_id, auth_provider, status)
		VALUES ($1, $2, $3, $4, $5, $6, 'active')
		RETURNING id, email, COALESCE(name,''), auth_provider, status`,
		p.Email, p.Name, pw, gl, gi, p.AuthProvider).
		Scan(&u.ID, &u.Email, &u.Name, &u.AuthProvider, &u.Status)
	if err != nil {
		return User{}, fmt.Errorf("create user: %w", err)
	}
	return u, nil
}

// TouchLastLogin records a successful sign-in.
func (s *Store) TouchLastLogin(ctx context.Context, userID string) error {
	_, err := s.pool.Raw().Exec(ctx,
		`UPDATE auth.users SET last_login_at = now() WHERE id = $1`, userID)
	return err
}

// UpdateGitHubLogin records a renamed GitHub login.
//
// Display only. The numeric github_user_id is what identifies the account, and
// it does not change on rename.
func (s *Store) UpdateGitHubLogin(ctx context.Context, userID, login string) error {
	_, err := s.pool.Raw().Exec(ctx,
		`UPDATE auth.users SET github_login = $2 WHERE id = $1`, userID, login)
	return err
}

// LinkGitHubIdentity attaches a GitHub identity to an existing local account.
//
// Callers must only reach here with an email GitHub reported as VERIFIED —
// otherwise this is an account-takeover primitive: claim any address on GitHub,
// sign in, inherit the matching EncoreBOM account.
//
// The WHERE clause refuses to overwrite a DIFFERENT existing link, so a second
// GitHub account cannot silently steal an already-linked user.
func (s *Store) LinkGitHubIdentity(ctx context.Context, userID string, githubID int64, login string) error {
	tag, err := s.pool.Raw().Exec(ctx, `
		UPDATE auth.users
		   SET github_user_id = $2,
		       github_login   = $3,
		       auth_provider  = CASE WHEN password_hash IS NULL THEN 'github' ELSE auth_provider END
		 WHERE id = $1
		   AND (github_user_id IS NULL OR github_user_id = $2)`, userID, githubID, login)
	if err != nil {
		return fmt.Errorf("link github identity: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return errors.New("this account is already linked to a different GitHub identity")
	}
	return nil
}

// UpdatePasswordHash rewrites a hash, used when argon2 parameters are raised.
func (s *Store) UpdatePasswordHash(ctx context.Context, userID, hash string) error {
	_, err := s.pool.Raw().Exec(ctx,
		`UPDATE auth.users SET password_hash = $2 WHERE id = $1`, userID, hash)
	return err
}

// ---------------------------------------------------------------------------
// Tenants and memberships
// ---------------------------------------------------------------------------

// Membership is a user's role in one tenant.
type Membership struct {
	TenantID   string
	TenantName string
	TenantSlug string
	Role       authz.Role
	AcceptedAt *time.Time
}

// MembershipsForUser is the PRE-TENANT lookup.
//
// Uses the SECURITY DEFINER function because login must discover which tenants
// a user belongs to before app.current_tenant_id can be set. A plain query
// would fail closed — correctly, but unhelpfully.
func (s *Store) MembershipsForUser(ctx context.Context, userID string) ([]Membership, error) {
	rows, err := s.pool.Raw().Query(ctx,
		`SELECT tenant_id, tenant_name, tenant_slug, role, accepted_at
		   FROM auth.memberships_for_user($1)`, userID)
	if err != nil {
		return nil, fmt.Errorf("memberships for user: %w", err)
	}
	defer rows.Close()

	var out []Membership
	for rows.Next() {
		var m Membership
		var role string
		if err := rows.Scan(&m.TenantID, &m.TenantName, &m.TenantSlug, &role, &m.AcceptedAt); err != nil {
			return nil, err
		}
		m.Role = authz.Role(role)
		out = append(out, m)
	}
	return out, rows.Err()
}

// maxSlugAttempts bounds the disambiguation loop below. Ten is far beyond any
// realistic collision, and a bound means a pathological case fails loudly
// instead of spinning.
const maxSlugAttempts = 10

// CreateTenantWithOwner creates a tenant and its first membership atomically.
//
// One transaction: a tenant with no owner is unreachable — nobody can
// administer it and nobody can be invited to it.
//
// The slug is DISAMBIGUATED, not required to be unique on the first try. Two
// unrelated companies are both entitled to be called "Acme", and the second one
// signing up must not be rejected because the first took the name. The slug is
// a URL convenience; auth.tenants.id is the identity.
func (s *Store) CreateTenantWithOwner(ctx context.Context, name, slug, userID string) (string, error) {
	tx, err := s.pool.Raw().Begin(ctx)
	if err != nil {
		return "", err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	tenantID, err := insertTenant(ctx, tx, name, slug)
	if err != nil {
		return "", err
	}

	// The membership insert is tenant-scoped, so the scope must be set inside
	// this transaction — the tenant only came into existence a statement ago.
	if _, err := tx.Exec(ctx,
		`SELECT set_config('app.current_tenant_id', $1, true)`, tenantID); err != nil {
		return "", fmt.Errorf("set tenant scope: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO auth.memberships (tenant_id, user_id, role, accepted_at)
		VALUES ($1, $2, 'owner', now())`, tenantID, userID); err != nil {
		return "", fmt.Errorf("create owner membership: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return "", err
	}
	return tenantID, nil
}

// insertTenant inserts, appending a numeric suffix on slug collision.
//
// Each attempt runs in a SAVEPOINT. Without one, the first unique violation
// would poison the surrounding transaction — Postgres refuses every subsequent
// statement until rollback — so the retry could never succeed.
func insertTenant(ctx context.Context, tx pgx.Tx, name, slug string) (string, error) {
	for attempt := 1; attempt <= maxSlugAttempts; attempt++ {
		candidate := slug
		if attempt > 1 {
			candidate = fmt.Sprintf("%s-%d", slug, attempt)
		}

		sp, err := tx.Begin(ctx) // nested Begin == SAVEPOINT in pgx
		if err != nil {
			return "", err
		}

		var id string
		err = sp.QueryRow(ctx,
			`INSERT INTO auth.tenants (name, slug) VALUES ($1, $2) RETURNING id`,
			name, candidate).Scan(&id)
		if err == nil {
			if err := sp.Commit(ctx); err != nil {
				return "", err
			}
			return id, nil
		}

		_ = sp.Rollback(ctx)

		var pgErr *pgconn.PgError
		// 23505 is unique_violation. Anything else is a real failure and must
		// not be retried — retrying a permission error ten times helps nobody.
		if !errors.As(err, &pgErr) || pgErr.Code != "23505" {
			return "", fmt.Errorf("create tenant: %w", err)
		}
	}
	return "", fmt.Errorf("create tenant: could not derive a free slug from %q after %d attempts",
		slug, maxSlugAttempts)
}

// ListMembers returns a tenant's members. Tenant-scoped.
func (s *Store) ListMembers(ctx context.Context, tenantID string) ([]Membership, error) {
	var out []Membership
	err := s.pool.WithTenant(ctx, tenantID, func(ctx context.Context, tx db.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT m.tenant_id, m.role, m.accepted_at, m.user_id
			  FROM auth.memberships m
			 ORDER BY m.created_at`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var m Membership
			var role, userID string
			if err := rows.Scan(&m.TenantID, &role, &m.AcceptedAt, &userID); err != nil {
				return err
			}
			m.Role = authz.Role(role)
			out = append(out, m)
		}
		return rows.Err()
	})
	return out, err
}

// ---------------------------------------------------------------------------
// Sessions
// ---------------------------------------------------------------------------

// Session is one refresh-token chain.
type Session struct {
	ID        string
	TenantID  string
	UserID    string
	FamilyID  string
	Role      authz.Role
	ExpiresAt time.Time
	RevokedAt *time.Time
}

// Revoked reports whether this session has been invalidated.
func (s Session) Revoked() bool { return s.RevokedAt != nil }

// CreateSession stores a refresh token's HASH.
func (s *Store) CreateSession(ctx context.Context, tenantID, userID, hash, familyID string,
	expiresAt time.Time, userAgent string, ip net.IP,
) (string, error) {
	var id string
	err := s.pool.WithTenant(ctx, tenantID, func(ctx context.Context, tx db.Tx) error {
		var ipAny any
		if ip != nil {
			ipAny = ip.String()
		}
		return tx.QueryRow(ctx, `
			INSERT INTO auth.sessions
				(tenant_id, user_id, refresh_token_hash, family_id, user_agent, ip, expires_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7)
			RETURNING id`,
			tenantID, userID, hash, familyID, userAgent, ipAny, expiresAt).Scan(&id)
	})
	return id, err
}

// SessionByRefreshHash is the PRE-TENANT refresh lookup.
//
// A refresh request presents only a token; the tenant is what we are trying to
// recover. Returns RevokedAt so the caller can detect reuse.
func (s *Store) SessionByRefreshHash(ctx context.Context, hash string) (Session, error) {
	var sess Session
	var role string
	err := s.pool.Raw().QueryRow(ctx, `
		SELECT session_id, tenant_id, user_id, family_id, expires_at, revoked_at, role
		  FROM auth.session_by_refresh_hash($1)`, hash).
		Scan(&sess.ID, &sess.TenantID, &sess.UserID, &sess.FamilyID,
			&sess.ExpiresAt, &sess.RevokedAt, &role)
	if errors.Is(err, pgx.ErrNoRows) {
		return Session{}, ErrNotFound
	}
	if err != nil {
		return Session{}, fmt.Errorf("session by refresh hash: %w", err)
	}
	sess.Role = authz.Role(role)
	return sess, nil
}

// RevokeSessionFamily invalidates an entire rotation chain.
//
// Called on refresh-token REUSE. Two parties hold a token that should have
// been consumed once; we cannot tell which is the thief, so both are logged
// out. Forcing a re-login beats leaving an attacker authenticated.
func (s *Store) RevokeSessionFamily(ctx context.Context, familyID string) (int, error) {
	var n int
	err := s.pool.Raw().QueryRow(ctx,
		`SELECT auth.revoke_session_family($1)`, familyID).Scan(&n)
	return n, err
}

// RotateSession revokes the presented session and stores its successor, in one
// transaction. Doing it in two steps risks a window where both tokens work.
func (s *Store) RotateSession(ctx context.Context, sess Session, newHash string,
	expiresAt time.Time,
) (string, error) {
	var newID string
	err := s.pool.WithTenant(ctx, sess.TenantID, func(ctx context.Context, tx db.Tx) error {
		if _, err := tx.Exec(ctx,
			`UPDATE auth.sessions SET revoked_at = now() WHERE id = $1`, sess.ID); err != nil {
			return err
		}
		return tx.QueryRow(ctx, `
			INSERT INTO auth.sessions
				(tenant_id, user_id, refresh_token_hash, family_id, expires_at)
			VALUES ($1, $2, $3, $4, $5)
			RETURNING id`,
			sess.TenantID, sess.UserID, newHash, sess.FamilyID, expiresAt).Scan(&newID)
	})
	return newID, err
}

// RevokeSession invalidates one session (logout).
func (s *Store) RevokeSession(ctx context.Context, tenantID, sessionID string) error {
	return s.pool.WithTenant(ctx, tenantID, func(ctx context.Context, tx db.Tx) error {
		_, err := tx.Exec(ctx,
			`UPDATE auth.sessions SET revoked_at = now() WHERE id = $1`, sessionID)
		return err
	})
}

// ---------------------------------------------------------------------------
// Audit
// ---------------------------------------------------------------------------

// AuthEvent is one audit entry.
type AuthEvent struct {
	TenantID  string // empty for pre-authentication events
	ActorID   string
	Action    string
	Metadata  map[string]any
	IP        net.IP
	UserAgent string
}

// RecordAuthEvent appends to the audit log.
//
// Uses the SECURITY DEFINER function so a pre-authentication event — a failed
// login for an unknown email — can be written without a tenant scope it cannot
// have. CERT-In §5.3.6 requires these be recorded.
//
// Metadata must NEVER carry a password, token or secret.
func (s *Store) RecordAuthEvent(ctx context.Context, e AuthEvent) error {
	var tenant, actor, ip any
	if e.TenantID != "" {
		tenant = e.TenantID
	}
	if e.ActorID != "" {
		actor = e.ActorID
	}
	if e.IP != nil {
		ip = e.IP.String()
	}
	meta := e.Metadata
	if meta == nil {
		meta = map[string]any{}
	}

	_, err := s.pool.Raw().Exec(ctx,
		`SELECT auth.record_auth_event($1, $2, $3, $4, $5, $6)`,
		tenant, actor, e.Action, meta, ip, e.UserAgent)
	if err != nil {
		return fmt.Errorf("record auth event: %w", err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Invitations
// ---------------------------------------------------------------------------

// Invitation is a pending tenant invite.
type Invitation struct {
	ID         string
	TenantID   string
	TenantName string
	Email      string
	Role       authz.Role
	ExpiresAt  time.Time
	AcceptedAt *time.Time
	RevokedAt  *time.Time
}

// Usable reports whether an invitation can still be accepted.
func (i Invitation) Usable(now time.Time) error {
	switch {
	case i.AcceptedAt != nil:
		return errors.New("invitation has already been accepted")
	case i.RevokedAt != nil:
		return errors.New("invitation has been revoked")
	case !i.ExpiresAt.After(now):
		return errors.New("invitation has expired")
	default:
		return nil
	}
}

// CreateInvitation stores an invite, keeping only the token HASH.
func (s *Store) CreateInvitation(ctx context.Context, tenantID, email string,
	role authz.Role, tokenHash, invitedBy string, expiresAt time.Time,
) (string, error) {
	var id string
	err := s.pool.WithTenant(ctx, tenantID, func(ctx context.Context, tx db.Tx) error {
		return tx.QueryRow(ctx, `
			INSERT INTO auth.invitations
				(tenant_id, email, role, token_hash, invited_by, expires_at)
			VALUES ($1, $2, $3, $4, $5, $6)
			RETURNING id`,
			tenantID, email, string(role), tokenHash, invitedBy, expiresAt).Scan(&id)
	})
	return id, err
}

// InvitationByTokenHash is the PRE-TENANT invite lookup: the invitee is not yet
// a member, so they have no tenant scope in which to read it.
func (s *Store) InvitationByTokenHash(ctx context.Context, hash string) (Invitation, error) {
	var inv Invitation
	var role string
	err := s.pool.Raw().QueryRow(ctx, `
		SELECT invitation_id, tenant_id, tenant_name, email, role,
		       expires_at, accepted_at, revoked_at
		  FROM auth.invitation_by_token_hash($1)`, hash).
		Scan(&inv.ID, &inv.TenantID, &inv.TenantName, &inv.Email, &role,
			&inv.ExpiresAt, &inv.AcceptedAt, &inv.RevokedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Invitation{}, ErrNotFound
	}
	if err != nil {
		return Invitation{}, fmt.Errorf("invitation by token hash: %w", err)
	}
	inv.Role = authz.Role(role)
	return inv, nil
}

// AcceptInvitation creates the membership and consumes the invite atomically.
//
// One database function rather than two application steps: a membership
// created without consuming the invite would leave the token replayable.
func (s *Store) AcceptInvitation(ctx context.Context, hash, userID string) (string, error) {
	var membershipID string
	err := s.pool.Raw().QueryRow(ctx,
		`SELECT auth.accept_invitation($1, $2)`, hash, userID).Scan(&membershipID)
	if err != nil {
		return "", fmt.Errorf("accept invitation: %w", err)
	}
	return membershipID, nil
}
