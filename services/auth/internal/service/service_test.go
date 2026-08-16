package service_test

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/encorebom/encorebom/libs/go-shared/auth"
	"github.com/encorebom/encorebom/libs/go-shared/authz"
	"github.com/encorebom/encorebom/libs/go-shared/platform/config"
	"github.com/encorebom/encorebom/libs/go-shared/platform/db"
	"github.com/encorebom/encorebom/libs/go-shared/platform/errs"
	"github.com/encorebom/encorebom/services/auth/internal/service"
	"github.com/encorebom/encorebom/services/auth/internal/store"
)

// Phase 3 acceptance tests.
//
// These need a live database (`task dev && task db:reset`) and SKIP rather than
// fail without one, matching the convention in platform/db. CI always has it.
//
// They run against real Postgres deliberately: the properties under test —
// RLS isolation, SECURITY DEFINER reachability, atomic invite acceptance — are
// properties of the DATABASE. A mocked store would pass while the product leaks.

func testPool(t *testing.T) *db.Pool {
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
	return pool
}

// fastArgon keeps the suite quick. Production parameters are deliberately slow,
// and every test here creates several accounts.
func fastArgon() auth.Argon2Params {
	p := auth.DefaultArgon2Params()
	p.Memory = 8 * 1024
	p.Iterations = 1
	return p
}

type fixture struct {
	svc   *service.Service
	store *store.Store
	pool  *db.Pool
	clock *fakeClock
}

// fakeClock lets expiry tests run without sleeping.
type fakeClock struct{ t time.Time }

func (c *fakeClock) Now() time.Time          { return c.t }
func (c *fakeClock) Advance(d time.Duration) { c.t = c.t.Add(d) }

func newFixture(t *testing.T) *fixture {
	t.Helper()
	pool := testPool(t)
	st := store.New(pool)

	issuer, err := auth.NewIssuer(auth.TokenConfig{
		SigningKey: []byte("test-signing-key-that-is-long-enough-to-pass-validation"),
		Issuer:     "encorebom-test",
		AccessTTL:  15 * time.Minute,
		RefreshTTL: 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("issuer: %v", err)
	}

	clock := &fakeClock{t: time.Now().UTC()}
	return &fixture{
		svc: service.New(service.Config{
			Store: st, Issuer: issuer, Argon: fastArgon(), Now: clock.Now,
		}),
		store: st, pool: pool, clock: clock,
	}
}

// uniqueEmail keeps parallel runs and reruns from colliding on the unique
// index. t.Name() is stable per test, and the nanosecond suffix per run.
func uniqueEmail(t *testing.T) string {
	t.Helper()
	return strings.ToLower(strings.NewReplacer("/", "-", " ", "-").Replace(t.Name())) +
		"-" + time.Now().Format("150405.000000000") + "@example.test"
}

const goodPassword = "correct-horse-battery-staple"

func register(t *testing.T, f *fixture, org string) (service.TokenPair, string) {
	t.Helper()
	email := uniqueEmail(t)
	pair, err := f.svc.Register(t.Context(), service.RegisterParams{
		Email: email, Password: goodPassword, Name: "Test User", TenantName: org,
	}, service.RequestMeta{})
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	return pair, email
}

// ---------------------------------------------------------------------------
// Registration and login
// ---------------------------------------------------------------------------

func TestRegisterCreatesTenantAndOwner(t *testing.T) {
	f := newFixture(t)
	pair, _ := register(t, f, "Acme Test Org")

	if pair.Role != authz.RoleOwner {
		t.Errorf("role = %q, want owner — the first user must be able to administer the tenant", pair.Role)
	}
	if pair.TenantID == "" || pair.AccessToken == "" || pair.RefreshToken == "" {
		t.Fatalf("incomplete token pair: %+v", pair)
	}
}

// The two error paths of login must be INDISTINGUISHABLE. If they are not,
// the endpoint tells an attacker which email addresses have accounts.
func TestLoginDoesNotRevealWhetherAnAccountExists(t *testing.T) {
	f := newFixture(t)
	_, email := register(t, f, "Enumeration Test Org")

	_, wrongPassword := f.svc.Login(t.Context(), service.LoginParams{
		Email: email, Password: "not-the-right-password",
	}, service.RequestMeta{})

	_, noSuchUser := f.svc.Login(t.Context(), service.LoginParams{
		Email: "definitely-not-registered-" + uniqueEmail(t), Password: goodPassword,
	}, service.RequestMeta{})

	if wrongPassword == nil || noSuchUser == nil {
		t.Fatal("both logins should have failed")
	}
	if wrongPassword.Error() != noSuchUser.Error() {
		t.Errorf("the two failures are distinguishable:\n  wrong password: %v\n  no such user:   %v",
			wrongPassword, noSuchUser)
	}
	if !errs.Is(wrongPassword, errs.AuthInvalidCreds) {
		t.Errorf("code = %v, want AUTH_INVALID_CREDS", wrongPassword)
	}
}

func TestLoginSucceedsWithCorrectPassword(t *testing.T) {
	f := newFixture(t)
	first, email := register(t, f, "Login Test Org")

	pair, err := f.svc.Login(t.Context(), service.LoginParams{
		Email: email, Password: goodPassword,
	}, service.RequestMeta{})
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	if pair.TenantID != first.TenantID {
		t.Errorf("tenant = %q, want %q", pair.TenantID, first.TenantID)
	}
	// A fresh login must not reuse the registration's refresh token.
	if pair.RefreshToken == first.RefreshToken {
		t.Error("login reissued the same refresh token; sessions are not independent")
	}
}

// Email is normalized, so the same person is one account however they type it.
func TestLoginIsCaseInsensitiveOnEmail(t *testing.T) {
	f := newFixture(t)
	_, email := register(t, f, "Case Test Org")

	if _, err := f.svc.Login(t.Context(), service.LoginParams{
		Email: "  " + strings.ToUpper(email) + "  ", Password: goodPassword,
	}, service.RequestMeta{}); err != nil {
		t.Errorf("login with differently-cased email failed: %v", err)
	}
}

func TestRegisterRejectsWeakInput(t *testing.T) {
	f := newFixture(t)

	tests := []struct {
		name   string
		params service.RegisterParams
	}{
		{"short password", service.RegisterParams{
			Email: uniqueEmail(t), Password: "short", TenantName: "Org"}},
		{"malformed email", service.RegisterParams{
			Email: "not-an-email", Password: goodPassword, TenantName: "Org"}},
		{"no organisation", service.RegisterParams{
			Email: uniqueEmail(t), Password: goodPassword, TenantName: "   "}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := f.svc.Register(t.Context(), tt.params, service.RequestMeta{}); err == nil {
				t.Error("accepted invalid registration")
			}
		})
	}
}

func TestRegisterRejectsDuplicateEmail(t *testing.T) {
	f := newFixture(t)
	_, email := register(t, f, "Duplicate Test Org")

	_, err := f.svc.Register(t.Context(), service.RegisterParams{
		Email: email, Password: goodPassword, TenantName: "Another Org",
	}, service.RequestMeta{})
	if err == nil {
		t.Fatal("a second account was created for the same email")
	}
}

// ---------------------------------------------------------------------------
// Refresh rotation and reuse detection — the core of the phase
// ---------------------------------------------------------------------------

func TestRefreshRotatesTheToken(t *testing.T) {
	f := newFixture(t)
	pair, _ := register(t, f, "Rotate Test Org")

	next, err := f.svc.Refresh(t.Context(), pair.RefreshToken, service.RequestMeta{})
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if next.RefreshToken == pair.RefreshToken {
		t.Fatal("refresh returned the SAME token; without rotation there is nothing to detect reuse with")
	}
	if next.TenantID != pair.TenantID || next.UserID != pair.UserID {
		t.Errorf("refresh changed identity: %+v -> %+v", pair, next)
	}
}

// ⚠ THE CENTRAL SECURITY TEST OF THIS PHASE.
//
// Presenting an already-rotated refresh token means two parties hold it. We
// cannot tell the thief from the victim, so BOTH must lose the session —
// otherwise a stolen token yields indefinite access.
func TestRefreshReuseRevokesTheWholeFamily(t *testing.T) {
	f := newFixture(t)
	pair, _ := register(t, f, "Reuse Test Org")

	// The legitimate client refreshes. `stolen` is now spent.
	stolen := pair.RefreshToken
	live, err := f.svc.Refresh(t.Context(), stolen, service.RequestMeta{})
	if err != nil {
		t.Fatalf("first refresh: %v", err)
	}

	// The attacker replays the spent token.
	if _, err := f.svc.Refresh(t.Context(), stolen, service.RequestMeta{}); err == nil {
		t.Fatal("a spent refresh token was accepted a second time")
	} else if !errs.Is(err, errs.AuthRefreshReused) {
		t.Errorf("code = %v, want AUTH_REFRESH_REUSED", err)
	}

	// And the legitimate client's CURRENT token must now be dead too. This is
	// the assertion that actually proves the family was revoked rather than
	// just the one replayed token.
	if _, err := f.svc.Refresh(t.Context(), live.RefreshToken, service.RequestMeta{}); err == nil {
		t.Fatal("the victim's live token still works — the family was not revoked, " +
			"so the thief keeps access through their own successor")
	}
}

func TestRefreshRejectsUnknownToken(t *testing.T) {
	f := newFixture(t)
	if _, err := f.svc.Refresh(t.Context(), "not-a-real-token", service.RequestMeta{}); err == nil {
		t.Fatal("an unknown refresh token was accepted")
	}
}

func TestRefreshRejectsExpiredToken(t *testing.T) {
	f := newFixture(t)
	pair, _ := register(t, f, "Expiry Test Org")

	f.clock.Advance(48 * time.Hour) // past the 24h refresh TTL

	_, err := f.svc.Refresh(t.Context(), pair.RefreshToken, service.RequestMeta{})
	if err == nil {
		t.Fatal("an expired refresh token was accepted")
	}
	if !errs.Is(err, errs.AuthTokenExpired) {
		t.Errorf("code = %v, want AUTH_TOKEN_EXPIRED", err)
	}
}

func TestLogoutRevokesTheSession(t *testing.T) {
	f := newFixture(t)
	pair, _ := register(t, f, "Logout Test Org")

	claims, err := verifyClaims(t, pair.AccessToken)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if err := f.svc.Logout(t.Context(), pair.TenantID, claims.SessionID,
		pair.UserID, service.RequestMeta{}); err != nil {
		t.Fatalf("logout: %v", err)
	}

	if _, err := f.svc.Refresh(t.Context(), pair.RefreshToken, service.RequestMeta{}); err == nil {
		t.Fatal("the refresh token still works after logout")
	}
}

func verifyClaims(t *testing.T, token string) (auth.Claims, error) {
	t.Helper()
	issuer, err := auth.NewIssuer(auth.TokenConfig{
		SigningKey: []byte("test-signing-key-that-is-long-enough-to-pass-validation"),
		Issuer:     "encorebom-test",
		AccessTTL:  15 * time.Minute,
		RefreshTTL: 24 * time.Hour,
	})
	if err != nil {
		return auth.Claims{}, err
	}
	return issuer.VerifyAccess(token, time.Now())
}

// ---------------------------------------------------------------------------
// Tenant isolation
// ---------------------------------------------------------------------------

// Two tenants, one query each. If RLS were off — or if a WHERE clause were
// forgotten — the counts would include the other tenant's rows.
func TestSessionsAreInvisibleAcrossTenants(t *testing.T) {
	f := newFixture(t)
	a, _ := register(t, f, "Isolation Org A")
	b, _ := register(t, f, "Isolation Org B")

	if a.TenantID == b.TenantID {
		t.Fatal("fixture error: both registrations landed in one tenant")
	}

	countIn := func(tenantID string) int {
		var n int
		err := f.pool.WithTenant(t.Context(), tenantID,
			func(ctx context.Context, tx db.Tx) error {
				return tx.QueryRow(ctx, `SELECT count(*) FROM auth.sessions`).Scan(&n)
			})
		if err != nil {
			t.Fatalf("count in %s: %v", tenantID, err)
		}
		return n
	}

	// Each tenant sees exactly its own one session.
	if got := countIn(a.TenantID); got != 1 {
		t.Errorf("tenant A sees %d sessions, want 1", got)
	}
	if got := countIn(b.TenantID); got != 1 {
		t.Errorf("tenant B sees %d sessions, want 1", got)
	}
}

// A user asking for a tenant they do not belong to must get a NOT-FOUND shape,
// never a forbidden one: 403 confirms the tenant exists.
func TestLoginToAForeignTenantIsNotFound(t *testing.T) {
	f := newFixture(t)
	_, emailA := register(t, f, "Foreign Org A")
	b, _ := register(t, f, "Foreign Org B")

	_, err := f.svc.Login(t.Context(), service.LoginParams{
		Email: emailA, Password: goodPassword, TenantID: b.TenantID,
	}, service.RequestMeta{})
	if err == nil {
		t.Fatal("a user logged into a tenant they do not belong to")
	}
	if !errs.Is(err, errs.NotFoundResource) {
		t.Errorf("code = %v, want NOT_FOUND_RESOURCE (a 403 would confirm the tenant exists)", err)
	}
}

// ---------------------------------------------------------------------------
// Invitations
// ---------------------------------------------------------------------------

func TestInviteAndAcceptJoinsTheTenant(t *testing.T) {
	f := newFixture(t)
	owner, _ := register(t, f, "Invite Test Org")

	invitee := uniqueEmail(t)
	inv, err := f.svc.CreateInvite(t.Context(), owner.TenantID, invitee,
		authz.RoleAnalyst, owner.UserID, service.RequestMeta{})
	if err != nil {
		t.Fatalf("create invite: %v", err)
	}

	pair, err := f.svc.AcceptInvite(t.Context(), service.AcceptInviteParams{
		Token: inv.Token, Password: goodPassword, Name: "Invited User",
	}, service.RequestMeta{})
	if err != nil {
		t.Fatalf("accept invite: %v", err)
	}
	if pair.TenantID != owner.TenantID {
		t.Errorf("invitee joined %q, want %q", pair.TenantID, owner.TenantID)
	}
	if pair.Role != authz.RoleAnalyst {
		t.Errorf("role = %q, want analyst — the invite's role must be honoured", pair.Role)
	}
}

// An invite token is a credential. Accepting twice would let a leaked link add
// a second person, or re-add someone who was removed.
func TestInviteCannotBeAcceptedTwice(t *testing.T) {
	f := newFixture(t)
	owner, _ := register(t, f, "Single Use Org")

	inv, err := f.svc.CreateInvite(t.Context(), owner.TenantID, uniqueEmail(t),
		authz.RoleViewer, owner.UserID, service.RequestMeta{})
	if err != nil {
		t.Fatalf("create invite: %v", err)
	}

	if _, err := f.svc.AcceptInvite(t.Context(), service.AcceptInviteParams{
		Token: inv.Token, Password: goodPassword,
	}, service.RequestMeta{}); err != nil {
		t.Fatalf("first accept: %v", err)
	}
	if _, err := f.svc.AcceptInvite(t.Context(), service.AcceptInviteParams{
		Token: inv.Token, Password: goodPassword,
	}, service.RequestMeta{}); err == nil {
		t.Fatal("the same invite token was accepted twice")
	}
}

func TestExpiredInviteIsRejected(t *testing.T) {
	f := newFixture(t)
	owner, _ := register(t, f, "Expired Invite Org")

	inv, err := f.svc.CreateInvite(t.Context(), owner.TenantID, uniqueEmail(t),
		authz.RoleViewer, owner.UserID, service.RequestMeta{})
	if err != nil {
		t.Fatalf("create invite: %v", err)
	}

	f.clock.Advance(8 * 24 * time.Hour) // past the 7-day default TTL

	if _, err := f.svc.AcceptInvite(t.Context(), service.AcceptInviteParams{
		Token: inv.Token, Password: goodPassword,
	}, service.RequestMeta{}); err == nil {
		t.Fatal("an expired invite was accepted")
	}
}

// Only the hash is stored, so a database read must not yield a usable token.
func TestInviteTokenIsNotStoredInPlaintext(t *testing.T) {
	f := newFixture(t)
	owner, _ := register(t, f, "Hash Only Org")

	inv, err := f.svc.CreateInvite(t.Context(), owner.TenantID, uniqueEmail(t),
		authz.RoleViewer, owner.UserID, service.RequestMeta{})
	if err != nil {
		t.Fatalf("create invite: %v", err)
	}

	var n int
	err = f.pool.WithTenant(t.Context(), owner.TenantID,
		func(ctx context.Context, tx db.Tx) error {
			return tx.QueryRow(ctx,
				`SELECT count(*) FROM auth.invitations WHERE token_hash = $1`,
				inv.Token).Scan(&n)
		})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if n != 0 {
		t.Error("the plaintext invite token is stored in token_hash")
	}
}

// ---------------------------------------------------------------------------
// Audit
// ---------------------------------------------------------------------------

// A failed login for an unknown email belongs to no tenant, but CERT-In §5.3.6
// still requires it be recorded. It must not be silently dropped because there
// is no tenant scope to write it in.
func TestPreAuthenticationFailureIsAudited(t *testing.T) {
	f := newFixture(t)
	unknown := uniqueEmail(t)

	if _, err := f.svc.Login(t.Context(), service.LoginParams{
		Email: unknown, Password: goodPassword,
	}, service.RequestMeta{}); err == nil {
		t.Fatal("login with an unknown email succeeded")
	}

	// Read as the OWNER, not the application role.
	//
	// This is not a convenience: a global audit row has no tenant, and the
	// nullable RLS policy has no `OR tenant_id IS NULL` in its USING clause, so
	// no tenant can read it. That is deliberate — those rows carry the email
	// addresses of people who are not any tenant's users. The row is therefore
	// write-only to the application and observable only out-of-band, which is
	// exactly what this test does.
	owner := ownerConn(t)
	var n int
	if err := owner.QueryRow(t.Context(), `
		SELECT count(*) FROM auth.audit_log
		 WHERE action = 'auth.login.failed'
		   AND tenant_id IS NULL
		   AND metadata->>'email' = $1`, unknown).Scan(&n); err != nil {
		t.Fatalf("query audit log: %v", err)
	}
	if n == 0 {
		t.Error("a pre-authentication failure was not recorded")
	}
}

// The same row must be UNREADABLE through the application role, in every
// tenant. If this ever passes, global auth events are leaking into tenants.
func TestGlobalAuditRowsAreNotReadableByAnyTenant(t *testing.T) {
	f := newFixture(t)
	owner, _ := register(t, f, "Global Audit Org")

	unknown := uniqueEmail(t)
	_, _ = f.svc.Login(t.Context(), service.LoginParams{
		Email: unknown, Password: goodPassword,
	}, service.RequestMeta{})

	var n int
	err := f.pool.WithTenant(t.Context(), owner.TenantID,
		func(ctx context.Context, tx db.Tx) error {
			return tx.QueryRow(ctx, `
				SELECT count(*) FROM auth.audit_log
				 WHERE tenant_id IS NULL AND metadata->>'email' = $1`, unknown).Scan(&n)
		})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if n != 0 {
		t.Errorf("a tenant can read %d global audit rows, exposing non-members' email addresses", n)
	}
}

// ownerConn opens a direct connection as the migration owner.
//
// TESTS ONLY, and only to observe what the application deliberately cannot.
// Application code must never do this: the owner bypasses FORCE RLS, which is
// the entire tenancy boundary. db.Open refuses such a role for that reason.
func ownerConn(t *testing.T) *pgx.Conn {
	t.Helper()
	cfg, err := config.LoadService("auth")
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	p := cfg.Postgres
	dsn := fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=%s",
		p.User, url.QueryEscape(p.Password.Reveal()), p.Host, p.Port, p.Database, p.SSLMode)

	conn, err := pgx.Connect(t.Context(), dsn)
	if err != nil {
		t.Skipf("owner connection unavailable: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close(context.Background()) })
	return conn
}

// The audit log is evidence. If the application role can rewrite it, it is not.
func TestAuditLogCannotBeRewrittenByTheApplicationRole(t *testing.T) {
	f := newFixture(t)
	owner, _ := register(t, f, "Audit Immutability Org")

	for _, stmt := range []struct{ name, sql string }{
		{"UPDATE", `UPDATE auth.audit_log SET action = 'tampered' WHERE tenant_id = $1`},
		{"DELETE", `DELETE FROM auth.audit_log WHERE tenant_id = $1`},
	} {
		t.Run(stmt.name, func(t *testing.T) {
			err := f.pool.WithTenant(t.Context(), owner.TenantID,
				func(ctx context.Context, tx db.Tx) error {
					_, execErr := tx.Exec(ctx, stmt.sql, owner.TenantID)
					return execErr
				})
			if err == nil {
				t.Errorf("%s on the audit log succeeded; the log is not append-only", stmt.name)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Store-level guards
// ---------------------------------------------------------------------------

// Linking is safe only because GitHub reported the email verified. Even so, a
// second GitHub identity must not be able to overwrite an existing link.
func TestGitHubIdentityCannotBeStolenFromALinkedAccount(t *testing.T) {
	f := newFixture(t)
	owner, _ := register(t, f, "Link Test Org")

	// github_user_id is globally unique, so a fixed constant would collide with
	// the previous run's leftover row rather than testing anything.
	firstGitHubID := time.Now().UnixNano() % 1_000_000_000

	if err := f.store.LinkGitHubIdentity(t.Context(), owner.UserID, firstGitHubID, "original"); err != nil {
		t.Fatalf("first link: %v", err)
	}
	// A different GitHub account tries to claim the same user.
	if err := f.store.LinkGitHubIdentity(t.Context(), owner.UserID, firstGitHubID+1, "impostor"); err == nil {
		t.Fatal("a second GitHub identity overwrote an existing link")
	}
	// The original link is intact.
	u, err := f.store.FindUserByGitHubID(t.Context(), firstGitHubID)
	if err != nil || u.ID != owner.UserID {
		t.Errorf("original link damaged: user=%+v err=%v", u, err)
	}
}

func TestFindUserByEmailReportsNotFound(t *testing.T) {
	f := newFixture(t)
	_, err := f.store.FindUserByEmail(t.Context(), "nobody-"+uniqueEmail(t))
	if !errors.Is(err, store.ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
}
