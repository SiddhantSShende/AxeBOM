package auth

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/encorebom/encorebom/libs/go-shared/authz"
	"github.com/encorebom/encorebom/libs/go-shared/platform/errs"
)

func testIssuer(t *testing.T) *Issuer {
	t.Helper()
	i, err := NewIssuer(TokenConfig{
		SigningKey: []byte("a-test-signing-key-of-at-least-32-bytes!"),
		Issuer:     "encorebom-test",
		AccessTTL:  15 * time.Minute,
		RefreshTTL: 30 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("NewIssuer: %v", err)
	}
	return i
}

// A short HMAC key can be brute-forced offline from one captured token.
func TestShortSigningKeyRejected(t *testing.T) {
	_, err := NewIssuer(TokenConfig{SigningKey: []byte("too-short")})
	if err == nil {
		t.Fatal("a short signing key must be rejected")
	}
	if !strings.Contains(err.Error(), "brute-forced") {
		t.Errorf("the error should explain why: %v", err)
	}
}

func TestAccessTokenRoundTrip(t *testing.T) {
	i := testIssuer(t)
	now := time.Now()

	token, issued, err := i.IssueAccess(now, "user-1", "tenant-a", "sess-1", authz.RoleAnalyst)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	got, err := i.VerifyAccess(token, now.Add(time.Minute))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if got.Subject != "user-1" || got.TenantID != "tenant-a" || got.Role != authz.RoleAnalyst {
		t.Errorf("claims round-tripped wrong: %+v", got)
	}
	if got.JTI != issued.JTI {
		t.Error("jti changed across round-trip")
	}
}

// THE classic JWT vulnerability: the token declares its own algorithm, a caller
// sets alg=none, and a verifier that trusts the header accepts anything.
func TestAlgNoneIsRejected(t *testing.T) {
	i := testIssuer(t)

	hdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	claims, _ := json.Marshal(Claims{
		Subject: "attacker", TenantID: "victim-tenant", Role: authz.RoleOwner,
		IssuedAt: time.Now().Unix(), Expires: time.Now().Add(time.Hour).Unix(),
		Issuer: "encorebom-test",
	})
	forged := hdr + "." + base64.RawURLEncoding.EncodeToString(claims) + "."

	if _, err := i.VerifyAccess(forged, time.Now()); err == nil {
		t.Fatal("alg=none token was ACCEPTED — the verifier trusts the token's own header")
	}
}

// Flipping a claim must invalidate the signature. This is the whole point.
func TestTamperedClaimsRejected(t *testing.T) {
	i := testIssuer(t)
	now := time.Now()
	token, _, _ := i.IssueAccess(now, "user-1", "tenant-a", "sess-1", authz.RoleViewer)

	parts := strings.Split(token, ".")
	raw, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var c Claims
	_ = json.Unmarshal(raw, &c)

	// Escalate: viewer -> owner, and hop to another tenant.
	c.Role = authz.RoleOwner
	c.TenantID = "tenant-b"
	tampered, _ := json.Marshal(c)
	forged := parts[0] + "." + base64.RawURLEncoding.EncodeToString(tampered) + "." + parts[2]

	if _, err := i.VerifyAccess(forged, now); err == nil {
		t.Fatal("a tampered token verified — privilege escalation and tenant hop")
	}
}

func TestSignatureFromAnotherKeyRejected(t *testing.T) {
	a := testIssuer(t)
	b, _ := NewIssuer(TokenConfig{
		SigningKey: []byte("a-DIFFERENT-signing-key-32-bytes-long!!"),
		Issuer:     "encorebom-test",
	})
	token, _, _ := b.IssueAccess(time.Now(), "u", "t", "s", authz.RoleOwner)

	if _, err := a.VerifyAccess(token, time.Now()); err == nil {
		t.Fatal("a token signed with another key verified")
	}
}

func TestExpiredTokenRejected(t *testing.T) {
	i := testIssuer(t)
	past := time.Now().Add(-2 * time.Hour)
	token, _, _ := i.IssueAccess(past, "u", "t", "s", authz.RoleViewer)

	_, err := i.VerifyAccess(token, time.Now())
	if err == nil {
		t.Fatal("an expired token verified")
	}
	if !errs.Is(err, errs.AuthTokenExpired) {
		t.Errorf("want AUTH_TOKEN_EXPIRED so the client knows to refresh, got %v", err)
	}
}

// A token from a different issuer must not be honoured, even if the signing
// key happens to match — this is what stops a token minted for another
// environment being replayed here.
func TestWrongIssuerRejected(t *testing.T) {
	same := []byte("a-test-signing-key-of-at-least-32-bytes!")
	other, _ := NewIssuer(TokenConfig{SigningKey: same, Issuer: "someone-else"})
	token, _, _ := other.IssueAccess(time.Now(), "u", "t", "s", authz.RoleViewer)

	if _, err := testIssuer(t).VerifyAccess(token, time.Now()); err == nil {
		t.Fatal("a token from another issuer verified")
	}
}

func TestMalformedTokensRejected(t *testing.T) {
	i := testIssuer(t)
	for _, bad := range []string{
		"", "not-a-token", "a.b", "a.b.c.d",
		"!!!.???.***",
		strings.Repeat("A", 5000),
	} {
		if _, err := i.VerifyAccess(bad, time.Now()); err == nil {
			t.Errorf("malformed token %q verified", truncate(bad))
		}
	}
}

// A token carrying a role outside the matrix must not be honoured — otherwise
// an unknown role reaches authz.Allow, which would deny it, but only after the
// tenant scope has already been applied.
func TestUnknownRoleInTokenRejected(t *testing.T) {
	c := Claims{
		Subject: "u", TenantID: "t", Role: authz.Role("superadmin"),
		IssuedAt: time.Now().Unix(), Expires: time.Now().Add(time.Hour).Unix(),
	}
	if err := c.Valid(time.Now()); err == nil {
		t.Fatal("a claim with an unknown role was considered valid")
	}
}

func TestClaimsRequireTenant(t *testing.T) {
	c := Claims{
		Subject: "u", TenantID: "", Role: authz.RoleViewer,
		IssuedAt: time.Now().Unix(), Expires: time.Now().Add(time.Hour).Unix(),
	}
	if err := c.Valid(time.Now()); err == nil {
		t.Fatal("a token with no tenant was accepted — that value drives RLS")
	}
}

// ---------------------------------------------------------------------------
// Refresh tokens
// ---------------------------------------------------------------------------

func TestRefreshTokenIsHashedNotStored(t *testing.T) {
	i := testIssuer(t)
	rt, err := i.NewRefreshToken(time.Now())
	if err != nil {
		t.Fatalf("mint: %v", err)
	}

	if rt.Plaintext == "" || rt.Hash == "" {
		t.Fatal("both plaintext and hash should be produced")
	}
	if rt.Plaintext == rt.Hash {
		t.Fatal("the stored value equals the plaintext — a database read would " +
			"yield a usable credential")
	}
	if HashRefreshToken(rt.Plaintext) != rt.Hash {
		t.Error("hash is not reproducible from the plaintext, so lookup would fail")
	}
	if rt.FamilyID == "" {
		t.Error("a refresh token needs a family id for reuse detection")
	}
}

func TestRotationKeepsFamilyAndChangesToken(t *testing.T) {
	i := testIssuer(t)
	now := time.Now()

	first, _ := i.NewRefreshToken(now)
	second, err := i.RotateRefreshToken(now, first.FamilyID)
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}

	if second.FamilyID != first.FamilyID {
		t.Error("rotation must stay in the same family, or reuse cannot be detected")
	}
	if second.Plaintext == first.Plaintext || second.Hash == first.Hash {
		t.Fatal("rotation produced the same token")
	}
}

func TestRefreshTokensAreUnique(t *testing.T) {
	i := testIssuer(t)
	seen := map[string]bool{}
	for n := 0; n < 500; n++ {
		rt, err := i.NewRefreshToken(time.Now())
		if err != nil {
			t.Fatalf("mint: %v", err)
		}
		if seen[rt.Plaintext] {
			t.Fatal("duplicate refresh token — the CSPRNG is not being used correctly")
		}
		seen[rt.Plaintext] = true
	}
}

// ---------------------------------------------------------------------------
// OAuth state (CSRF)
// ---------------------------------------------------------------------------

// Without state verification an attacker starts a flow, sends the victim the
// callback URL, and the victim's account is linked to the ATTACKER's identity.
func TestOAuthStateMismatchRejected(t *testing.T) {
	want, err := NewOAuthState()
	if err != nil {
		t.Fatalf("mint state: %v", err)
	}

	if err := VerifyOAuthState(want, want); err != nil {
		t.Errorf("matching state should verify: %v", err)
	}
	for _, got := range []string{"", "forged", want + "x", want[:len(want)-1]} {
		if err := VerifyOAuthState(got, want); err == nil {
			t.Errorf("state %q was accepted against %q", truncate(got), truncate(want))
		}
	}
	if err := VerifyOAuthState("anything", ""); err == nil {
		t.Error("an empty expected state must never verify")
	}
}

// ---------------------------------------------------------------------------
// Passwords
// ---------------------------------------------------------------------------

// Fast params keep the suite quick; production uses DefaultArgon2Params.
func fastParams() Argon2Params {
	return Argon2Params{Memory: 8 * 1024, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 32}
}

func TestPasswordHashAndVerify(t *testing.T) {
	p := fastParams()
	hash, err := HashPassword("correct horse battery staple", p)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}

	if !strings.HasPrefix(hash, "$argon2id$") {
		t.Errorf("expected a PHC argon2id hash, got %q", truncate(hash))
	}
	if strings.Contains(hash, "correct horse") {
		t.Fatal("the plaintext appears in the hash")
	}
	if err := VerifyPassword("correct horse battery staple", hash); err != nil {
		t.Errorf("correct password rejected: %v", err)
	}
	if err := VerifyPassword("wrong password", hash); err == nil {
		t.Fatal("a wrong password verified")
	}
}

// Equal passwords must produce different hashes, or the store leaks which
// users share a password.
func TestPasswordHashesAreSalted(t *testing.T) {
	p := fastParams()
	a, _ := HashPassword("same-password", p)
	b, _ := HashPassword("same-password", p)
	if a == b {
		t.Fatal("identical passwords produced identical hashes — the salt is not random")
	}
	// Both must still verify.
	for _, h := range []string{a, b} {
		if err := VerifyPassword("same-password", h); err != nil {
			t.Errorf("salted hash failed to verify: %v", err)
		}
	}
}

func TestEmptyPasswordRefused(t *testing.T) {
	if _, err := HashPassword("", fastParams()); err == nil {
		t.Fatal("hashing an empty password should be refused")
	}
}

func TestMalformedHashRejected(t *testing.T) {
	for _, bad := range []string{
		"", "not-a-hash", "$argon2i$v=19$m=1,t=1,p=1$c2FsdA$aGFzaA",
		"$argon2id$v=99$m=1,t=1,p=1$c2FsdA$aGFzaA",
		"$argon2id$v=19$garbage$c2FsdA$aGFzaA",
	} {
		if err := VerifyPassword("x", bad); err == nil {
			t.Errorf("malformed hash %q verified", truncate(bad))
		}
	}
}

// Parameters are raised over time; old hashes must still verify and be
// upgradable on next login — the only moment the plaintext exists.
func TestNeedsRehashDetectsWeakerParams(t *testing.T) {
	weak := fastParams()
	hash, _ := HashPassword("pw", weak)

	if NeedsRehash(hash, weak) {
		t.Error("a hash at current params should not need rehashing")
	}

	stronger := weak
	stronger.Memory *= 4
	if !NeedsRehash(hash, stronger) {
		t.Error("a hash weaker than policy should be flagged for rehash")
	}

	// And the old hash must still verify, or raising params locks everyone out.
	if err := VerifyPassword("pw", hash); err != nil {
		t.Errorf("old hash stopped verifying after a params change: %v", err)
	}

	if !NeedsRehash("not-a-hash", weak) {
		t.Error("an unparseable hash should be replaced")
	}
}

func TestDefaultParamsAreNotTrivial(t *testing.T) {
	p := DefaultArgon2Params()
	// OWASP's argon2id recommendation is 19 MiB / t=2. Anything materially
	// lower makes an offline crack of a leaked hash cheap.
	if p.Memory < 19*1024 {
		t.Errorf("memory = %d KiB, want >= 19456 (OWASP argon2id guidance)", p.Memory)
	}
	if p.Iterations < 2 {
		t.Errorf("iterations = %d, want >= 2", p.Iterations)
	}
	if p.SaltLength < 16 || p.KeyLength < 32 {
		t.Errorf("salt/key too short: %d/%d", p.SaltLength, p.KeyLength)
	}
}

// Without a dummy verify, a missing user returns instantly while a real one
// costs ~50ms of argon2 — a measurable account-enumeration oracle.
func TestDummyVerifyBurnsComparableWork(t *testing.T) {
	p := fastParams()

	start := time.Now()
	DummyVerify(p)
	dummy := time.Since(start)

	hash, _ := HashPassword("pw", p)
	start = time.Now()
	_ = VerifyPassword("wrong", hash)
	real := time.Since(start)

	// Wall-clock on a shared CI box is noisy, so this asserts the same order of
	// magnitude rather than a tight bound — the point is that dummy is not zero.
	if dummy < real/10 {
		t.Errorf("DummyVerify (%v) is far cheaper than a real verify (%v); "+
			"login timing would reveal which accounts exist", dummy, real)
	}
}

func truncate(s string) string {
	if len(s) > 40 {
		return s[:40] + "…"
	}
	return s
}
