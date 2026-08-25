package auth

import (
	"strings"
	"testing"
	"time"

	"github.com/axebom/axebom/libs/go-shared/authz"
	"github.com/axebom/axebom/libs/go-shared/platform/errs"
)

var keyNow = time.Date(2026, 8, 18, 9, 0, 0, 0, time.UTC)

func mint(t *testing.T, scopes ...Scope) Minted {
	t.Helper()
	if len(scopes) == 0 {
		scopes = []Scope{ScopeScanRun}
	}
	m, err := Mint("tenant-a", "ci pipeline", "user-1", scopes, 0, keyNow)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// ---------------------------------------------------------------------------
// Storage
// ---------------------------------------------------------------------------

// TestTheKeyIsNeverStored.
//
// ⚠ AN API KEY IS A LONG-LIVED BEARER CREDENTIAL. It gets pasted into a CI
// config, copied into a wiki, and echoed by a build log. Storing it means a
// database disclosure is a disclosure of every customer's key.
func TestTheKeyIsNeverStored(t *testing.T) {
	m := mint(t)

	if m.Record.Hash == "" {
		t.Fatal("no hash was stored")
	}
	if strings.Contains(m.Record.Hash, m.Key) {
		t.Fatal("the stored hash contains the key")
	}
	// And nothing on the record reveals it.
	rendered := m.Record.Redacted()
	if strings.Contains(rendered, m.Key) {
		t.Errorf("the log form contains the key: %s", rendered)
	}
	if !strings.Contains(rendered, m.Record.KeyID) {
		t.Errorf("the log form does not identify which key: %s", rendered)
	}
}

// TestTheKeyCarriesARecognisablePrefix.
//
// ⚠ A RECOGNISABLE PREFIX IS A FEATURE. GitHub, GitLab and every commercial
// secret scanner match on known prefixes; a key that looks like random base64
// is one a scanner cannot find in a public commit. Making ours identifiable is
// what gets it caught and revoked.
func TestTheKeyCarriesARecognisablePrefix(t *testing.T) {
	m := mint(t)
	if !strings.HasPrefix(m.Key, KeyPrefix) {
		t.Fatalf("key %q carries no prefix", m.Key)
	}
}

// TestTheKeyIDMakesLookupASingleIndexedRead.
//
// Without it, verification compares hashes against every key in the tenant —
// O(keys) on every request, and a tenant with a thousand keys makes the whole
// API slow.
func TestTheKeyIDMakesLookupASingleIndexedRead(t *testing.T) {
	m := mint(t)

	parsed, err := ParseKeyID(m.Key)
	if err != nil {
		t.Fatal(err)
	}
	if parsed != m.Record.KeyID {
		t.Errorf("parsed id %q, stored %q", parsed, m.Record.KeyID)
	}
}

func TestAMalformedKeyIsRejectedBeforeAnyLookup(t *testing.T) {
	for _, presented := range []string{
		"", "not-a-key", "ebk_", "ebk_short_abc",
		"ebk_" + strings.Repeat("a", 11) + "_x", // wrong id length
	} {
		if _, err := ParseKeyID(presented); err == nil {
			t.Errorf("%q was parsed as a key id", presented)
		}
	}
}

func TestKeysAreDistinct(t *testing.T) {
	seen := map[string]bool{}
	for range 25 {
		m := mint(t)
		if seen[m.Key] {
			t.Fatal("a key was generated twice")
		}
		seen[m.Key] = true
	}
}

// ---------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------

func TestAGoodKeyVerifies(t *testing.T) {
	m := mint(t)
	if err := Verify(m.Key, m.Record, keyNow); err != nil {
		t.Fatalf("a fresh key did not verify: %v", err)
	}
}

func TestAWrongKeyDoesNotVerify(t *testing.T) {
	m := mint(t)
	other := mint(t)
	if err := Verify(other.Key, m.Record, keyNow); err == nil {
		t.Fatal("another tenant's key verified")
	}
}

// TestARevokedKeyIsRefusedButOnlyAfterTheHashIsChecked.
//
// ⚠ ORDER MATTERS. Checking revocation first means a caller can learn whether a
// key EXISTS by timing the difference between "wrong key" and "revoked key".
func TestARevokedKeyIsRefusedButOnlyAfterTheHashIsChecked(t *testing.T) {
	m := mint(t)
	revoked := keyNow.Add(-time.Hour)
	m.Record.RevokedAt = &revoked

	// The right key, revoked: a specific error.
	err := Verify(m.Key, m.Record, keyNow)
	if err == nil {
		t.Fatal("a revoked key verified")
	}
	if !strings.Contains(err.Error(), "revoked") {
		t.Errorf("the error does not say the key was revoked: %v", err)
	}

	// The WRONG key against a revoked record: indistinguishable from any other
	// wrong key, so revocation status leaks nothing.
	other := mint(t)
	wrongErr := Verify(other.Key, m.Record, keyNow)
	if strings.Contains(wrongErr.Error(), "revoked") {
		t.Errorf("a wrong key learned that the record was revoked: %v", wrongErr)
	}
}

func TestAnExpiredKeyIsRefused(t *testing.T) {
	m := mint(t)
	if err := Verify(m.Key, m.Record, m.Record.ExpiresAt.Add(time.Second)); err == nil {
		t.Fatal("an expired key verified")
	}
	if !errs.Is(Verify(m.Key, m.Record, m.Record.ExpiresAt.Add(time.Second)),
		errs.AuthTokenExpired) {
		t.Error("expiry does not use the taxonomy's expired code")
	}
}

// TestAKeyExpiresByDefault.
//
// ⚠ A DEFAULT OF "NEVER EXPIRES" IS HOW A CREDENTIAL OUTLIVES THE PERSON WHO
// CREATED IT. Nobody gets round to rotating a key that has not stopped working.
func TestAKeyExpiresByDefault(t *testing.T) {
	m := mint(t)
	if m.Record.ExpiresAt.IsZero() {
		t.Fatal("the key never expires")
	}
	if !m.Record.ExpiresAt.Equal(keyNow.Add(DefaultTTL)) {
		t.Errorf("expiry = %s, want %s", m.Record.ExpiresAt, keyNow.Add(DefaultTTL))
	}
	if DefaultTTL > 180*24*time.Hour {
		t.Errorf("the default TTL is %s; long enough that nobody rotates", DefaultTTL)
	}
}

func TestAnExcessiveTTLIsRefused(t *testing.T) {
	_, err := Mint("tenant-a", "forever", "user-1", []Scope{ScopeScanRun}, 10*365*24*time.Hour, keyNow)
	if err == nil {
		t.Fatal("a ten-year key was minted")
	}
}

// ---------------------------------------------------------------------------
// Scopes
// ---------------------------------------------------------------------------

// TestAScopeIsNarrowerThanARole.
//
// ⚠ A CI PIPELINE NEEDS TO START A SCAN AND DOWNLOAD A REPORT. Giving it an
// analyst role also gives it triage, share-link minting and campaign editing —
// none of which it will ever do, all of which it could do if the key leaked.
func TestAScopeIsNarrowerThanARole(t *testing.T) {
	m := mint(t, ScopeScanRun, ScopeReportDownload)

	if err := AuthorizeKey(m.Record, authz.ResourceScan, authz.ActionRun); err != nil {
		t.Errorf("a scan:run key cannot start a scan: %v", err)
	}
	if err := AuthorizeKey(m.Record, authz.ResourceReport, authz.ActionDownload); err != nil {
		t.Errorf("a report:download key cannot download: %v", err)
	}

	// Everything an analyst could do that this key did not ask for.
	for _, denied := range []struct {
		res authz.Resource
		act authz.Action
	}{
		{authz.ResourceVEX, authz.ActionTriage},
		{authz.ResourceShareLink, authz.ActionShare},
		{authz.ResourceCampaign, authz.ActionUpdate},
		{authz.ResourceScan, authz.ActionDelete},
	} {
		if err := AuthorizeKey(m.Record, denied.res, denied.act); err == nil {
			t.Errorf("a scan:run key may (%s, %s)", denied.res, denied.act)
		}
	}
}

// TestThereIsNoAdminScope.
//
// ⚠ NOTHING THAT MANAGES TENANTS, MEMBERS OR ROLES IS REACHABLE WITH AN API
// KEY. Those need a human with a session: the blast radius of an automated
// credential doing them is the whole tenant.
func TestThereIsNoAdminScope(t *testing.T) {
	for _, s := range Scopes() {
		res, _, ok := s.Permission()
		if !ok {
			t.Errorf("scope %q maps to no permission", s)
			continue
		}
		switch res {
		case authz.ResourceTenant, authz.ResourceMember, authz.ResourceAuditLog:
			t.Errorf("scope %q reaches %s, which needs a human with a session", s, res)
		}
	}
}

// TestEveryScopeIsWithinTheAnalystRole.
//
// A scope is a NARROWING of what a key may do, never a widening.
func TestEveryScopeIsWithinTheAnalystRole(t *testing.T) {
	for _, s := range Scopes() {
		res, act, ok := s.Permission()
		if !ok {
			continue
		}
		if !authz.Allow(authz.RoleAnalyst, res, act).Allowed {
			t.Errorf("scope %q names (%s, %s), which an analyst does not hold — "+
				"a scope must narrow a role, never widen it", s, res, act)
		}
	}
}

func TestAnUnknownScopeIsRefused(t *testing.T) {
	_, err := Mint("tenant-a", "x", "user-1", []Scope{"tenant:delete"}, 0, keyNow)
	if err == nil {
		t.Fatal("an unknown scope was accepted")
	}
}

func TestAKeyNeedsAtLeastOneScope(t *testing.T) {
	if _, err := Mint("tenant-a", "x", "user-1", nil, 0, keyNow); err == nil {
		t.Fatal("a key with no scopes was minted")
	}
}

// TestAKeyNeedsAName.
//
// ⚠ FACED WITH SIX UNNAMED KEYS, an operator responding to a leak either
// revokes all of them and breaks production, or guesses.
func TestAKeyNeedsAName(t *testing.T) {
	for _, name := range []string{"", "   ", "\t"} {
		if _, err := Mint("tenant-a", name, "user-1", []Scope{ScopeScanRun}, 0, keyNow); err == nil {
			t.Errorf("a key named %q was minted", name)
		}
	}
}

func TestAKeyBelongsToATenant(t *testing.T) {
	if _, err := Mint("", "x", "user-1", []Scope{ScopeScanRun}, 0, keyNow); err == nil {
		t.Fatal("a key with no tenant was minted")
	}
}

func TestActiveReflectsRevocationAndExpiry(t *testing.T) {
	m := mint(t)
	if !m.Record.Active(keyNow) {
		t.Error("a fresh key is not active")
	}
	if m.Record.Active(m.Record.ExpiresAt.Add(time.Second)) {
		t.Error("an expired key is active")
	}

	revoked := keyNow
	m.Record.RevokedAt = &revoked
	if m.Record.Active(keyNow) {
		t.Error("a revoked key is active")
	}
}
