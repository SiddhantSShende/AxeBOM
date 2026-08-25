package auth

import (
	"strings"
	"testing"
	"time"

	"github.com/axebom/axebom/libs/go-shared/authz"
)

func serviceIssuer(t *testing.T) *Issuer {
	t.Helper()
	i, err := NewIssuer(TokenConfig{
		SigningKey: []byte("a-signing-key-of-sufficient-length-for-hs256"),
		Issuer:     "axebom",
		AccessTTL:  15 * time.Minute,
		RefreshTTL: 24 * time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	return i
}

func TestAServiceTokenIsScopedToOneTenant(t *testing.T) {
	// ⚠ THERE IS NO CROSS-TENANT SERVICE TOKEN, and there must not be. The
	// campaign scheduler reads across tenants through one narrow SECURITY
	// DEFINER function and then acts inside each tenant separately; a wildcard
	// token would make that service the one component whose compromise reads
	// everything.
	i := serviceIssuer(t)

	if _, err := i.MintService("campaign", ""); err == nil {
		t.Fatal("a service token was minted with no tenant")
	}

	token, err := i.MintService("campaign", "tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	claims, err := i.VerifyAccess(token, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if claims.TenantID != "tenant-a" {
		t.Errorf("tenant = %q, want tenant-a", claims.TenantID)
	}
}

func TestAServiceTokenExpiresFastAndIsVerifiable(t *testing.T) {
	i := serviceIssuer(t)
	now := time.Now()

	token, err := i.MintService("campaign", "tenant-a")
	if err != nil {
		t.Fatal(err)
	}

	if _, err := i.VerifyAccess(token, now); err != nil {
		t.Fatalf("a fresh service token did not verify: %v", err)
	}

	// ⚠ THE ONLY CONTROL ON A LEAKED SERVICE TOKEN IS ITS TTL. It has no
	// session, so logging somebody out cannot revoke it.
	if _, err := i.VerifyAccess(token, now.Add(ServiceTokenTTL+time.Minute)); err == nil {
		t.Fatal("a service token outlived its TTL")
	}

	if ServiceTokenTTL > 5*time.Minute {
		t.Errorf("ServiceTokenTTL is %s; a bearer credential with no human behind "+
			"it and no revocation path should be minutes, not longer", ServiceTokenTTL)
	}
}

func TestAServiceSubjectCannotCollideWithAUser(t *testing.T) {
	// User ids are uuids, which contain no colon; the reserved prefix is what
	// makes "is this a person?" answerable from the subject alone.
	i := serviceIssuer(t)

	token, _ := i.MintService("campaign", "tenant-a")
	claims, err := i.VerifyAccess(token, time.Now())
	if err != nil {
		t.Fatal(err)
	}

	if !IsService(claims.Subject) {
		t.Fatalf("subject %q is not recognised as a service", claims.Subject)
	}
	if got := ServiceName(claims.Subject); got != "campaign" {
		t.Errorf("service name = %q, want campaign", got)
	}

	// A uuid subject is a person.
	if IsService("0199a3f4-1c2b-7e3d-9f10-2a4b6c8d0e1f") {
		t.Error("a uuid subject was read as a service")
	}
	if ServiceName("0199a3f4-1c2b-7e3d-9f10-2a4b6c8d0e1f") != "" {
		t.Error("a user id produced a service name")
	}
}

func TestAServiceNameWithAColonIsRefused(t *testing.T) {
	// The subject is `service:<name>`. A colon inside the name makes the parse
	// ambiguous, and an ambiguous parse is how one service impersonates another.
	i := serviceIssuer(t)
	if _, err := i.MintService("campaign:admin", "tenant-a"); err == nil {
		t.Fatal("a service name containing a colon was accepted")
	}
	if _, err := i.MintService("", "tenant-a"); err == nil {
		t.Fatal("an empty service name was accepted")
	}
}

func TestAServiceTokenCarriesTheLeastRoleThatWorks(t *testing.T) {
	// ⚠ ANALYST, NOT ADMIN. It is the minimum that holds (scan, run). Widening
	// it because some new call fails is the wrong fix — the right question is
	// whether a service should be making that call at all.
	i := serviceIssuer(t)
	token, _ := i.MintService("campaign", "tenant-a")
	claims, err := i.VerifyAccess(token, time.Now())
	if err != nil {
		t.Fatal(err)
	}

	if claims.Role != authz.RoleAnalyst {
		t.Fatalf("service role = %q, want analyst", claims.Role)
	}
	if !authz.Allow(claims.Role, authz.ResourceScan, authz.ActionRun).Allowed {
		t.Error("the service role cannot start a scan, which is its only purpose")
	}
	for _, forbidden := range []struct {
		res authz.Resource
		act authz.Action
	}{
		{authz.ResourceMember, authz.ActionInvite},
		{authz.ResourceTenant, authz.ActionUpdate},
		{authz.ResourceAuditLog, authz.ActionRead},
	} {
		if authz.Allow(claims.Role, forbidden.res, forbidden.act).Allowed {
			t.Errorf("a service token may (%s, %s); it should not",
				forbidden.res, forbidden.act)
		}
	}
}

func TestServiceTokensAreDistinct(t *testing.T) {
	// A reused jti would make two calls indistinguishable in an audit log.
	i := serviceIssuer(t)
	seen := map[string]bool{}
	for range 5 {
		token, err := i.MintService("campaign", "tenant-a")
		if err != nil {
			t.Fatal(err)
		}
		claims, err := i.VerifyAccess(token, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		if seen[claims.JTI] {
			t.Fatalf("jti %s was reused", claims.JTI)
		}
		seen[claims.JTI] = true
	}
}

func TestAServiceTokenIsNotForgeableWithAnotherKey(t *testing.T) {
	i := serviceIssuer(t)
	token, _ := i.MintService("campaign", "tenant-a")

	other, err := NewIssuer(TokenConfig{
		SigningKey: []byte("a-different-signing-key-of-sufficient-length"),
		Issuer:     "axebom",
		AccessTTL:  15 * time.Minute,
		RefreshTTL: 24 * time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := other.VerifyAccess(token, time.Now()); err == nil {
		t.Fatal("a token verified under a foreign key")
	}

	// And a tampered tenant does not verify.
	tampered := strings.Replace(token, ".", ".x", 1)
	if _, err := i.VerifyAccess(tampered, time.Now()); err == nil {
		t.Fatal("a tampered token verified")
	}
}
