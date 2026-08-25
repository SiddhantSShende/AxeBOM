package oidcauth_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/axebom/axebom/libs/go-shared/oidcauth"
)

// ⚠ THE ONE THING THAT CANNOT BE TESTED HERMETICALLY.
//
// ZITADEL derives the `iss` claim from the host of the request that asked for
// the token, and the whole service-token design turns on overriding that host.
// A fake token endpoint would happily agree with whatever we assumed. So this
// test talks to a real instance, and SKIPS when there is not one — the same
// contract the DB-backed tests use, for the same reason: a developer without
// the stack running should not see a red suite they cannot fix.
func TestServiceTokensCarryThePublicIssuer(t *testing.T) {
	const (
		keyPath = "../../../deploy/compose/.data/zitadel-bootstrap/service-keys/svc-fetcher.json"
		baseURL = "http://localhost:58080"
	)

	issuer := envOrSkip(t, "ZITADEL_ISSUER", "http://localhost:5173")
	projectID := os.Getenv("ZITADEL_PROJECT_ID")
	if projectID == "" {
		t.Skip("ZITADEL_PROJECT_ID is not set — run `task iam:bootstrap`")
	}
	abs, _ := filepath.Abs(keyPath)
	if _, err := os.Stat(abs); err != nil {
		t.Skipf("no service key at %s — run `task iam:bootstrap`", abs)
	}

	src, err := oidcauth.NewServiceTokenSource(oidcauth.ServiceTokenConfig{
		KeyPath:   abs,
		BaseURL:   baseURL,
		Issuer:    issuer,
		ProjectID: projectID,
	})
	if err != nil {
		t.Fatalf("new source: %v", err)
	}

	token, err := src.Token(t.Context())
	if err != nil {
		t.Skipf("ZITADEL unavailable (%v) — run `task iam:up`", err)
	}

	// The verifier is configured for the PUBLIC issuer. If the Host override
	// were missing, ZITADEL would have minted `iss: http://localhost:58080`
	// and this would fail — which is precisely the regression being guarded.
	v, err := oidcauth.NewVerifier(oidcauth.Config{
		Issuer:    issuer,
		JWKSURL:   baseURL + "/oauth/v2/keys",
		ProjectID: projectID,
	})
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}

	id, err := v.Verify(t.Context(), token)
	if err != nil {
		t.Fatalf("a token minted through :58080 did not verify against the public "+
			"issuer %s — the Host override is not working: %v", issuer, err)
	}
	if !id.Service {
		t.Errorf("the machine user's token does not carry the %q role; "+
			"RequireService would refuse it", oidcauth.ServiceRoleKey)
	}
}

func envOrSkip(t *testing.T, key, fallback string) string {
	t.Helper()
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
