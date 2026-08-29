package oidcauth_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/axebom/axebom/libs/go-shared/oidcauth"
)

// ⚠ WHAT THIS GUARDS THAT THE HERMETIC TESTS CANNOT.
//
// middleware_test.go mints its own tokens with a locally generated key and a
// httptest key set, so it proves the LOGIC. It cannot prove that a token a real
// ZITADEL issued is accepted by a real service, and the two failures that cost
// the most time in this integration were both invisible to it:
//
//   - the key set could not be fetched at all, because ZITADEL selects its
//     instance from the Host header and an in-network fetch answers 404. Every
//     service then refused every token with "could not be verified", which
//     reads as a client fault rather than an IdP one.
//   - the machine user's token carried no roles, because role assertion covers
//     application sign-in and a JWT-profile grant has no application.
//
// Both present as "authentication is broken everywhere" and neither shows up
// until a real token meets a real service.
//
// This talks to the running stack and SKIPS when there is not one — the same
// contract platform/db's RLS tests use, so a developer without compose up does
// not see a red suite they cannot fix.
func TestLiveAServiceTokenIsAcceptedByARealService(t *testing.T) {
	tok, gateway := liveServiceToken(t)

	// Any well-formed id. The project almost certainly does not exist, and
	// that is the point: an ACCEPTED token reaches the handler and gets the
	// handler's own 404, while a REJECTED one never gets that far and answers
	// 401. Distinguishing those two is the whole assertion, and it needs no
	// fixture data to be seeded first.
	const absent = "01900000-0000-7000-8000-0000000000ff"
	const tenant = "01900000-0000-7000-8000-00000000000a"

	t.Run("a verified service principal reaches the handler", func(t *testing.T) {
		code, body := get(t, gateway, absent, tok, tenant)
		if code == http.StatusUnauthorized || code == http.StatusForbidden {
			t.Fatalf("a real ZITADEL service token was refused: %d %s\n"+
				"the token itself verifies in TestServiceTokensCarryThePublicIssuer, "+
				"so look at the SERVICE's ZITADEL_ISSUER / ZITADEL_PROJECT_ID / "+
				"key-set reachability rather than at the token", code, body)
		}
		// NOTFOUND_PROJECT, not the generic NOTFOUND_RESOURCE: mapStoreError
		// (services/project/internal/service) maps a missing project to the
		// taxonomy's own specific code for exactly this case
		// (docs/02-CONTRACTS.md's NOTFOUND_ example is this code). What this
		// assertion actually guards is unchanged — an accepted token reaches the
		// handler's own 404 rather than the middleware's 401/403.
		if got := errorCode(body); got != "NOTFOUND_PROJECT" {
			t.Errorf("status %d code %q, want the handler's own NOTFOUND_PROJECT: %s",
				code, got, body)
		}
	})

	// A machine token's resource owner is the AxeBOM organisation, never the
	// customer. Guessing a tenant would be a cross-tenant read on every call
	// where the caller forgot to say.
	t.Run("a service principal that names no tenant is refused", func(t *testing.T) {
		code, body := get(t, gateway, absent, tok, "")
		if code != http.StatusUnauthorized {
			t.Errorf("status = %d, want 401: %s", code, body)
		}
		if got := errorCode(body); got != "AUTH_TENANT_CONTEXT_MISSING" {
			t.Errorf("code = %q, want AUTH_TENANT_CONTEXT_MISSING: %s", got, body)
		}
	})

	// The header is a statement of intent by an already-authenticated service,
	// not a credential. On its own it must buy exactly nothing — otherwise the
	// tenancy boundary is a header any client can set.
	t.Run("the tenant header alone grants nothing", func(t *testing.T) {
		code, body := get(t, gateway, absent, "", tenant)
		if code != http.StatusUnauthorized {
			t.Errorf("status = %d, want 401: %s", code, body)
		}
	})
}

// liveServiceToken mints a real token, skipping when the stack is absent.
func liveServiceToken(t *testing.T) (token, gateway string) {
	t.Helper()

	const keyPath = "../../../deploy/compose/.data/zitadel-bootstrap/service-keys/svc-fetcher.json"

	issuer := envOrSkip(t, "ZITADEL_ISSUER", "http://localhost:5173")
	gateway = envOrSkip(t, "AXEBOM_GATEWAY_URL", "http://localhost:8080")

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
		BaseURL:   envOrSkip(t, "ZITADEL_INTERNAL_URL", "http://localhost:58080"),
		Issuer:    issuer,
		ProjectID: projectID,
	})
	if err != nil {
		t.Fatalf("new source: %v", err)
	}
	token, err = src.Token(t.Context())
	if err != nil {
		t.Skipf("ZITADEL unavailable (%v) — run `task iam:up`", err)
	}
	return token, gateway
}

// get calls the service-only source endpoint through the gateway.
func get(t *testing.T, gateway, projectID, token, tenant string) (int, string) {
	t.Helper()

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet,
		gateway+"/v1/projects/"+projectID+"/source", nil)
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if tenant != "" {
		req.Header.Set(oidcauth.HeaderServiceTenant, tenant)
	}

	resp, err := (&http.Client{Timeout: 20 * time.Second}).Do(req)
	if err != nil {
		t.Skipf("the gateway at %s is unreachable (%v) — run `task dev`", gateway, err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<10))
	return resp.StatusCode, string(body)
}

// errorCode reads the stable machine code out of the canonical error envelope.
func errorCode(body string) string {
	var out struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	_ = json.Unmarshal([]byte(body), &out)
	return out.Error.Code
}
