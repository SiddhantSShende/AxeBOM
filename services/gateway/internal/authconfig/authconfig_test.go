package authconfig_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/encorebom/encorebom/libs/go-shared/oidcauth"
	"github.com/encorebom/encorebom/libs/go-shared/platform/config"
	"github.com/encorebom/encorebom/services/gateway/internal/authconfig"
)

const (
	issuer    = "http://localhost:5173"
	projectID = "387580691908395029"
	clientID  = "387580692277559317"
)

func configured() config.OIDC {
	return config.OIDC{Issuer: issuer, ProjectID: projectID, SPAClientID: clientID}
}

// The audience scope is the one that cannot be omitted: without it ZITADEL
// mints a token whose audience is the client id alone, and every service
// refuses it — a login that succeeds followed by an application that 401s.
func TestTheDocumentRequestsTheProjectAudience(t *testing.T) {
	doc := authconfig.Build(configured())
	want := oidcauth.AudienceScope(projectID)
	if !slices.Contains(doc.Scopes, want) {
		t.Fatalf("scopes = %v, want one of them to be %q", doc.Scopes, want)
	}
}

// The claim names are published so the SPA never writes a ZITADEL URN of its
// own. If these drift from the verifier, the browser reads an empty roles map
// and every multi-tenant user loses their organisation switcher.
func TestTheClaimNamesMatchTheVerifier(t *testing.T) {
	doc := authconfig.Build(configured())
	if doc.OrgClaim != oidcauth.ClaimOrgID {
		t.Errorf("org claim = %q, want %q", doc.OrgClaim, oidcauth.ClaimOrgID)
	}
	wantRoles := "urn:zitadel:iam:org:project:" + projectID + ":roles"
	if doc.RolesClaim != wantRoles {
		t.Errorf("roles claim = %q, want %q", doc.RolesClaim, wantRoles)
	}
	if doc.OrgHeader != oidcauth.HeaderOrg {
		t.Errorf("org header = %q, want %q", doc.OrgHeader, oidcauth.HeaderOrg)
	}
}

// ⚠ NOTHING SECRET MAY APPEAR HERE. The endpoint is unauthenticated by
// necessity, so this test is the guard against a future field that assumes
// otherwise.
func TestTheDocumentCarriesNoSecret(t *testing.T) {
	cfg := configured()
	cfg.InternalURL = "http://zitadel-api:8080"
	cfg.ServiceKeyPath = "/var/run/encorebom/service-keys/svc-campaign.json"

	rec := serve(t, cfg)
	body := rec.Body.String()
	for _, forbidden := range []string{cfg.InternalURL, cfg.ServiceKeyPath, "secret", "key"} {
		if strings.Contains(strings.ToLower(body), strings.ToLower(forbidden)) {
			t.Fatalf("document contains %q:\n%s", forbidden, body)
		}
	}
}

// A half-provisioned gateway must say so here. The alternative is a redirect to
// an authorize URL with an empty client_id and a ZITADEL error page that names
// neither variable.
func TestAnUnprovisionedGatewayRefusesRatherThanServingAnEmptyDocument(t *testing.T) {
	rec := serve(t, config.OIDC{Issuer: issuer})
	// 500: this is our own misconfiguration, not the caller's mistake, and the
	// INTERNAL_ prefix in the error taxonomy says so.
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "iam bootstrap") {
		t.Fatalf("the error should name the command that fixes it:\n%s", rec.Body.String())
	}
}

// An operator who re-provisions identity must not have to wait out a cache
// before anyone can log in again.
func TestTheDocumentIsNotCached(t *testing.T) {
	rec := serve(t, configured())
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", got)
	}
}

func TestTheDocumentRoundTripsAsJSON(t *testing.T) {
	rec := serve(t, configured())
	var doc authconfig.Document
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if doc.Issuer != issuer || doc.ClientID != clientID || doc.ProjectID != projectID {
		t.Fatalf("document = %+v", doc)
	}
}

func serve(t *testing.T, cfg config.OIDC) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	authconfig.Handler(cfg)(rec, httptest.NewRequest(http.MethodGet, "/v1/auth/config", nil))
	return rec
}
