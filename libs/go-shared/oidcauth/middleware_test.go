package oidcauth_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/axebom/axebom/libs/go-shared/authz"
	"github.com/axebom/axebom/libs/go-shared/oidcauth"
	"github.com/axebom/axebom/libs/go-shared/platform/ctxkey"

	jose "github.com/go-jose/go-jose/v4"
)

// These tests are the specification for the identity bridge.
//
// Everything here is hermetic: a locally generated key, a locally served JWKS,
// and tokens minted in-process. No ZITADEL, no database. The claim SHAPES were
// taken from a real token minted against a live v4.17.1 instance — in
// particular the roles claim, which two ZITADEL documentation pages render
// differently and which is an object, not an array.

const (
	testIssuer  = "http://localhost:5173"
	testProject = "387580691908395029"
	acmeOrg     = "387580692495597589"
	betaOrg     = "387580731989164053"
)

type fixture struct {
	verifier *oidcauth.Verifier
	key      *rsa.PrivateKey
	kid      string
}

func newFixture(t *testing.T) *fixture {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	const kid = "test-key-1"

	jwks := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
		Key: key.Public(), KeyID: kid, Algorithm: string(jose.RS256), Use: "sig",
	}}}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jwks)
	}))
	t.Cleanup(srv.Close)

	v, err := oidcauth.NewVerifier(oidcauth.Config{
		Issuer:    testIssuer,
		JWKSURL:   srv.URL,
		ProjectID: testProject,
	})
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}
	return &fixture{verifier: v, key: key, kid: kid}
}

// mint signs an access token with the given claims.
func (f *fixture) mint(t *testing.T, claims map[string]any) string {
	t.Helper()
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: f.key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", f.kid),
	)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	obj, err := signer.Sign(payload)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	s, err := obj.CompactSerialize()
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}
	return s
}

// humanClaims is a token for a person, shaped exactly like a real one.
func humanClaims(sub string, roles map[string]map[string]string, homeOrg string) map[string]any {
	now := time.Now()
	return map[string]any{
		"iss":                                   testIssuer,
		"sub":                                   sub,
		"aud":                                   []string{testProject},
		"iat":                                   now.Add(-time.Minute).Unix(),
		"nbf":                                   now.Add(-time.Minute).Unix(),
		"exp":                                   now.Add(10 * time.Minute).Unix(),
		"urn:zitadel:iam:user:resourceowner:id": homeOrg,
		"urn:zitadel:iam:user:resourceowner:name":               "Acme Industries",
		"urn:zitadel:iam:org:project:" + testProject + ":roles": roles,
		"email":          "alice@acme.test",
		"email_verified": true,
		"name":           "Alice Owner",
	}
}

// stubResolver records what it was asked and answers deterministically.
type stubResolver struct{ last oidcauth.ResolveRequest }

func (s *stubResolver) Resolve(_ context.Context, in oidcauth.ResolveRequest) (oidcauth.Principal, error) {
	s.last = in
	return oidcauth.Principal{
		TenantID: "01900000-0000-7000-8000-00000000000a",
		UserID:   "01900000-0000-7000-8000-0000000000a1",
		Role:     in.Role,
	}, nil
}

// capture runs the middleware and reports the context it produced.
func capture(t *testing.T, f *fixture, r oidcauth.Resolver, req *http.Request) (int, string, string, string) {
	t.Helper()
	var tenant, user, role string
	h := oidcauth.Authenticate(f.verifier, r, nil)(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			tenant, _ = ctxkey.TenantID(r.Context())
			user = ctxkey.UserID(r.Context())
			role = ctxkey.Role(r.Context())
			w.WriteHeader(http.StatusOK)
		}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code, tenant, user, role
}

func authed(token string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/v1/projects", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	return req
}

func TestAValidTokenPopulatesTheTenantContext(t *testing.T) {
	f := newFixture(t)
	tok := f.mint(t, humanClaims("387580726016606229",
		map[string]map[string]string{"owner": {acmeOrg: "acme.localhost"}}, acmeOrg))

	code, tenant, user, role := capture(t, f, &stubResolver{}, authed(tok))
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200", code)
	}
	if tenant != "01900000-0000-7000-8000-00000000000a" {
		t.Errorf("tenant = %q", tenant)
	}
	if user != "01900000-0000-7000-8000-0000000000a1" {
		t.Errorf("user = %q", user)
	}
	if role != string(authz.RoleOwner) {
		t.Errorf("role = %q, want owner", role)
	}
}

// ⚠ THE TENANT MUST NEVER COME FROM A HEADER ON A PERSON'S REQUEST.
//
// X-AxeBOM-Tenant exists for service principals. If a human token could set
// it, the header would BE the tenancy boundary and every RLS policy in the
// product would be advisory.
func TestTenantHeaderIsIgnoredForHumans(t *testing.T) {
	f := newFixture(t)
	tok := f.mint(t, humanClaims("387580726016606229",
		map[string]map[string]string{"owner": {acmeOrg: "acme.localhost"}}, acmeOrg))

	req := authed(tok)
	req.Header.Set(oidcauth.HeaderServiceTenant, "01900000-0000-7000-8000-00000000000b")

	stub := &stubResolver{}
	code, tenant, _, _ := capture(t, f, stub, req)
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200", code)
	}
	if stub.last.OrgID != acmeOrg {
		t.Errorf("resolved org = %q, want the org from the TOKEN (%s)", stub.last.OrgID, acmeOrg)
	}
	if tenant == "01900000-0000-7000-8000-00000000000b" {
		t.Fatal("the header selected the tenant; the tenancy boundary is broken")
	}
}

// The org header may only narrow to something the token already grants.
func TestOrgHeaderCannotGrantAnOrgTheTokenDoesNot(t *testing.T) {
	f := newFixture(t)
	tok := f.mint(t, humanClaims("387580726016606229",
		map[string]map[string]string{"owner": {acmeOrg: "acme.localhost"}}, acmeOrg))

	req := authed(tok)
	req.Header.Set(oidcauth.HeaderOrg, betaOrg)

	code, _, _, _ := capture(t, f, &stubResolver{}, req)
	if code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 — the caller has no role in that org", code)
	}
}

// Carol: analyst in Acme, viewer in Beta. One human, two tenants, two roles.
func TestAMultiOrgUserSelectsTheirOrgAndGetsThatOrgsRole(t *testing.T) {
	f := newFixture(t)
	roles := map[string]map[string]string{
		"analyst": {acmeOrg: "acme.localhost"},
		"viewer":  {betaOrg: "beta.localhost"},
	}
	tok := f.mint(t, humanClaims("387580730026229781", roles, acmeOrg))

	req := authed(tok)
	req.Header.Set(oidcauth.HeaderOrg, betaOrg)

	stub := &stubResolver{}
	code, _, _, role := capture(t, f, stub, req)
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200", code)
	}
	if stub.last.OrgID != betaOrg {
		t.Errorf("org = %q, want beta", stub.last.OrgID)
	}
	if role != string(authz.RoleViewer) {
		t.Errorf("role = %q, want viewer — the role is per TENANT, not per user", role)
	}
}

// ⚠ AMBIGUITY IS REFUSED, NOT GUESSED. Picking one would make the answer
// depend on map iteration order — a different tenant's data on every request.
func TestAMultiOrgUserWhoNamesNoOrgIsRefused(t *testing.T) {
	f := newFixture(t)
	roles := map[string]map[string]string{
		"analyst": {acmeOrg: "acme.localhost"},
		"viewer":  {betaOrg: "beta.localhost"},
	}
	// Home org deliberately absent from the roles map, so there is no
	// defensible fallback.
	tok := f.mint(t, humanClaims("387580730026229781", roles, "999999"))

	// ⚠ 409, NOT 401. The token is perfect; the account is ambiguous. A 401
	// would tell the client to throw the token away and log in again, which
	// returns an identical token and asks the identical question — a loop.
	rec := run(t, f, &stubResolver{}, authed(tok))
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409", rec.Code)
	}
	if got := errorCodeOf(t, rec); got != "AUTH_ORG_AMBIGUOUS" {
		t.Fatalf("code = %q, want AUTH_ORG_AMBIGUOUS", got)
	}
}

// A token minted for a different application on the same instance is a VALID
// ZITADEL token. Accepting it is cross-application privilege escalation.
func TestATokenForAnotherProjectIsRejected(t *testing.T) {
	f := newFixture(t)
	claims := humanClaims("387580726016606229",
		map[string]map[string]string{"owner": {acmeOrg: "acme.localhost"}}, acmeOrg)
	claims["aud"] = []string{"some-other-project"}

	code, _, _, _ := capture(t, f, &stubResolver{}, authed(f.mint(t, claims)))
	if code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", code)
	}
}

func TestAnExpiredTokenIsRejected(t *testing.T) {
	f := newFixture(t)
	claims := humanClaims("387580726016606229",
		map[string]map[string]string{"owner": {acmeOrg: "acme.localhost"}}, acmeOrg)
	claims["exp"] = time.Now().Add(-time.Minute).Unix()

	code, _, _, _ := capture(t, f, &stubResolver{}, authed(f.mint(t, claims)))
	if code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", code)
	}
}

func TestATokenFromAnotherIssuerIsRejected(t *testing.T) {
	f := newFixture(t)
	claims := humanClaims("387580726016606229",
		map[string]map[string]string{"owner": {acmeOrg: "acme.localhost"}}, acmeOrg)
	claims["iss"] = "http://evil.example"

	code, _, _, _ := capture(t, f, &stubResolver{}, authed(f.mint(t, claims)))
	if code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", code)
	}
}

// The classic JWT forgery: strip the signature and claim the algorithm is none.
func TestAnUnsignedTokenIsRejected(t *testing.T) {
	f := newFixture(t)
	// {"alg":"none"} . {claims} . <empty>
	const unsigned = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0." +
		"eyJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjUxNzMiLCJzdWIiOiJhdHRhY2tlciJ9."

	code, _, _, _ := capture(t, f, &stubResolver{}, authed(unsigned))
	if code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", code)
	}
}

func TestATokenInTheQueryStringIsNotAccepted(t *testing.T) {
	f := newFixture(t)
	tok := f.mint(t, humanClaims("387580726016606229",
		map[string]map[string]string{"owner": {acmeOrg: "acme.localhost"}}, acmeOrg))

	req := httptest.NewRequest(http.MethodGet, "/v1/projects?access_token="+tok, nil)
	code, _, _, _ := capture(t, f, &stubResolver{}, req)
	if code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 — a token in a URL outlives the request", code)
	}
}

// A service principal names its target tenant on the request, because a machine
// token's resource owner is the machine's own organisation.
func TestAServicePrincipalActsForTheNamedTenant(t *testing.T) {
	f := newFixture(t)
	claims := humanClaims("387580734069538837",
		map[string]map[string]string{"service": {"387579833485426709": "axebom.localhost"}},
		"387579833485426709")
	claims["name"] = "svc-fetcher"

	req := authed(f.mint(t, claims))
	req.Header.Set(oidcauth.HeaderServiceTenant, "01900000-0000-7000-8000-00000000000b")

	code, tenant, user, role := capture(t, f, &stubResolver{}, req)
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200", code)
	}
	if tenant != "01900000-0000-7000-8000-00000000000b" {
		t.Errorf("tenant = %q, want the named tenant", tenant)
	}
	if user != oidcauth.ServiceSubjectPrefix+"svc-fetcher" {
		t.Errorf("user = %q, want the service: prefix that RequireService checks for", user)
	}
	if role != string(authz.RoleAnalyst) {
		t.Errorf("role = %q, want analyst", role)
	}
}

func TestAServicePrincipalWithoutATenantIsRefused(t *testing.T) {
	f := newFixture(t)
	claims := humanClaims("387580734069538837",
		map[string]map[string]string{"service": {"387579833485426709": "axebom.localhost"}},
		"387579833485426709")

	code, _, _, _ := capture(t, f, &stubResolver{}, authed(f.mint(t, claims)))
	if code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 — a service must say who it is acting for", code)
	}
}

func TestNoBearerTokenIsRejected(t *testing.T) {
	f := newFixture(t)
	req := httptest.NewRequest(http.MethodGet, "/v1/projects", nil)
	code, _, _, _ := capture(t, f, &stubResolver{}, req)
	if code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", code)
	}
}

// ---------------------------------------------------------------- expiry code

// An expired token must be DISTINGUISHABLE from an invalid one.
//
// The client's correct response differs: renew and retry versus sign in again.
// Collapsing the two sends a user with a fifteen-minute token through a full
// login every fifteen minutes, and nothing is leaked by saying so — the caller
// is holding the token and can read `exp` itself.
func TestAnExpiredTokenSaysSo(t *testing.T) {
	f := newFixture(t)
	claims := humanClaims("387580726016606229",
		map[string]map[string]string{"owner": {acmeOrg: "acme.localhost"}}, acmeOrg)
	claims["exp"] = time.Now().Add(-time.Minute).Unix()

	rec := run(t, f, &stubResolver{}, authed(f.mint(t, claims)))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if got := errorCodeOf(t, rec); got != "AUTH_TOKEN_EXPIRED" {
		t.Fatalf("code = %q, want AUTH_TOKEN_EXPIRED", got)
	}
}

// Everything that is not expiry stays a single opaque code, so a forged token
// cannot be used to probe which part of it was wrong.
func TestAForgedTokenIsNotToldWhySpecifically(t *testing.T) {
	f := newFixture(t)
	claims := humanClaims("387580726016606229",
		map[string]map[string]string{"owner": {acmeOrg: "acme.localhost"}}, acmeOrg)
	claims["iss"] = "http://evil.example"

	rec := run(t, f, &stubResolver{}, authed(f.mint(t, claims)))
	if got := errorCodeOf(t, rec); got != "AUTH_TOKEN_INVALID" {
		t.Fatalf("code = %q, want AUTH_TOKEN_INVALID", got)
	}
}

// ------------------------------------------------------------ websocket auth

// A browser cannot put an Authorization header on a WebSocket handshake, so the
// token arrives as an offered subprotocol.
func TestAWebSocketHandshakeMayCarryTheTokenAsASubprotocol(t *testing.T) {
	f := newFixture(t)
	tok := f.mint(t, humanClaims("387580726016606229",
		map[string]map[string]string{"owner": {acmeOrg: "acme.localhost"}}, acmeOrg))

	req := httptest.NewRequest(http.MethodGet, "/v1/scans/abc/progress", nil)
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Sec-WebSocket-Protocol",
		oidcauth.WSSubprotocol+", "+oidcauth.WSBearerPrefix+tok)

	code, tenant, _, role := capture(t, f, &stubResolver{}, req)
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200", code)
	}
	if tenant == "" || role != string(authz.RoleOwner) {
		t.Fatalf("tenant = %q role = %q, want a populated context", tenant, role)
	}
}

// ⚠ THE SUBPROTOCOL IS READ ONLY ON A REAL UPGRADE. Otherwise it becomes a
// second, unaudited way to present a credential on any request at all.
func TestTheSubprotocolIsIgnoredWithoutAnUpgrade(t *testing.T) {
	f := newFixture(t)
	tok := f.mint(t, humanClaims("387580726016606229",
		map[string]map[string]string{"owner": {acmeOrg: "acme.localhost"}}, acmeOrg))

	req := httptest.NewRequest(http.MethodGet, "/v1/projects", nil)
	req.Header.Set("Sec-WebSocket-Protocol", oidcauth.WSBearerPrefix+tok)

	code, _, _, _ := capture(t, f, &stubResolver{}, req)
	if code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 — an ordinary request must not be authenticated by a subprotocol", code)
	}
}

// The Authorization header always wins, so a socket that can send one is not
// silently authenticated by a stale subprotocol value.
func TestTheAuthorizationHeaderTakesPrecedenceOverTheSubprotocol(t *testing.T) {
	f := newFixture(t)
	good := f.mint(t, humanClaims("387580726016606229",
		map[string]map[string]string{"owner": {acmeOrg: "acme.localhost"}}, acmeOrg))

	req := httptest.NewRequest(http.MethodGet, "/v1/scans/abc/progress", nil)
	req.Header.Set("Authorization", "Bearer "+good)
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Sec-WebSocket-Protocol", oidcauth.WSBearerPrefix+"not-a-token")

	code, _, _, _ := capture(t, f, &stubResolver{}, req)
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200", code)
	}
}

// ------------------------------------------------------------------- helpers

func run(t *testing.T, f *fixture, r oidcauth.Resolver, req *http.Request) *httptest.ResponseRecorder {
	t.Helper()
	h := oidcauth.Authenticate(f.verifier, r, nil)(http.HandlerFunc(
		func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func errorCodeOf(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var body struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode error body %q: %v", rec.Body.String(), err)
	}
	return body.Error.Code
}
