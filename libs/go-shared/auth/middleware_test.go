package auth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/axebom/axebom/libs/go-shared/authz"
	"github.com/axebom/axebom/libs/go-shared/platform/ctxkey"
)

// captured records what a handler saw, so tests can assert on the context the
// middleware built rather than on the response alone.
type captured struct {
	reached  bool
	tenantID string
	userID   string
	role     string
	needsRes bool
}

func handlerCapturing(c *captured) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.reached = true
		c.tenantID, _ = ctxkey.TenantID(r.Context())
		c.userID = ctxkey.UserID(r.Context())
		c.role = ctxkey.Role(r.Context())
		c.needsRes = NeedsResourceCheck(r.Context())
		w.WriteHeader(http.StatusOK)
	})
}

func authedRequest(t *testing.T, i *Issuer, tenant string, role authz.Role) *http.Request {
	t.Helper()
	token, _, err := i.IssueAccess(time.Now(), "user-1", tenant, "sess-1", role)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	return req
}

// The tenant that reaches the context — and therefore Postgres RLS — must come
// from the verified token.
func TestAuthenticatePopulatesContextFromToken(t *testing.T) {
	i := testIssuer(t)
	var c captured

	Authenticate(i, nil)(handlerCapturing(&c)).
		ServeHTTP(httptest.NewRecorder(), authedRequest(t, i, "tenant-a", authz.RoleAnalyst))

	if !c.reached {
		t.Fatal("handler was not reached")
	}
	if c.tenantID != "tenant-a" || c.userID != "user-1" || c.role != "analyst" {
		t.Errorf("context = tenant %q user %q role %q", c.tenantID, c.userID, c.role)
	}
}

// A header or query parameter must NOT be able to choose the tenant. If it
// could, any caller could read any tenant's data, because this value is what
// db.WithTenantFromContext hands to RLS.
func TestTenantCannotBeSetByHeaderOrQuery(t *testing.T) {
	i := testIssuer(t)
	var c captured

	req := authedRequest(t, i, "tenant-a", authz.RoleViewer)
	req.Header.Set("X-Tenant-ID", "tenant-b")
	req.Header.Set("X-Tenant", "tenant-b")
	req.URL.RawQuery = "tenant_id=tenant-b&tid=tenant-b"

	Authenticate(i, nil)(handlerCapturing(&c)).ServeHTTP(httptest.NewRecorder(), req)

	if c.tenantID != "tenant-a" {
		t.Fatalf("tenant was overridden by request input: got %q, want tenant-a", c.tenantID)
	}
}

func TestMissingOrMalformedAuthorizationRejected(t *testing.T) {
	i := testIssuer(t)

	cases := []struct{ name, header string }{
		{"absent", ""},
		{"no scheme", "abc.def.ghi"},
		{"wrong scheme", "Basic dXNlcjpwYXNz"},
		{"empty bearer", "Bearer "},
		{"bearer only", "Bearer"},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			var c captured
			req := httptest.NewRequest(http.MethodGet, "/x", nil)
			if tt.header != "" {
				req.Header.Set("Authorization", tt.header)
			}
			rec := httptest.NewRecorder()
			Authenticate(i, nil)(handlerCapturing(&c)).ServeHTTP(rec, req)

			if c.reached {
				t.Error("handler was reached without a valid token")
			}
			if rec.Code != http.StatusUnauthorized {
				t.Errorf("status = %d, want 401", rec.Code)
			}
		})
	}
}

// A token in a query string leaks into access logs, proxy logs, browser
// history and Referer headers. It must not be accepted there.
func TestTokenInQueryStringNotAccepted(t *testing.T) {
	i := testIssuer(t)
	token, _, _ := i.IssueAccess(time.Now(), "u", "tenant-a", "s", authz.RoleOwner)

	var c captured
	req := httptest.NewRequest(http.MethodGet, "/x?access_token="+token+"&token="+token, nil)
	rec := httptest.NewRecorder()
	Authenticate(i, nil)(handlerCapturing(&c)).ServeHTTP(rec, req)

	if c.reached {
		t.Fatal("a token supplied via the query string was accepted")
	}
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

func TestExpiredTokenGivesRefreshableCode(t *testing.T) {
	i := testIssuer(t)
	token, _, _ := i.IssueAccess(time.Now().Add(-2*time.Hour), "u", "t", "s", authz.RoleViewer)

	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	var c captured
	Authenticate(i, nil)(handlerCapturing(&c)).ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	var body struct {
		Error struct{ Code string } `json:"error"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	// The client needs to distinguish "refresh me" from "log in again".
	if body.Error.Code != "AUTH_TOKEN_EXPIRED" {
		t.Errorf("code = %q, want AUTH_TOKEN_EXPIRED", body.Error.Code)
	}
}

// ---------------------------------------------------------------------------
// Authorize
// ---------------------------------------------------------------------------

func TestAuthorizeEnforcesTheMatrix(t *testing.T) {
	i := testIssuer(t)

	tests := []struct {
		role       authz.Role
		resource   authz.Resource
		action     authz.Action
		wantStatus int
	}{
		{authz.RoleViewer, authz.ResourceProject, authz.ActionRead, http.StatusOK},
		{authz.RoleViewer, authz.ResourceProject, authz.ActionCreate, http.StatusForbidden},
		{authz.RoleAnalyst, authz.ResourceProject, authz.ActionCreate, http.StatusOK},
		{authz.RoleAnalyst, authz.ResourceAuditLog, authz.ActionList, http.StatusForbidden},
		{authz.RoleAdmin, authz.ResourceAuditLog, authz.ActionList, http.StatusOK},
		{authz.RoleAdmin, authz.ResourceTenant, authz.ActionUpdate, http.StatusForbidden},
		{authz.RoleOwner, authz.ResourceTenant, authz.ActionUpdate, http.StatusOK},
	}

	for _, tt := range tests {
		var c captured
		h := Authenticate(i, nil)(Authorize(tt.resource, tt.action)(handlerCapturing(&c)))

		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, authedRequest(t, i, "tenant-a", tt.role))

		if rec.Code != tt.wantStatus {
			t.Errorf("%s %s:%s -> %d, want %d",
				tt.role, tt.resource, tt.action, rec.Code, tt.wantStatus)
		}
		if (rec.Code == http.StatusOK) != c.reached {
			t.Errorf("%s %s:%s: handler reached=%v but status=%d",
				tt.role, tt.resource, tt.action, c.reached, rec.Code)
		}
	}
}

// A route wrapped in Authorize but NOT Authenticate is a wiring bug. It must
// fail closed rather than treat "no role" as permissive.
func TestAuthorizeWithoutAuthenticateFailsClosed(t *testing.T) {
	var c captured
	rec := httptest.NewRecorder()

	Authorize(authz.ResourceProject, authz.ActionRead)(handlerCapturing(&c)).
		ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/x", nil))

	if c.reached {
		t.Fatal("handler was reached with no authenticated role")
	}
	if rec.Code == http.StatusOK {
		t.Fatalf("status = %d; a missing role must not be permissive", rec.Code)
	}
}

// An unregistered permission must be denied even for an owner — the matrix
// fails closed, so a new endpoint is denied until somebody decides on it.
func TestUnregisteredPermissionDeniedThroughMiddleware(t *testing.T) {
	i := testIssuer(t)
	var c captured

	h := Authenticate(i, nil)(
		Authorize(authz.Resource("brand_new_thing"), authz.ActionRead)(handlerCapturing(&c)))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, authedRequest(t, i, "tenant-a", authz.RoleOwner))

	if c.reached {
		t.Fatal("an unregistered permission reached the handler")
	}
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", rec.Code)
	}
}

// Report download is the one conditional permission. The middleware must tell
// the handler so, or a handler checking only `Allowed` would serve a private
// report to a Viewer.
func TestConditionalPermissionIsSignalledToHandler(t *testing.T) {
	i := testIssuer(t)

	var c captured
	Authenticate(i, nil)(Authorize(authz.ResourceReport, authz.ActionDownload)(handlerCapturing(&c))).
		ServeHTTP(httptest.NewRecorder(), authedRequest(t, i, "tenant-a", authz.RoleViewer))

	if !c.reached {
		t.Fatal("viewer should reach the handler to have the resource checked")
	}
	if !c.needsRes {
		t.Error("handler was not told the decision is conditional — it would " +
			"serve a private report to a viewer")
	}

	// An unconditional permission must not set it, or handlers learn to ignore it.
	var c2 captured
	Authenticate(i, nil)(Authorize(authz.ResourceProject, authz.ActionRead)(handlerCapturing(&c2))).
		ServeHTTP(httptest.NewRecorder(), authedRequest(t, i, "tenant-a", authz.RoleViewer))
	if c2.needsRes {
		t.Error("an unconditional permission set NeedsResourceCheck")
	}
}

// A denial should say what was refused, so support does not need a debugger.
func TestDenialCarriesActionableDetail(t *testing.T) {
	i := testIssuer(t)
	rec := httptest.NewRecorder()

	Authenticate(i, nil)(Authorize(authz.ResourceTenant, authz.ActionUpdate)(
		http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))).
		ServeHTTP(rec, authedRequest(t, i, "tenant-a", authz.RoleViewer))

	var body struct {
		Error struct {
			Code    string           `json:"code"`
			Message string           `json:"message"`
			Details []map[string]any `json:"details"`
		} `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("response is not the canonical error shape: %v", err)
	}
	if body.Error.Code != "PERM_ROLE_INSUFFICIENT" {
		t.Errorf("code = %q", body.Error.Code)
	}
	if len(body.Error.Details) == 0 || body.Error.Details[0]["resource"] != "tenant" {
		t.Errorf("details should name the resource: %+v", body.Error.Details)
	}
}

func TestRequireTenant(t *testing.T) {
	if _, err := RequireTenant(t.Context()); err == nil {
		t.Error("RequireTenant must fail with no tenant in context")
	}
	ctx := ctxkey.WithTenantID(t.Context(), "tenant-a")
	got, err := RequireTenant(ctx)
	if err != nil || got != "tenant-a" {
		t.Errorf("got (%q, %v)", got, err)
	}
}
