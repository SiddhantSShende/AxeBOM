package vault

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Paths are derived from server-side facts and are tenant-prefixed, which is
// what makes the ownership check possible at all.
func TestPathIsDeterministicAndTenantPrefixed(t *testing.T) {
	ref := Ref{TenantID: "tenant-a", Kind: KindRepoToken, ID: "conn-1"}

	first, err := ref.Path()
	if err != nil {
		t.Fatalf("path: %v", err)
	}
	second, _ := ref.Path()
	if first != second {
		t.Errorf("path is not deterministic: %q then %q", first, second)
	}
	if !strings.Contains(first, "tenant-a") {
		t.Errorf("path %q is not tenant-prefixed", first)
	}

	// A different tenant with the SAME id must land somewhere else, or one
	// tenant's connection would overwrite another's secret.
	other := Ref{TenantID: "tenant-b", Kind: KindRepoToken, ID: "conn-1"}
	otherPath, _ := other.Path()
	if otherPath == first {
		t.Error("two tenants derive the same path for the same id")
	}
}

// A separator in an identifier means something upstream is building a ref from
// user input — which is exactly when a traversal reaches Vault.
func TestPathRejectsTraversalAndControlCharacters(t *testing.T) {
	for _, bad := range []string{
		"../../root", "tenant/../other", "tenant%2f..", `tenant\..`,
		"tenant\x00", "tenant\nname", "with.dot",
	} {
		t.Run(bad, func(t *testing.T) {
			if _, err := (Ref{TenantID: bad, Kind: KindRepoToken, ID: "x"}).Path(); err == nil {
				t.Errorf("accepted tenant id %q", bad)
			}
			if _, err := (Ref{TenantID: "t", Kind: KindRepoToken, ID: bad}).Path(); err == nil {
				t.Errorf("accepted resource id %q", bad)
			}
		})
	}
}

func TestPathRejectsUnknownKindAndEmptyIdentifiers(t *testing.T) {
	cases := []Ref{
		{TenantID: "t", Kind: "arbitrary", ID: "x"},
		{TenantID: "", Kind: KindRepoToken, ID: "x"},
		{TenantID: "t", Kind: KindRepoToken, ID: ""},
	}
	for _, ref := range cases {
		if _, err := ref.Path(); err == nil {
			t.Errorf("accepted %+v", ref)
		}
	}
}

// ⚠ THE OWNERSHIP TEST.
//
// The service holds ONE Vault token with access to the whole mount, so a stored
// path is a read primitive. If a ref can be influenced — a mass-assignment bug,
// an import, an admin API — it must not become a way to read another tenant's
// secret.
func TestStoredRefIsNotACrossTenantReadPrimitive(t *testing.T) {
	m := NewMemory()

	refA := Ref{TenantID: "tenant-a", Kind: KindRepoToken, ID: "conn-1"}
	pathA, err := m.Put(t.Context(), refA, map[string]string{"token": "secret-a"})
	if err != nil {
		t.Fatalf("put: %v", err)
	}

	refB := Ref{TenantID: "tenant-b", Kind: KindRepoToken, ID: "conn-1"}
	if _, err := m.Get(t.Context(), refB, pathA); !errors.Is(err, ErrRefNotOwned) {
		t.Errorf("Get: err = %v, want ErrRefNotOwned", err)
	}
	if err := m.Delete(t.Context(), refB, pathA); !errors.Is(err, ErrRefNotOwned) {
		t.Errorf("Delete: err = %v, want ErrRefNotOwned", err)
	}

	// The secret survives the failed cross-tenant delete.
	got, err := m.Get(t.Context(), refA, pathA)
	if err != nil || got["token"] != "secret-a" {
		t.Errorf("the owner lost access after a refused cross-tenant delete: %v %v", got, err)
	}
}

func TestMemoryRoundTripAndDelete(t *testing.T) {
	m := NewMemory()
	ref := Ref{TenantID: "t", Kind: KindRepoToken, ID: "c"}

	path, err := m.Put(t.Context(), ref, map[string]string{"token": "abc"})
	if err != nil {
		t.Fatalf("put: %v", err)
	}
	got, err := m.Get(t.Context(), ref, path)
	if err != nil || got["token"] != "abc" {
		t.Fatalf("get = %v, %v", got, err)
	}
	if err := m.Delete(t.Context(), ref, path); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := m.Get(t.Context(), ref, path); !errors.Is(err, ErrNotFound) {
		t.Errorf("after delete: err = %v, want ErrNotFound", err)
	}
	// Deleting what is not there is success, so a retry after a partial
	// failure does not error.
	if err := m.Delete(t.Context(), ref, path); err != nil {
		t.Errorf("second delete: %v", err)
	}
}

// The stored map must be copied in and out, or a caller mutating its own map
// would silently change the stored secret.
func TestMemoryDoesNotShareMaps(t *testing.T) {
	m := NewMemory()
	ref := Ref{TenantID: "t", Kind: KindRepoToken, ID: "c"}

	in := map[string]string{"token": "original"}
	path, _ := m.Put(t.Context(), ref, in)
	in["token"] = "mutated"

	got, _ := m.Get(t.Context(), ref, path)
	if got["token"] != "original" {
		t.Error("mutating the caller's map changed the stored secret")
	}

	got["token"] = "mutated-again"
	again, _ := m.Get(t.Context(), ref, path)
	if again["token"] != "original" {
		t.Error("mutating a returned map changed the stored secret")
	}
}

// ---------------------------------------------------------------------------
// HTTP client
// ---------------------------------------------------------------------------

func TestClientPutGetDeleteAgainstAFakeVault(t *testing.T) {
	var lastMethod, lastPath, lastToken string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lastMethod, lastPath, lastToken = r.Method, r.URL.Path, r.Header.Get("X-Vault-Token")

		switch r.Method {
		case http.MethodPost:
			w.WriteHeader(http.StatusNoContent)
		case http.MethodGet:
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"data":{"data":{"token":"from-vault"}}}`))
		case http.MethodDelete:
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	defer srv.Close()

	c, err := New(Config{Address: srv.URL, Token: "test-token", Mount: "secret"})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	ref := Ref{TenantID: "tenant-a", Kind: KindRepoToken, ID: "conn-1"}

	path, err := c.Put(t.Context(), ref, map[string]string{"token": "abc"})
	if err != nil {
		t.Fatalf("put: %v", err)
	}
	if lastToken != "test-token" {
		t.Errorf("X-Vault-Token = %q", lastToken)
	}
	// KV v2 writes go to /data/. Missing the segment writes to the wrong
	// endpoint and reads back nothing.
	if !strings.Contains(lastPath, "/secret/data/") {
		t.Errorf("put path = %q, want the KV v2 /data/ endpoint", lastPath)
	}

	got, err := c.Get(t.Context(), ref, path)
	if err != nil || got["token"] != "from-vault" {
		t.Fatalf("get = %v, %v", got, err)
	}

	if err := c.Delete(t.Context(), ref, path); err != nil {
		t.Fatalf("delete: %v", err)
	}
	// Deletion must use /metadata/: deleting through /data/ soft-deletes the
	// latest version and leaves every prior version readable, so a "deleted"
	// credential would still be retrievable.
	if lastMethod != http.MethodDelete || !strings.Contains(lastPath, "/secret/metadata/") {
		t.Errorf("delete went to %s %q, want the /metadata/ endpoint", lastMethod, lastPath)
	}
}

// Vault error bodies can echo the path. A secret path in a log is a map for
// whoever reads the log, so only the status is reported.
func TestClientErrorsDoNotLeakThePath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"errors":["permission denied on ` + r.URL.Path + `"]}`))
	}))
	defer srv.Close()

	c, _ := New(Config{Address: srv.URL, Token: "t", Mount: "secret"})
	ref := Ref{TenantID: "tenant-a", Kind: KindRepoToken, ID: "conn-1"}

	_, err := c.Get(t.Context(), ref, "")
	if err == nil {
		t.Fatal("a 403 was treated as success")
	}
	if strings.Contains(err.Error(), "tenant-a") || strings.Contains(err.Error(), "conn-1") {
		t.Errorf("the error leaks the secret path: %v", err)
	}
}

func TestClientRequiresAddressAndToken(t *testing.T) {
	if _, err := New(Config{Token: "t"}); err == nil {
		t.Error("accepted an empty address")
	}
	if _, err := New(Config{Address: "http://localhost:8200"}); err == nil {
		t.Error("accepted an empty token")
	}
}

// A sealed Vault is reachable and useless. Readiness must say so rather than
// reporting healthy because the socket answered.
func TestPingTreatsSealedAsUnhealthy(t *testing.T) {
	tests := []struct {
		name      string
		status    int
		wantError bool
	}{
		{"active", http.StatusOK, false},
		{"standby", http.StatusTooManyRequests, false},
		{"sealed", http.StatusServiceUnavailable, true},
		{"uninitialized", http.StatusNotImplemented, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tt.status)
			}))
			defer srv.Close()

			c, _ := New(Config{Address: srv.URL, Token: "t"})
			err := c.Ping(t.Context())
			if tt.wantError && err == nil {
				t.Errorf("status %d reported healthy", tt.status)
			}
			if !tt.wantError && err != nil {
				t.Errorf("status %d reported unhealthy: %v", tt.status, err)
			}
		})
	}
}

// The memory fake must enforce the SAME ownership rule as the client. A fake
// that skips it would let a cross-tenant test pass while the product is
// vulnerable — worse than having no test.
func TestMemoryAndClientAgreeOnOwnership(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("the client contacted Vault despite a ref it does not own")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c, _ := New(Config{Address: srv.URL, Token: "t"})
	m := NewMemory()

	foreign := "axebom/tenants/tenant-a/repo-token/conn-1"
	ref := Ref{TenantID: "tenant-b", Kind: KindRepoToken, ID: "conn-1"}

	_, clientErr := c.Get(t.Context(), ref, foreign)
	_, memErr := m.Get(t.Context(), ref, foreign)

	if !errors.Is(clientErr, ErrRefNotOwned) || !errors.Is(memErr, ErrRefNotOwned) {
		t.Errorf("client %v, memory %v — both must be ErrRefNotOwned", clientErr, memErr)
	}
}
