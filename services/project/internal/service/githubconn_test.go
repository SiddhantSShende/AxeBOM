package service_test

import (
	"context"
	"strings"
	"testing"

	"github.com/axebom/axebom/libs/go-shared/platform/errs"
	"github.com/axebom/axebom/libs/go-shared/vault"
	"github.com/axebom/axebom/services/project/internal/service"
)

// cleanupGitHubConnection removes the tenant-wide row a test created.
//
// ⚠ TENANT-SCOPED, SO IT DOES NOT CASCADE FROM A PROJECT. Every other fixture
// here is cleaned up by deleting its project; this row outlives them all, and
// leaving it behind would make the next test's "not connected" assertion fail
// for a reason that has nothing to do with the code under test.
func cleanupGitHubConnection(t *testing.T, f *fixture, tenantID string) {
	t.Helper()
	t.Cleanup(func() {
		// ⚠ context.Background(), NOT t.Context() — the same reason
		// cleanupProject spells out. t.Context() is already CANCELLED by the
		// time cleanups run, so the disconnect failed with "context canceled",
		// the row survived, and the next test in the package found the tenant
		// already connected. It failed loudly rather than silently, which is
		// the only reason this was a five-minute bug instead of a confusing
		// one — the "already connected" assertion is worth keeping for exactly
		// that.
		if err := f.svc.DisconnectGitHub(context.Background(), tenantID); err != nil {
			t.Logf("cleanup github connection for %s: %v", tenantID, err)
		}
	})
}

// TestGitHubIsConnectedOnceAndReusedByEveryProject is the ask, verified.
//
// ⚠ EVERY REGISTRATION USED TO OPEN ITS OWN OAUTH POPUP. useGitHubConnect took
// a repo-scoped token by postMessage and handed it through the browser to the
// connection endpoint, which stored it against that ONE project. Nothing kept
// it, so three projects meant three authorisations — and every repo search sent
// the token back out through the browser again.
func TestGitHubIsConnectedOnceAndReusedByEveryProject(t *testing.T) {
	f := newFixture(t)
	cleanupGitHubConnection(t, f, tenantA)

	before, err := f.svc.GitHubConnection(t.Context(), tenantA)
	if err != nil {
		t.Fatalf("status before connecting: %v", err)
	}
	if before.Connected {
		t.Fatal("the tenant was already connected; the fixture is not isolated")
	}

	status, err := f.svc.ConnectGitHub(t.Context(), tenantA, userA, "gho_test_token", "acme-bot")
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	if !status.Connected || status.GitHubLogin != "acme-bot" {
		t.Errorf("status = %+v, want connected as acme-bot", status)
	}

	// The point: a SECOND project needs no second authorisation.
	after, err := f.svc.GitHubConnection(t.Context(), tenantA)
	if err != nil {
		t.Fatalf("status after connecting: %v", err)
	}
	if !after.Connected {
		t.Error("the connection did not survive; every project would authorise again")
	}

	token, err := f.svc.GitHubToken(t.Context(), tenantA)
	if err != nil {
		t.Fatalf("the stored token could not be read back: %v", err)
	}
	if token != "gho_test_token" {
		t.Errorf("token = %q, want the one that was stored", token)
	}
}

// TestTheGitHubTokenIsNeverInTheStatus.
//
// ⚠ THE WHOLE POINT IS THAT THE BROWSER STOPS HOLDING A GITHUB CREDENTIAL. A
// status endpoint that returned the token — or the Vault path to it — would
// hand it back on every page load, which is worse than the per-project popup it
// replaced.
func TestTheGitHubTokenIsNeverInTheStatus(t *testing.T) {
	f := newFixture(t)
	cleanupGitHubConnection(t, f, tenantA)

	const secret = "gho_this_must_not_leak"
	status, err := f.svc.ConnectGitHub(t.Context(), tenantA, userA, secret, "acme-bot")
	if err != nil {
		t.Fatalf("connect: %v", err)
	}

	rendered := status.GitHubLogin + " " + status.ConnectedAt
	if strings.Contains(rendered, secret) {
		t.Error("the token appears in the connection status")
	}
	if strings.Contains(rendered, "axebom/tenants/") {
		t.Error("the Vault path appears in the connection status")
	}
}

// TestOneTenantsGitHubConnectionIsInvisibleToAnother is invariant 6 on a table
// whose primary key is the tenant id — the shape where a forgotten RLS policy
// would be least obvious, because every query looks tenant-free.
func TestOneTenantsGitHubConnectionIsInvisibleToAnother(t *testing.T) {
	f := newFixture(t)
	cleanupGitHubConnection(t, f, tenantA)

	if _, err := f.svc.ConnectGitHub(t.Context(), tenantA, userA, "gho_a", "acme-bot"); err != nil {
		t.Fatalf("connect A: %v", err)
	}

	other, err := f.svc.GitHubConnection(t.Context(), tenantB)
	if err != nil {
		t.Fatalf("status for B: %v", err)
	}
	if other.Connected {
		t.Fatal("tenant B sees tenant A's GitHub connection")
	}
	if _, err := f.svc.GitHubToken(t.Context(), tenantB); err == nil {
		t.Fatal("tenant B read tenant A's GitHub token")
	}
}

// Reconnecting replaces the one connection rather than failing on the key, and
// the new token is the one that is read back — an expired authorisation is
// repaired by connecting again, so this is the common path, not an edge case.
func TestReconnectingReplacesTheToken(t *testing.T) {
	f := newFixture(t)
	cleanupGitHubConnection(t, f, tenantA)

	if _, err := f.svc.ConnectGitHub(t.Context(), tenantA, userA, "gho_old", "old-bot"); err != nil {
		t.Fatalf("first connect: %v", err)
	}
	if _, err := f.svc.ConnectGitHub(t.Context(), tenantA, userA, "gho_new", "new-bot"); err != nil {
		t.Fatalf("reconnect: %v", err)
	}

	token, err := f.svc.GitHubToken(t.Context(), tenantA)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if token != "gho_new" {
		t.Errorf("token = %q, want the reconnected one", token)
	}
}

// Disconnecting leaves the tenant in the state it started in, and asking for a
// token then says what to do rather than failing opaquely.
func TestDisconnectingRemovesTheConnectionAndTheToken(t *testing.T) {
	f := newFixture(t)
	cleanupGitHubConnection(t, f, tenantA)

	if _, err := f.svc.ConnectGitHub(t.Context(), tenantA, userA, "gho_x", "acme-bot"); err != nil {
		t.Fatalf("connect: %v", err)
	}
	if err := f.svc.DisconnectGitHub(t.Context(), tenantA); err != nil {
		t.Fatalf("disconnect: %v", err)
	}

	status, err := f.svc.GitHubConnection(t.Context(), tenantA)
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if status.Connected {
		t.Error("the connection survived a disconnect")
	}

	_, err = f.svc.GitHubToken(t.Context(), tenantA)
	if err == nil {
		t.Fatal("a token was returned after disconnecting")
	}
	if !errs.Is(err, errs.ValidationFieldRequired) {
		t.Errorf("code = %s, want %s", errs.From(err).Code, errs.ValidationFieldRequired)
	}
	if !strings.Contains(err.Error(), "Connect it once") {
		t.Errorf("the error does not say what to do: %v", err)
	}

	// Disconnecting twice is not an error: the customer's intent is already
	// satisfied, and failing would suggest it had not been.
	if err := f.svc.DisconnectGitHub(t.Context(), tenantA); err != nil {
		t.Errorf("second disconnect: %v", err)
	}
}

// TestConnectingARepoWithNoTokenUsesTheOrganisationCredential.
//
// ⚠ AN EMPTY TOKEN USED TO MEAN "PUBLIC REPOSITORY", AND CONNECT-ONCE BREAKS
// THAT ASSUMPTION. The wizard used to hand Connect the token from its own OAuth
// popup; with the organisation connected, the browser never holds one. Left
// alone, every repository picked on the connect-once path would have been
// stored as a public connection — cloning fine in a test against a public repo
// and failing at scan time, with no credential, for every private one.
func TestConnectingARepoWithNoTokenUsesTheOrganisationCredential(t *testing.T) {
	f := newFixture(t)
	cleanupGitHubConnection(t, f, tenantA)
	p := createProjectFromSource(t, f, tenantA, "github")

	if _, err := f.svc.ConnectGitHub(t.Context(), tenantA, userA, "gho_org_token", "acme-bot"); err != nil {
		t.Fatalf("connect github: %v", err)
	}

	conn, err := f.svc.Connect(t.Context(), tenantA, p.ID, service.ConnectInput{
		Provider: "github", RepoURL: "https://github.com/acme/widget",
		RepoExternalID: "12345", DefaultBranch: "main",
		// No token: the browser has none on the connect-once path.
	})
	if err != nil {
		t.Fatalf("connect repo: %v", err)
	}
	if conn.CredentialRef == "" {
		t.Fatal("the connection was stored with no credential; every private " +
			"repository picked this way would fail at scan time")
	}

	secret, err := f.vault.Get(t.Context(),
		vault.Ref{TenantID: tenantA, Kind: vault.KindRepoToken, ID: conn.ID}, conn.CredentialRef)
	if err != nil {
		t.Fatalf("read the connection credential: %v", err)
	}
	if secret["token"] != "gho_org_token" {
		t.Errorf("stored token = %q, want the organisation's", secret["token"])
	}
}

// With no organisation connection, an empty token still means "public
// repository" — the original behaviour, which must survive.
func TestConnectingARepoWithNoTokenAndNoOrgConnectionStaysPublic(t *testing.T) {
	f := newFixture(t)
	cleanupGitHubConnection(t, f, tenantA)
	p := createProjectFromSource(t, f, tenantA, "github")

	conn, err := f.svc.Connect(t.Context(), tenantA, p.ID, service.ConnectInput{
		Provider: "github", RepoURL: "https://github.com/acme/public",
		RepoExternalID: "999", DefaultBranch: "main",
	})
	if err != nil {
		t.Fatalf("connect repo: %v", err)
	}
	if conn.CredentialRef != "" {
		t.Errorf("a public connection gained a credential ref: %q", conn.CredentialRef)
	}
}
