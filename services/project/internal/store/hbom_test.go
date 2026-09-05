package store_test

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/axebom/axebom/libs/go-shared/platform/config"
	"github.com/axebom/axebom/libs/go-shared/platform/db"
	"github.com/axebom/axebom/services/project/internal/hbom"
	"github.com/axebom/axebom/services/project/internal/store"
)

// Against real Postgres — the properties under test (RLS isolation, the
// cross-schema document resolution, versioning on re-import) are properties
// of the database, matching the discipline service_test.go already uses in
// this service. SKIPS without one; CI always has one.

const (
	tenantA = "01900000-0000-7000-8000-00000000000a"
	tenantB = "01900000-0000-7000-8000-00000000000b"
	userA   = "01900000-0000-7000-8000-0000000000a1"
)

func openPool(t *testing.T) *db.Pool {
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
	return pool
}

func uniqueName(t *testing.T) string {
	t.Helper()
	return strings.ToLower(strings.ReplaceAll(t.Name(), "/", "-")) +
		"-" + time.Now().Format("150405.000000000")
}

// createTestProject inserts a minimal project directly via the store's own
// CreateProject and registers a cleanup.
//
// ⚠ THE CLEANUP IS A SOFT DELETE, AND THIS COMMENT USED TO CALL IT A HARD ONE.
// store.DeleteProject sets `deleted_at`, so `ON DELETE CASCADE` never fires:
// every child row a test creates SURVIVES the test. That went unnoticed while
// the only children were in `normalize.*` (cleaned up explicitly below), and
// stopped being invisible the moment project.hardware_devices existed — the dev
// database accumulated 44 devices from one afternoon's test runs, on the very
// screen those tests exist to prove works.
//
// Anything a test creates under a project must therefore clean itself up. See
// cleanupDevices.
func createTestProject(t *testing.T, st *store.Store, tenantID string) string {
	t.Helper()
	p, err := st.CreateProject(t.Context(), store.Project{
		TenantID: tenantID, Name: uniqueName(t),
		SourceType: "manual", SDLCStage: "source", CreatedBy: userA,
	})
	if err != nil {
		t.Fatalf("create project: %v", err)
	}
	t.Cleanup(func() {
		_ = st.DeleteProject(context.Background(), tenantID, p.ID)
	})
	return p.ID
}

// cleanupHBOMDocuments removes every normalize.bom_documents row (and, via
// CASCADE, its hardware_components) this test created for a project — there
// is no FK from project.projects to make this automatic.
func cleanupHBOMDocuments(t *testing.T, pool *db.Pool, tenantID, projectID string) {
	t.Helper()
	t.Cleanup(func() {
		err := pool.WithTenant(context.Background(), tenantID, func(ctx context.Context, tx db.Tx) error {
			_, err := tx.Exec(ctx, `DELETE FROM normalize.bom_documents WHERE scan_id = $1 AND bom_type = 'HBOM'`, projectID)
			return err
		})
		if err != nil {
			t.Logf("cleanup hbom documents for project %s: %v", projectID, err)
		}
	})
}

func TestReplaceHardwareTreeRoundTripsThroughGetHardwareTree(t *testing.T) {
	pool := openPool(t)
	st := store.New(pool)
	projectID := createTestProject(t, st, tenantA)
	cleanupHBOMDocuments(t, pool, tenantA, projectID)

	root := &hbom.Component{
		ProductName: "Gateway", ModelNumber: "GW-1", Compliance: []string{"RoHS", "CE"},
		Children: []*hbom.Component{
			{ProductName: "Mainboard", ModelNumber: "MB-1", Criticality: "high"},
		},
	}

	docID, err := st.ReplaceHardwareTree(t.Context(), tenantA, projectID, []*hbom.Component{root})
	if err != nil {
		t.Fatalf("ReplaceHardwareTree: %v", err)
	}
	if docID == "" {
		t.Fatal("expected a document id")
	}

	roots, err := st.GetHardwareTree(t.Context(), tenantA, projectID)
	if err != nil {
		t.Fatalf("GetHardwareTree: %v", err)
	}
	if len(roots) != 1 {
		t.Fatalf("roots = %d, want 1", len(roots))
	}
	if roots[0].ProductName != "Gateway" || roots[0].ID == "" {
		t.Errorf("root = %+v", roots[0])
	}
	if got, want := roots[0].Compliance, []string{"RoHS", "CE"}; !equalStrings(got, want) {
		t.Errorf("compliance = %v, want %v", got, want)
	}
	if len(roots[0].Children) != 1 || roots[0].Children[0].ProductName != "Mainboard" {
		t.Fatalf("children = %+v", roots[0].Children)
	}
	if roots[0].Children[0].Criticality != "high" {
		t.Errorf("child criticality = %q, want high", roots[0].Children[0].Criticality)
	}
	if roots[0].Children[0].ParentID != roots[0].ID {
		t.Errorf("child parent id = %q, want %q", roots[0].Children[0].ParentID, roots[0].ID)
	}
}

func TestGetHardwareTreeIsAnEmptyListBeforeAnyImport(t *testing.T) {
	pool := openPool(t)
	st := store.New(pool)
	projectID := createTestProject(t, st, tenantA)
	cleanupHBOMDocuments(t, pool, tenantA, projectID)

	roots, err := st.GetHardwareTree(t.Context(), tenantA, projectID)
	if err != nil {
		t.Fatalf("GetHardwareTree: %v", err)
	}
	if len(roots) != 0 {
		t.Errorf("roots = %v, want none — no import has happened yet", roots)
	}
}

func TestReImportCreatesANewVersionRatherThanMutating(t *testing.T) {
	pool := openPool(t)
	st := store.New(pool)
	projectID := createTestProject(t, st, tenantA)
	cleanupHBOMDocuments(t, pool, tenantA, projectID)

	first := &hbom.Component{ProductName: "V1", ModelNumber: "V1"}
	if _, err := st.ReplaceHardwareTree(t.Context(), tenantA, projectID, []*hbom.Component{first}); err != nil {
		t.Fatalf("first import: %v", err)
	}

	second := &hbom.Component{ProductName: "V2", ModelNumber: "V2"}
	docID2, err := st.ReplaceHardwareTree(t.Context(), tenantA, projectID, []*hbom.Component{second})
	if err != nil {
		t.Fatalf("second import: %v", err)
	}

	roots, err := st.GetHardwareTree(t.Context(), tenantA, projectID)
	if err != nil {
		t.Fatalf("GetHardwareTree: %v", err)
	}
	if len(roots) != 1 || roots[0].ProductName != "V2" {
		t.Fatalf("roots = %+v, want only the second import's tree", roots)
	}

	// The first version's document must still exist, untouched — versions are
	// retained, never overwritten (CLAUDE.md invariant 10).
	var count int
	err = pool.WithTenant(t.Context(), tenantA, func(ctx context.Context, tx db.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT count(*) FROM normalize.bom_documents WHERE scan_id = $1 AND bom_type = 'HBOM'`,
			projectID).Scan(&count)
	})
	if err != nil {
		t.Fatalf("count documents: %v", err)
	}
	if count != 2 {
		t.Errorf("document count = %d, want 2 (both versions retained)", count)
	}
	_ = docID2
}

func TestSaveHardwareComponentUpdatesInPlace(t *testing.T) {
	pool := openPool(t)
	st := store.New(pool)
	projectID := createTestProject(t, st, tenantA)
	cleanupHBOMDocuments(t, pool, tenantA, projectID)

	root := &hbom.Component{ProductName: "Gateway", ModelNumber: "GW-1"}
	if _, err := st.ReplaceHardwareTree(t.Context(), tenantA, projectID, []*hbom.Component{root}); err != nil {
		t.Fatalf("import: %v", err)
	}
	roots, err := st.GetHardwareTree(t.Context(), tenantA, projectID)
	if err != nil {
		t.Fatalf("GetHardwareTree: %v", err)
	}
	saved := roots[0]
	saved.Criticality = "critical"
	saved.WarrantyAMC = "3 years on-site"

	out, err := st.SaveHardwareComponent(t.Context(), tenantA, projectID, saved)
	if err != nil {
		t.Fatalf("SaveHardwareComponent: %v", err)
	}
	if out.ID != saved.ID {
		t.Errorf("id changed on update: got %q, want %q", out.ID, saved.ID)
	}

	roots, err = st.GetHardwareTree(t.Context(), tenantA, projectID)
	if err != nil {
		t.Fatalf("GetHardwareTree: %v", err)
	}
	if len(roots) != 1 {
		t.Fatalf("update must not create a second root: got %d", len(roots))
	}
	if roots[0].Criticality != "critical" || roots[0].WarrantyAMC != "3 years on-site" {
		t.Errorf("update was not persisted: %+v", roots[0])
	}
}

func TestSaveHardwareComponentRejectsAnIDFromAnotherProject(t *testing.T) {
	pool := openPool(t)
	st := store.New(pool)
	projectA := createTestProject(t, st, tenantA)
	projectB := createTestProject(t, st, tenantA)
	cleanupHBOMDocuments(t, pool, tenantA, projectA)
	cleanupHBOMDocuments(t, pool, tenantA, projectB)

	root := &hbom.Component{ProductName: "Belongs to A", ModelNumber: "A-1"}
	if _, err := st.ReplaceHardwareTree(t.Context(), tenantA, projectA, []*hbom.Component{root}); err != nil {
		t.Fatalf("import into project A: %v", err)
	}
	rootsA, err := st.GetHardwareTree(t.Context(), tenantA, projectA)
	if err != nil {
		t.Fatalf("GetHardwareTree A: %v", err)
	}

	// A copied id from project A, submitted against project B.
	forged := rootsA[0]
	forged.ProductName = "Hijacked"

	_, err = st.SaveHardwareComponent(t.Context(), tenantA, projectB, forged)
	if !errors.Is(err, store.ErrComponentNotFound) {
		t.Fatalf("error = %v, want ErrComponentNotFound", err)
	}

	// And project A's row must be unchanged.
	rootsA, err = st.GetHardwareTree(t.Context(), tenantA, projectA)
	if err != nil {
		t.Fatalf("GetHardwareTree A after attempted hijack: %v", err)
	}
	if rootsA[0].ProductName != "Belongs to A" {
		t.Errorf("project A's component was mutated by a request scoped to project B: %+v", rootsA[0])
	}
}

func TestHardwareTreeCrossTenantAccessIsNotFound(t *testing.T) {
	pool := openPool(t)
	st := store.New(pool)
	projectID := createTestProject(t, st, tenantA)
	cleanupHBOMDocuments(t, pool, tenantA, projectID)

	root := &hbom.Component{ProductName: "Secret", ModelNumber: "S-1"}
	if _, err := st.ReplaceHardwareTree(t.Context(), tenantA, projectID, []*hbom.Component{root}); err != nil {
		t.Fatalf("import: %v", err)
	}

	_, err := st.GetHardwareTree(t.Context(), tenantB, projectID)
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("error = %v, want ErrNotFound for a project id belonging to another tenant", err)
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestAlternatesRoundTripThroughSaveAndGet.
//
// ⚠ THE API CARRIED THIS FIELD IN BOTH DIRECTIONS AND THE STORE IN NEITHER.
//
// componentDTO has mapped `alternates` out (toAlternateDTOs) and in
// (fromAlternateDTOs) since the manufacturing fields landed, and
// normalize.hardware_component_alternates was written only by the Python
// normalize pipeline and read only by the report service. So a SCANNED
// hardware BOM had alternates and an EDITED one silently did not: the save
// returned 200 and discarded them, and every read returned `[]`.
func TestAlternatesRoundTripThroughSaveAndGet(t *testing.T) {
	pool := openPool(t)
	st := store.New(pool)
	projectID := createTestProject(t, st, tenantA)
	cleanupHBOMDocuments(t, pool, tenantA, projectID)

	root := &hbom.Component{ProductName: "Gateway", ModelNumber: "GW-1"}
	if _, err := st.ReplaceHardwareTree(t.Context(), tenantA, projectID, []*hbom.Component{root}); err != nil {
		t.Fatalf("import: %v", err)
	}
	roots, err := st.GetHardwareTree(t.Context(), tenantA, projectID)
	if err != nil {
		t.Fatalf("GetHardwareTree: %v", err)
	}

	saved := roots[0]
	saved.Alternates = []hbom.Alternate{
		{ManufacturerName: "Panasonic", ModelNumber: "ERJ-2RKF1002X", SupplierSKU: "P10.0KDACT-ND", Equivalence: "drop-in"},
		{ManufacturerName: "Vishay", ModelNumber: "CRCW040210K0FKED"},
	}
	if _, err := st.SaveHardwareComponent(t.Context(), tenantA, projectID, saved); err != nil {
		t.Fatalf("SaveHardwareComponent: %v", err)
	}

	roots, err = st.GetHardwareTree(t.Context(), tenantA, projectID)
	if err != nil {
		t.Fatalf("GetHardwareTree: %v", err)
	}
	got := roots[0].Alternates
	if len(got) != 2 {
		t.Fatalf("alternates did not round-trip: got %d, want 2 (%+v)", len(got), got)
	}
	if got[0].ModelNumber != "ERJ-2RKF1002X" || got[0].Equivalence != "drop-in" {
		t.Errorf("first alternate is wrong: %+v", got[0])
	}
	// ⚠ AN ALTERNATE WITH NO STATED EQUIVALENCE IS `unverified`, NEVER
	// SOMETHING STRONGER. A blank field in a spreadsheet must not become an
	// approved substitution.
	if got[1].Equivalence != "unverified" {
		t.Errorf("an unstated equivalence became %q, want %q", got[1].Equivalence, "unverified")
	}
	if got[0].Ordinal != 0 || got[1].Ordinal != 1 {
		t.Errorf("ordinals were not preserved: %d, %d", got[0].Ordinal, got[1].Ordinal)
	}
}

// TestRemovingAnAlternateActuallyRemovesIt.
//
// ⚠ AN UPSERT-ONLY WRITE PATH WOULD PASS THE ROUND-TRIP TEST ABOVE AND FAIL
// THIS ONE. Alternates are an ordered set belonging to one component, so
// deleting a second source in the editor has to delete the row — otherwise
// every alternate ever added accumulates and an obsolete part looks
// second-sourced when it is not.
func TestRemovingAnAlternateActuallyRemovesIt(t *testing.T) {
	pool := openPool(t)
	st := store.New(pool)
	projectID := createTestProject(t, st, tenantA)
	cleanupHBOMDocuments(t, pool, tenantA, projectID)

	root := &hbom.Component{
		ProductName: "Gateway",
		Alternates: []hbom.Alternate{
			{ManufacturerName: "Panasonic", ModelNumber: "A"},
			{ManufacturerName: "Vishay", ModelNumber: "B"},
		},
	}
	if _, err := st.ReplaceHardwareTree(t.Context(), tenantA, projectID, []*hbom.Component{root}); err != nil {
		t.Fatalf("import: %v", err)
	}
	roots, err := st.GetHardwareTree(t.Context(), tenantA, projectID)
	if err != nil {
		t.Fatalf("GetHardwareTree: %v", err)
	}
	if len(roots[0].Alternates) != 2 {
		t.Fatalf("import did not store both alternates: %+v", roots[0].Alternates)
	}

	saved := roots[0]
	saved.Alternates = saved.Alternates[:1]
	if _, err := st.SaveHardwareComponent(t.Context(), tenantA, projectID, saved); err != nil {
		t.Fatalf("SaveHardwareComponent: %v", err)
	}

	roots, err = st.GetHardwareTree(t.Context(), tenantA, projectID)
	if err != nil {
		t.Fatalf("GetHardwareTree: %v", err)
	}
	if len(roots[0].Alternates) != 1 {
		t.Fatalf("removing an alternate left %d behind: %+v", len(roots[0].Alternates), roots[0].Alternates)
	}
	if roots[0].Alternates[0].ModelNumber != "A" {
		t.Errorf("the wrong alternate survived: %+v", roots[0].Alternates[0])
	}
}

// TestEditingManufacturingFieldsActuallyPersists.
//
// ⚠ THE UPDATE STATEMENT SET ONLY THE CERT-In COLUMNS. Quantity, designators,
// footprint, SKU, supplier, price, currency, DNP, assembly type, lifecycle and
// datasheet were writable on CREATE and silently unwritable on EDIT: the API
// accepted them, returned 200, and left the stored value untouched. Nothing
// failed and nothing said so.
func TestEditingManufacturingFieldsActuallyPersists(t *testing.T) {
	pool := openPool(t)
	st := store.New(pool)
	projectID := createTestProject(t, st, tenantA)
	cleanupHBOMDocuments(t, pool, tenantA, projectID)

	root := &hbom.Component{ProductName: "Resistor", Quantity: 1}
	if _, err := st.ReplaceHardwareTree(t.Context(), tenantA, projectID, []*hbom.Component{root}); err != nil {
		t.Fatalf("import: %v", err)
	}
	roots, err := st.GetHardwareTree(t.Context(), tenantA, projectID)
	if err != nil {
		t.Fatalf("GetHardwareTree: %v", err)
	}

	saved := roots[0]
	saved.Quantity = 12
	saved.Designators = []string{"R1", "R4", "R17"}
	saved.PackageFootprint = "0402"
	saved.SupplierSKU = "311-10.0KLRCT-ND"
	saved.PreferredSupplier = "Digi-Key"
	saved.UnitPrice = "0.003400"
	saved.Currency = "USD"
	saved.AssemblyType = "smt"
	saved.LifecycleStatus = "active"
	saved.DoNotPopulate = true

	if _, err := st.SaveHardwareComponent(t.Context(), tenantA, projectID, saved); err != nil {
		t.Fatalf("SaveHardwareComponent: %v", err)
	}

	roots, err = st.GetHardwareTree(t.Context(), tenantA, projectID)
	if err != nil {
		t.Fatalf("GetHardwareTree: %v", err)
	}
	got := roots[0]
	if got.Quantity != 12 {
		t.Errorf("quantity did not persist: got %d, want 12", got.Quantity)
	}
	if strings.Join(got.Designators, ",") != "R1,R4,R17" {
		t.Errorf("designators did not persist: %v", got.Designators)
	}
	if got.PackageFootprint != "0402" || got.SupplierSKU != "311-10.0KLRCT-ND" {
		t.Errorf("procurement fields did not persist: %+v", got)
	}
	if got.UnitPrice != "0.003400" {
		t.Errorf("unit price did not persist exactly: got %q, want %q", got.UnitPrice, "0.003400")
	}
	if !got.DoNotPopulate {
		t.Error("the do-not-populate flag did not persist")
	}
	if got.AssemblyType != "smt" || got.LifecycleStatus != "active" {
		t.Errorf("assembly/lifecycle did not persist: %+v", got)
	}
}
