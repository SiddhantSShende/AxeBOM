package store_test

import (
	"context"
	"errors"
	"testing"

	"github.com/axebom/axebom/libs/go-shared/platform/db"
	"github.com/axebom/axebom/services/project/internal/hbom"
	"github.com/axebom/axebom/services/project/internal/store"
)

// cleanupDevices hard-deletes every device a test registered under a project.
//
// ⚠ NECESSARY BECAUSE createTestProject's CLEANUP IS A SOFT DELETE, so
// `ON DELETE CASCADE` never fires and each run leaves its devices behind — on
// the same screen these tests exist to prove works. Registered before the rows
// are created, so it runs even when the test fails partway.
func cleanupDevices(t *testing.T, pool *db.Pool, tenantID, projectID string) {
	t.Helper()
	t.Cleanup(func() {
		err := pool.WithTenant(context.Background(), tenantID,
			func(ctx context.Context, tx db.Tx) error {
				_, err := tx.Exec(ctx,
					`DELETE FROM project.hardware_devices WHERE project_id = $1`, projectID)
				return err
			})
		if err != nil {
			t.Logf("cleanup devices for project %s: %v", projectID, err)
		}
	})
}

// Against real Postgres, for the same reason the rest of this package is: the
// properties under test — RLS isolation, the two partial unique indexes, and
// the cross-schema parts summary — are properties of the DATABASE. A mock would
// assert that the code I wrote does what I wrote.

func TestADeviceRoundTripsAndCarriesNoPartsUntilSomeAreImported(t *testing.T) {
	pool := openPool(t)
	st := store.New(pool)
	projectID := createTestProject(t, st, tenantA)
	cleanupDevices(t, pool, tenantA, projectID)

	created, err := st.CreateDevice(t.Context(), tenantA, projectID, userA, &hbom.Device{
		Name: "Edge Gateway rev C", Manufacturer: "Encore Systems",
		ModelNumber: "ENC-GW-4400", SerialNumber: uniqueName(t),
		FirmwareVersion: "N3AET92W", Location: "Rack 4, Pune DC",
		Criticality: "critical",
	})
	if err != nil {
		t.Fatalf("create device: %v", err)
	}
	if created.ID == "" {
		t.Fatal("no id was returned")
	}

	// ⚠ THE ASSERTION THAT MATTERS MOST ON A FRESH DEVICE. Registering a device
	// and importing its parts are two acts. An empty PartsUpdatedAt is what
	// says "no parts list yet"; a zero ComponentCount alone would be
	// indistinguishable from a parts list that was read and found empty.
	if created.PartsUpdatedAt != "" || created.BOMDocumentID != "" {
		t.Errorf("a freshly registered device claims a parts list: doc=%q at=%q",
			created.BOMDocumentID, created.PartsUpdatedAt)
	}

	got, err := st.GetDevice(t.Context(), tenantA, projectID, created.ID)
	if err != nil {
		t.Fatalf("get device: %v", err)
	}
	if got.Name != "Edge Gateway rev C" || got.ModelNumber != "ENC-GW-4400" ||
		got.Criticality != "critical" || got.Location != "Rack 4, Pune DC" {
		t.Errorf("round trip lost a field: %+v", got)
	}

	list, err := st.ListDevices(t.Context(), tenantA, projectID)
	if err != nil {
		t.Fatalf("list devices: %v", err)
	}
	if len(list) != 1 || list[0].ID != created.ID {
		t.Fatalf("list returned %d devices, want the one just created", len(list))
	}
}

// TestTwoDevicesMayShareAModelButNotASerial.
//
// ⚠ THE ASYMMETRY IS THE POINT. Two units of the same product are the ordinary
// case and must be allowed; two records claiming the same serial are one
// physical device registered twice, which is a mistake worth refusing at the
// database rather than detecting later in a report.
func TestTwoDevicesMayShareAModelButNotASerial(t *testing.T) {
	pool := openPool(t)
	st := store.New(pool)
	projectID := createTestProject(t, st, tenantA)
	cleanupDevices(t, pool, tenantA, projectID)

	serial := uniqueName(t)
	if _, err := st.CreateDevice(t.Context(), tenantA, projectID, userA, &hbom.Device{
		Name: "unit 1", ModelNumber: "ENC-GW-4400", SerialNumber: serial,
	}); err != nil {
		t.Fatalf("first device: %v", err)
	}

	if _, err := st.CreateDevice(t.Context(), tenantA, projectID, userA, &hbom.Device{
		Name: "unit 2", ModelNumber: "ENC-GW-4400", SerialNumber: uniqueName(t),
	}); err != nil {
		t.Fatalf("a second unit of the same model was refused: %v", err)
	}

	_, err := st.CreateDevice(t.Context(), tenantA, projectID, userA, &hbom.Device{
		Name: "unit 1 again", ModelNumber: "ENC-GW-4400", SerialNumber: serial,
	})
	if !errors.Is(err, store.ErrSerialTaken) {
		t.Fatalf("a duplicate serial was accepted: err = %v", err)
	}
}

// TestManyDevicesMayHaveNoSerialAtAll.
//
// ⚠ THE PARTIAL INDEX IS WHAT MAKES THIS LEGAL, AND nullIfEmpty IS WHAT KEEPS
// IT WORKING. The index is `WHERE serial_number IS NOT NULL`; if the store
// wrote ” instead of NULL, the second unserialled board would be refused with
// "serial already taken" — a confusing lie about a field the user left blank.
func TestManyDevicesMayHaveNoSerialAtAll(t *testing.T) {
	pool := openPool(t)
	st := store.New(pool)
	projectID := createTestProject(t, st, tenantA)
	cleanupDevices(t, pool, tenantA, projectID)

	for i, name := range []string{"prototype A", "prototype B", "prototype C"} {
		if _, err := st.CreateDevice(t.Context(), tenantA, projectID, userA, &hbom.Device{
			Name: name,
		}); err != nil {
			t.Fatalf("device %d with no serial was refused: %v", i, err)
		}
	}
}

// TestADeviceFromAnotherProjectIsNotFound — the URL must not lie. RLS covers
// the cross-tenant case; this is the cross-PROJECT one, and it is 404 rather
// than 403 for the same reason (invariant 6: a 403 confirms the id exists).
func TestADeviceFromAnotherProjectIsNotFound(t *testing.T) {
	pool := openPool(t)
	st := store.New(pool)
	projectA := createTestProject(t, st, tenantA)
	projectB := createTestProject(t, st, tenantA)
	cleanupDevices(t, pool, tenantA, projectA)
	cleanupDevices(t, pool, tenantA, projectB)

	created, err := st.CreateDevice(t.Context(), tenantA, projectA, userA, &hbom.Device{Name: "in A"})
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	if _, err := st.GetDevice(t.Context(), tenantA, projectB, created.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("a device was readable through another project's path: err = %v", err)
	}
	if err := st.DeleteDevice(t.Context(), tenantA, projectB, created.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("a device was deletable through another project's path: err = %v", err)
	}
}

// TestDeviceCrossTenantAccessIsNotFound — RLS, not a WHERE clause.
func TestDeviceCrossTenantAccessIsNotFound(t *testing.T) {
	pool := openPool(t)
	st := store.New(pool)
	projectID := createTestProject(t, st, tenantA)
	cleanupDevices(t, pool, tenantA, projectID)

	created, err := st.CreateDevice(t.Context(), tenantA, projectID, userA, &hbom.Device{Name: "tenant A only"})
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	if _, err := st.GetDevice(t.Context(), tenantB, projectID, created.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("tenant B read tenant A's device: err = %v", err)
	}
}

// TestUpdateDeviceEditsRegistrationWithoutTouchingParts.
func TestUpdateDeviceEditsRegistrationWithoutTouchingParts(t *testing.T) {
	pool := openPool(t)
	st := store.New(pool)
	projectID := createTestProject(t, st, tenantA)
	cleanupDevices(t, pool, tenantA, projectID)

	created, err := st.CreateDevice(t.Context(), tenantA, projectID, userA, &hbom.Device{
		Name: "before", Location: "bench",
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	updated, err := st.UpdateDevice(t.Context(), tenantA, projectID, created.ID, &hbom.Device{
		Name: "after", Location: "Rack 9", Criticality: "high",
	})
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if updated.Name != "after" || updated.Location != "Rack 9" || updated.Criticality != "high" {
		t.Errorf("update did not apply: %+v", updated)
	}
	// ⚠ CLEARED, NOT KEPT. The update writes every editable column, so a field
	// omitted from the request is a field the caller cleared — the same
	// full-replacement semantics PUT implies everywhere else in this service.
	if updated.Notes != "" {
		t.Errorf("Notes = %q after an update that omitted it", updated.Notes)
	}
}

func TestDeletingADeviceHidesItFromTheList(t *testing.T) {
	pool := openPool(t)
	st := store.New(pool)
	projectID := createTestProject(t, st, tenantA)
	cleanupDevices(t, pool, tenantA, projectID)

	created, err := st.CreateDevice(t.Context(), tenantA, projectID, userA, &hbom.Device{
		Name: "retire me", SerialNumber: uniqueName(t),
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := st.DeleteDevice(t.Context(), tenantA, projectID, created.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}

	list, err := st.ListDevices(t.Context(), tenantA, projectID)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(list) != 0 {
		t.Fatalf("a deleted device is still listed: %d rows", len(list))
	}
	if _, err := st.GetDevice(t.Context(), tenantA, projectID, created.ID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("a deleted device is still readable: err = %v", err)
	}

	// ⚠ AND ITS SERIAL IS FREE AGAIN. The unique index is
	// `WHERE ... deleted_at IS NULL`, so retiring a unit and re-registering it
	// works — which is what happens when somebody registers a board twice and
	// deletes the wrong record.
	if _, err := st.CreateDevice(t.Context(), tenantA, projectID, userA, &hbom.Device{
		Name: "re-registered", SerialNumber: created.SerialNumber,
	}); err != nil {
		t.Errorf("a retired device's serial is still reserved: %v", err)
	}
}
