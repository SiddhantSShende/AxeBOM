package service_test

import (
	"context"
	"strings"
	"testing"

	"github.com/axebom/axebom/libs/go-shared/platform/db"
	"github.com/axebom/axebom/libs/go-shared/platform/errs"
	"github.com/axebom/axebom/services/project/internal/hbom"
	"github.com/axebom/axebom/services/project/internal/qbom"
)

// TestADeviceCannotBeRegisteredAgainstAnSBOMOnlyProject is the defect this
// milestone was named for, proven against the real database rather than against
// the registry in isolation.
//
// ⚠ THIS SUCCEEDED BEFORE. The row was written, the device appeared on the
// hardware screen, and no report the project could generate would ever contain
// it — because the project produces an SBOM and a device is hardware. Nothing
// in the service, the store or the schema had an opinion about it.
func TestADeviceCannotBeRegisteredAgainstAnSBOMOnlyProject(t *testing.T) {
	f := newFixture(t)
	p := createProject(t, f, tenantA) // SBOM, upload

	_, err := f.svc.CreateDevice(t.Context(), tenantA, p.ID, userA, &hbom.Device{
		Name: "a gateway that does not belong here",
	})
	if err == nil {
		t.Fatal("a hardware device was registered against an SBOM-only project")
	}
	if !errs.Is(err, errs.ProjectNotClassified) {
		t.Errorf("code = %s, want %s", errs.From(err).Code, errs.ProjectNotClassified)
	}
	// 409, not 404: the project exists and the caller may see it. A 404 would
	// send them hunting for a project that is right there.
	if got := errs.From(err).HTTPStatus(); got != 409 {
		t.Errorf("status = %d, want 409", got)
	}
}

// The same call on a project that IS classified for hardware must work, or the
// gate has simply broken the feature.
func TestADeviceRegistersAgainstAnHBOMProject(t *testing.T) {
	f := newFixture(t)
	p := createProjectFromSource(t, f, tenantA, "manual", "HBOM")
	cleanupDevicesFor(t, f, tenantA, p.ID)

	d, err := f.svc.CreateDevice(t.Context(), tenantA, p.ID, userA, &hbom.Device{
		Name: "gateway-" + uniqueName(t),
	})
	if err != nil {
		t.Fatalf("a device was refused on a hardware project: %v", err)
	}
	if d.ID == "" {
		t.Error("the device was accepted but has no id")
	}
}

// A project classified for both is a real shape — hardware with its firmware's
// software inventory — and must not be caught by the gate.
func TestADeviceRegistersOnAProjectClassifiedForBoth(t *testing.T) {
	f := newFixture(t)
	p := createProjectFromSource(t, f, tenantA, "upload", "SBOM", "HBOM")
	cleanupDevicesFor(t, f, tenantA, p.ID)

	if _, err := f.svc.CreateDevice(t.Context(), tenantA, p.ID, userA, &hbom.Device{
		Name: "dual-" + uniqueName(t),
	}); err != nil {
		t.Fatalf("a device was refused on an SBOM+HBOM project: %v", err)
	}
}

// TestQuantumMetadataCannotBeSavedAgainstANonQBOMProject.
//
// SaveQuantumDevice MINTS a bom_documents row, so this is a creation, not an
// edit — the same class of defect as the device, on a different BOM type.
func TestQuantumMetadataCannotBeSavedAgainstANonQBOMProject(t *testing.T) {
	f := newFixture(t)
	p := createProject(t, f, tenantA) // SBOM only

	_, _, _, err := f.svc.SaveQuantumDevice(t.Context(), tenantA, p.ID, qbom.DeviceValues{})
	if err == nil {
		t.Fatal("Table 8 quantum metadata was saved against an SBOM-only project")
	}
	if !errs.Is(err, errs.ProjectNotClassified) {
		t.Errorf("code = %s, want %s", errs.From(err).Code, errs.ProjectNotClassified)
	}
	// The message must name what the caller was doing. CLAUDE.md's honest
	// labels forbid implying AxeBOM inventories quantum devices, so the noun is
	// "quantum device metadata" — asserted here because it is customer-facing
	// copy, not an internal string.
	if !strings.Contains(err.Error(), "quantum device metadata") {
		t.Errorf("the refusal does not say what was being saved: %v", err)
	}
}

// TestAnHBOMImportIsRefusedOnANonHardwareProject covers the third creation
// path — a CSV/XLSX import, which writes a whole tree at once.
func TestAnHBOMImportIsRefusedOnANonHardwareProject(t *testing.T) {
	f := newFixture(t)
	p := createProject(t, f, tenantA) // SBOM only

	csv := "product_name,quantity\nwidget,1\n"
	_, err := f.svc.ImportHBOM(t.Context(), tenantA, p.ID, []byte(csv), nil, "parts.csv")
	if err == nil {
		t.Fatal("a hardware parts file was imported into an SBOM-only project")
	}
	if !errs.Is(err, errs.ProjectNotClassified) {
		t.Errorf("code = %s, want %s", errs.From(err).Code, errs.ProjectNotClassified)
	}
}

// TestTheGateStillHidesAnotherTenantsProject.
//
// ⚠ THE GATE ADDED A PROJECT LOOKUP, AND A LOOKUP IS EXACTLY WHERE INVARIANT 6
// GETS BROKEN. Refusing a cross-tenant device with "this project is not
// classified for HBOM" would confirm the project exists. It must stay 404.
func TestTheGateStillHidesAnotherTenantsProject(t *testing.T) {
	f := newFixture(t)
	p := createProjectFromSource(t, f, tenantA, "manual", "HBOM")

	_, err := f.svc.CreateDevice(t.Context(), tenantB, p.ID, userA, &hbom.Device{Name: "probe"})
	if err == nil {
		t.Fatal("tenant B registered a device on tenant A's project")
	}
	if got := errs.From(err).HTTPStatus(); got != 404 {
		t.Errorf("status = %d, want 404 — anything else confirms the project exists", got)
	}
}

// cleanupDevicesFor hard-deletes the devices a test registered.
//
// cleanupProject deletes the project row and hardware_devices cascades from it,
// but the cleanups run in reverse registration order — so this is registered
// first at each call site to be safe against a future change in that order.
func cleanupDevicesFor(t *testing.T, f *fixture, tenantID, projectID string) {
	t.Helper()
	t.Cleanup(func() {
		err := f.pool.WithTenant(context.Background(), tenantID,
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
