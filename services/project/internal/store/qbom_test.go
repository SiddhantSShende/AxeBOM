package store_test

import (
	"context"
	"errors"
	"testing"

	"github.com/axebom/axebom/libs/go-shared/model"
	"github.com/axebom/axebom/libs/go-shared/platform/db"
	"github.com/axebom/axebom/services/project/internal/qbom"
	"github.com/axebom/axebom/services/project/internal/store"
)

// Against real Postgres, same discipline as hbom_test.go: the properties
// under test (RLS isolation, cross-schema CBOM resolution, versioning on
// re-save) are properties of the database.

// cleanupQBOMDocuments removes every normalize.bom_documents row (and, via
// CASCADE, its quantum_components) this test created for a project.
func cleanupQBOMDocuments(t *testing.T, pool *db.Pool, tenantID, projectID string) {
	t.Helper()
	t.Cleanup(func() {
		err := pool.WithTenant(context.Background(), tenantID, func(ctx context.Context, tx db.Tx) error {
			_, err := tx.Exec(ctx, `DELETE FROM normalize.bom_documents WHERE scan_id = $1 AND bom_type = 'QBOM'`, projectID)
			return err
		})
		if err != nil {
			t.Logf("cleanup qbom documents for project %s: %v", projectID, err)
		}
	})
}

// cbomFixture is a hand-inserted, minimal CBOM: one scan, one bom_document,
// and a handful of crypto_assets — enough to exercise QBOM's derived
// crypto-asset-reference resolution against data shaped the way a real CBOM
// normalization pass would leave it. There is no store API for scan.scans
// or normalize.crypto_assets — those schemas belong to scan-orchestrator and
// the normalizer — so this fixture inserts directly via SQL, matching
// dependencies_test.go's seedSBOM.
type cbomFixture struct {
	scanID     string
	docID      string
	assetNames []string
}

func seedCBOM(t *testing.T, pool *db.Pool, tenantID, projectID string, assetNames ...string) cbomFixture {
	t.Helper()
	f := cbomFixture{assetNames: assetNames}

	err := pool.WithTenant(t.Context(), tenantID, func(ctx context.Context, tx db.Tx) error {
		if err := tx.QueryRow(ctx, `
			INSERT INTO scan.scans (tenant_id, project_id, triggered_by, source_kind)
			VALUES ($1, $2, 'user', 'git') RETURNING id`, tenantID, projectID).Scan(&f.scanID); err != nil {
			return err
		}

		if err := tx.QueryRow(ctx, `
			INSERT INTO normalize.bom_documents
				(tenant_id, scan_id, bom_type, normalization_version,
				 ruleset_version, alias_snapshot_id, spdx_license_list_version, generated_at)
						-- ⚠ alias_snapshot_id IS NULL, NOT app.uuid_v7(). Migration 0012 gave
			-- the column a real FK, so a minted id is now rejected outright.
			-- NULL is also what production writes for this BOM type: QBOM's source CBOM runs
			-- no alias closure, so there is no snapshot to reference.
VALUES ($1, $2, 'CBOM', 1, 'test-1', NULL, 'test-1', now())
			RETURNING id`, tenantID, f.scanID).Scan(&f.docID); err != nil {
			return err
		}

		for _, name := range assetNames {
			// asset_key is NOT NULL since migrations/normalize/0020; the `name:`
			// tier is the ladder's own last resort for an asset known by name only.
			if _, err := tx.Exec(ctx, `
				INSERT INTO normalize.crypto_assets
					(tenant_id, bom_document_id, asset_type, name, primitive,
					 asset_key, identity_rule, identity_confidence)
				VALUES ($1, $2, 'algorithm', $3::text, 'RSA', 'name:' || $3::text, 'name', 'low')`,
				tenantID, f.docID, name); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("seed cbom fixture: %v", err)
	}

	t.Cleanup(func() {
		_ = pool.WithTenant(context.Background(), tenantID, func(ctx context.Context, tx db.Tx) error {
			_, _ = tx.Exec(ctx, `DELETE FROM normalize.bom_documents WHERE id = $1`, f.docID)
			_, err := tx.Exec(ctx, `DELETE FROM scan.scans WHERE id = $1`, f.scanID)
			return err
		})
	})

	return f
}

func TestGetQuantumDeviceIsAnHonestEmptyDeviceBeforeAnySave(t *testing.T) {
	pool := openPool(t)
	st := store.New(pool)
	projectID := createTestProject(t, st, tenantA)
	cleanupQBOMDocuments(t, pool, tenantA, projectID)

	device, gaps, err := st.GetQuantumDevice(t.Context(), tenantA, projectID)
	if err != nil {
		t.Fatalf("GetQuantumDevice: %v", err)
	}
	if device.ModelName != qbom.NotProvided {
		t.Errorf("model_name = %q, want %q before any save", device.ModelName, qbom.NotProvided)
	}
	if len(gaps) != len(model.QBOMFields) {
		t.Errorf("gaps = %d, want %d (every element unrecorded)", len(gaps), len(model.QBOMFields))
	}
}

func TestSaveQuantumDeviceRoundTripsThroughGetQuantumDevice(t *testing.T) {
	pool := openPool(t)
	st := store.New(pool)
	projectID := createTestProject(t, st, tenantA)
	cleanupQBOMDocuments(t, pool, tenantA, projectID)

	values := qbom.DeviceValues{
		ModelName:             "IBM Q System One",
		Version:               "1.2",
		VendorOrigin:          "IBM, United States",
		CommunicationProtocol: "REST over TLS 1.3",
		SoftwareDependencies:  []string{"qiskit==1.0.0"},
		AttestationSignature:  "sig:deadbeef",
		// LicenseInfo, Hardware, EnvironmentalImpact deliberately left blank.
	}

	device, gaps, docID, err := st.SaveQuantumDevice(t.Context(), tenantA, projectID, values)
	if err != nil {
		t.Fatalf("SaveQuantumDevice: %v", err)
	}
	if docID == "" {
		t.Fatal("expected a bom document id")
	}
	if device.ModelName != "IBM Q System One" {
		t.Errorf("model_name = %q", device.ModelName)
	}
	if device.LicenseInfo != qbom.NotProvided {
		t.Errorf("license_info = %q, want %q", device.LicenseInfo, qbom.NotProvided)
	}

	got, gotGaps, err := st.GetQuantumDevice(t.Context(), tenantA, projectID)
	if err != nil {
		t.Fatalf("GetQuantumDevice: %v", err)
	}
	if got.ModelName != "IBM Q System One" || got.Version != "1.2" || got.VendorOrigin != "IBM, United States" {
		t.Errorf("round-tripped device = %+v", got)
	}
	if got.CommunicationProtocol != "REST over TLS 1.3" {
		t.Errorf("communication_protocol = %q", got.CommunicationProtocol)
	}
	if len(got.SoftwareDependencies) != 1 || got.SoftwareDependencies[0] != "qiskit==1.0.0" {
		t.Errorf("software_dependencies = %v", got.SoftwareDependencies)
	}
	if got.AttestationSignature != "sig:deadbeef" {
		t.Errorf("attestation_signature = %q", got.AttestationSignature)
	}
	if got.LicenseInfo != qbom.NotProvided || got.Hardware != qbom.NotProvided || got.EnvironmentalImpact != qbom.NotProvided {
		t.Errorf("blank fields not stored as %q: license=%q hardware=%q env=%q",
			qbom.NotProvided, got.LicenseInfo, got.Hardware, got.EnvironmentalImpact)
	}

	// Five captured fields were substantive (model_name, version, vendor_origin,
	// communication_protocol, software_dependencies, attestation_signature =
	// six), plus both derived fields are not-provided (no CBOM seeded) — so
	// gaps must cover license_info, hardware, environmental_impact and both
	// derived fields.
	if len(gaps) != 5 {
		t.Errorf("gaps = %d, want 5 (license_info, hardware, environmental_impact, crypto_assets, findings)", len(gaps))
	}
	if len(gaps) != len(gotGaps) {
		t.Errorf("gaps from Save (%d) and Get (%d) disagree", len(gaps), len(gotGaps))
	}
}

func TestSaveQuantumDeviceResolvesCryptoAssetRefsFromCurrentCBOM(t *testing.T) {
	pool := openPool(t)
	st := store.New(pool)
	projectID := createTestProject(t, st, tenantA)
	cleanupQBOMDocuments(t, pool, tenantA, projectID)
	seedCBOM(t, pool, tenantA, projectID, "RSA-2048 signing key", "AES-256-GCM session cipher")

	device, gaps, _, err := st.SaveQuantumDevice(t.Context(), tenantA, projectID, qbom.DeviceValues{ModelName: "X"})
	if err != nil {
		t.Fatalf("SaveQuantumDevice: %v", err)
	}
	if len(device.CryptoAssetRefs) != 2 {
		t.Fatalf("crypto asset refs = %v, want 2 (one per seeded crypto asset)", device.CryptoAssetRefs)
	}
	// ⚠ THE ASSET KEY, NOT THE ROW ID: a re-normalized CBOM gets new row ids,
	// and a QBOM referencing them would stop resolving (workers/qbom/derive.py
	// resolves in the same order). Ordered by asset key.
	wantRefs := []string{"name:AES-256-GCM session cipher", "name:RSA-2048 signing key"}
	for i, want := range wantRefs {
		if device.CryptoAssetRefs[i] != want {
			t.Errorf("crypto asset refs = %v, want %v", device.CryptoAssetRefs, wantRefs)
			break
		}
	}
	if device.FieldStatus[model.FieldCertinQbom05CryptographicAsset] != "provided" {
		t.Errorf("crypto asset field status = %q, want provided",
			device.FieldStatus[model.FieldCertinQbom05CryptographicAsset])
	}
	for _, g := range gaps {
		if g.FieldID == model.FieldCertinQbom05CryptographicAsset {
			t.Errorf("crypto asset field must not be a gap once a CBOM exists: %+v", g)
		}
	}

	// findings still has no matching concept in this codebase — always a gap.
	if device.FieldStatus[model.FieldCertinQbom10Vulnerabilities] != qbom.NotProvided {
		t.Errorf("findings field status = %q, want %q (no crypto-asset finding matching exists)",
			device.FieldStatus[model.FieldCertinQbom10Vulnerabilities], qbom.NotProvided)
	}

	// GetQuantumDevice reads back the PERSISTED field_status, so it must
	// agree with what Save just computed and stored — not re-derive from a
	// (possibly since-changed) CBOM on every read.
	_, gotGaps, err := st.GetQuantumDevice(t.Context(), tenantA, projectID)
	if err != nil {
		t.Fatalf("GetQuantumDevice: %v", err)
	}
	if len(gotGaps) != len(gaps) {
		t.Errorf("persisted gaps = %d, want %d (matching what Save computed)", len(gotGaps), len(gaps))
	}
}

func TestReSaveQuantumDeviceCreatesANewVersionRatherThanMutating(t *testing.T) {
	pool := openPool(t)
	st := store.New(pool)
	projectID := createTestProject(t, st, tenantA)
	cleanupQBOMDocuments(t, pool, tenantA, projectID)

	if _, _, _, err := st.SaveQuantumDevice(t.Context(), tenantA, projectID, qbom.DeviceValues{ModelName: "V1"}); err != nil {
		t.Fatalf("first save: %v", err)
	}
	if _, _, _, err := st.SaveQuantumDevice(t.Context(), tenantA, projectID, qbom.DeviceValues{ModelName: "V2"}); err != nil {
		t.Fatalf("second save: %v", err)
	}

	got, _, err := st.GetQuantumDevice(t.Context(), tenantA, projectID)
	if err != nil {
		t.Fatalf("GetQuantumDevice: %v", err)
	}
	if got.ModelName != "V2" {
		t.Fatalf("model_name = %q, want the second save's value", got.ModelName)
	}

	var count int
	err = pool.WithTenant(t.Context(), tenantA, func(ctx context.Context, tx db.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT count(*) FROM normalize.bom_documents WHERE scan_id = $1 AND bom_type = 'QBOM'`,
			projectID).Scan(&count)
	})
	if err != nil {
		t.Fatalf("count documents: %v", err)
	}
	if count != 2 {
		t.Errorf("document count = %d, want 2 (both versions retained, CLAUDE.md invariant 10)", count)
	}
}

func TestQuantumDeviceCrossTenantAccessIsNotFound(t *testing.T) {
	pool := openPool(t)
	st := store.New(pool)
	projectID := createTestProject(t, st, tenantA)
	cleanupQBOMDocuments(t, pool, tenantA, projectID)

	if _, _, _, err := st.SaveQuantumDevice(t.Context(), tenantA, projectID, qbom.DeviceValues{ModelName: "Secret"}); err != nil {
		t.Fatalf("save: %v", err)
	}

	_, _, err := st.GetQuantumDevice(t.Context(), tenantB, projectID)
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("error = %v, want ErrNotFound for a project id belonging to another tenant", err)
	}
}
