package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/axebom/axebom/libs/go-shared/platform/db"
	"github.com/axebom/axebom/services/project/internal/qbom"
)

// ---------------------------------------------------------------------------
// Quantum BOM (QBOM) device metadata
//
// ⚠ CAPTURED, NOT DISCOVERED. NOTHING HERE SCANS — see
// services/project/internal/qbom's package doc.
//
// normalize.quantum_components is owned by the normalizer domain, not this
// service's own `project` schema — but exactly like HBOM (see hbom.go's own
// comment) and unlike normalize.components/normalize.findings, QBOM device
// metadata has no scan and no Python normalizer writing to it: this service
// is the only writer, because form/import capture is the whole pipeline for
// Table 8.
//
// ⚠ scan_id STANDS IN FOR THE PROJECT ID, DELIBERATELY, FOR THIS BOM TYPE
// TOO — same reasoning as hbom.go: QBOM device metadata has no scan row to
// point at, so the project id gives each project exactly one QBOM device
// lineage to resolve by, with the same "highest normalization_version wins"
// rule every other BOM type uses.
//
// ⚠ crypto_asset_refs / finding_refs ARE RESOLVED ONLY WHEN A DEVICE IS
// SAVED, NEVER RE-DERIVED ON A PLAIN READ. docs/01-DATA-MODEL.md's
// quantum_components entry notes the crypto asset reference is available
// "via bom_document_id" — there is deliberately no column for either
// reference field on this table (see
// migrations/normalize/0003_specialized_boms.sql). SaveQuantumDevice
// resolves the CURRENT CBOM's crypto assets at save time and persists the
// resulting field_status (all eleven elements, including the two derived
// ones) alongside the nine captured columns; GetQuantumDevice reads that
// persisted field_status back rather than re-querying the CBOM, because the
// persisted value IS the versioned, immutable record of what was true when
// this device was last saved (CLAUDE.md invariant 10 — normalization is a
// deterministic pure function of its inputs, versioned, never silently
// recomputed on read). A project whose CBOM has since found new crypto
// assets picks them up the next time its QBOM device is saved, even with
// unchanged form values.
// ---------------------------------------------------------------------------

const quantumComponentColumns = `
	SELECT model_name, COALESCE(version,''), COALESCE(vendor_origin,''),
	       COALESCE(license_info,''), COALESCE(communication_protocol,''),
	       COALESCE(hardware,''), software_dependencies,
	       COALESCE(environmental_impact,''), COALESCE(attestation_signature,''),
	       field_status
	  FROM normalize.quantum_components`

// GetQuantumDevice returns a project's current QBOM device metadata and its
// gaps.
//
// ⚠ RETURNS AN HONEST EMPTY DEVICE, NOT ErrNotFound, WHEN NOTHING HAS BEEN
// RECORDED YET — matching GetHardwareTree's precedent: "no device metadata
// captured" is the ordinary starting state for a quantum project, not an
// error.
func (s *Store) GetQuantumDevice(ctx context.Context, tenantID, projectID string) (*qbom.Device, []qbom.FieldGap, error) {
	var device *qbom.Device
	var gaps []qbom.FieldGap
	err := s.pool.WithTenant(ctx, tenantID, func(ctx context.Context, tx db.Tx) error {
		if err := projectExists(ctx, tx, projectID); err != nil {
			return err
		}

		stored, found, err := loadStoredQuantumDevice(ctx, tx, projectID)
		if err != nil {
			return err
		}
		if !found {
			// Nothing saved yet, and nothing to derive from without a save —
			// the same all-not-provided shape qbom.NormalizeDevice produces
			// for an empty submission.
			device, gaps = qbom.NormalizeDevice(qbom.DeviceValues{}, nil, nil)
			return nil
		}

		device = stored
		gaps = qbom.GapsFromStatus(device.FieldStatus)
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	return device, gaps, nil
}

// SaveQuantumDevice normalizes and stores a project's QBOM device metadata
// as a NEW normalization version, never mutating a previous save in place —
// the same "raw artifacts are immutable, normalization is versioned"
// discipline CLAUDE.md invariant 10 states for the scanner pipeline,
// applied here to a form submission (mirrors ReplaceHardwareTree). This is a
// full replace: every one of the nine captured columns comes from values,
// not merged with whatever was saved before.
func (s *Store) SaveQuantumDevice(ctx context.Context, tenantID, projectID string, values qbom.DeviceValues) (*qbom.Device, []qbom.FieldGap, string, error) {
	var device *qbom.Device
	var gaps []qbom.FieldGap
	var docID string
	err := s.pool.WithTenant(ctx, tenantID, func(ctx context.Context, tx db.Tx) error {
		if err := projectExists(ctx, tx, projectID); err != nil {
			return err
		}

		cryptoRefs, err := resolveCryptoAssetRefs(ctx, tx, projectID)
		if err != nil {
			return err
		}
		// findingRefs is always empty: this codebase has no concept of a
		// vulnerability matched against a crypto asset the way software
		// components are matched against CVEs — normalize.findings keys on
		// component_id, and there is no crypto-asset equivalent anywhere in
		// this schema. Passing nil here is the honest answer, not a
		// shortcut; see this package's qbom.go doc comment and the final
		// report note on this gap.
		device, gaps = qbom.NormalizeDevice(values, cryptoRefs, nil)

		fieldStatus, err := json.Marshal(device.FieldStatus)
		if err != nil {
			return fmt.Errorf("marshal qbom field_status: %w", err)
		}

		version, err := nextQBOMVersion(ctx, tx, projectID)
		if err != nil {
			return err
		}

		// ⚠ alias_snapshot_id IS NULL, NOT A MINTED UUID. QBOM is derived from
		// CBOM crypto assets plus a Table 8 device form; it runs no
		// alias-closure pipeline, so there is no snapshot to reference. The
		// column used to take a bare app.uuid_v7() — a value that satisfied
		// NOT NULL and meant nothing — and since migration 0012 gave it a real
		// FK, that id would now be rejected. NULL is also the honest answer:
		// it declines to assert, where a fabricated id asserted something
		// false to anyone joining bom_documents -> alias_snapshot.
		//
		// ⚠ project_id AND scan_id BOTH CARRY THE PROJECT ID, AND THAT IS NOT
		// REDUNDANCY. scan_id is borrowed — a device form has no scan to point
		// at, and the column has no FK precisely so it could be borrowed. It
		// stays populated because resolveQBOMDocument below and every QBOM row
		// written before migration 0014 read it.
		//
		// project_id is the real lineage key, and writing it is what makes a
		// QBOM report resolvable at all: services/report resolves documents by
		// the REPORT's scan id, which is a genuine scan id and therefore never
		// equal to this. Before this line every QBOM report failed with
		// NOTFOUND_RESOURCE. See migrations/normalize/0014.
		if err := tx.QueryRow(ctx, `
			INSERT INTO normalize.bom_documents
				(tenant_id, scan_id, project_id, bom_type, normalization_version,
				 ruleset_version, alias_snapshot_id, spdx_license_list_version)
			VALUES ($1, $2, $2, 'QBOM', $3, '', NULL, '')
			RETURNING id`, tenantID, projectID, version).Scan(&docID); err != nil {
			return fmt.Errorf("create qbom document: %w", err)
		}

		softwareDeps := device.SoftwareDependencies
		if softwareDeps == nil {
			softwareDeps = []string{}
		}

		if _, err := tx.Exec(ctx, `
			INSERT INTO normalize.quantum_components
				(tenant_id, bom_document_id, model_name, version, vendor_origin,
				 license_info, communication_protocol, hardware,
				 software_dependencies, environmental_impact,
				 attestation_signature, field_status)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
			tenantID, docID, device.ModelName, device.Version, device.VendorOrigin,
			device.LicenseInfo, device.CommunicationProtocol, device.Hardware,
			softwareDeps, device.EnvironmentalImpact, device.AttestationSignature,
			fieldStatus,
		); err != nil {
			return fmt.Errorf("insert quantum component: %w", err)
		}
		return nil
	})
	if err != nil {
		return nil, nil, "", err
	}
	return device, gaps, docID, nil
}

// ---------------------------------------------------------------------------
// Document resolution
// ---------------------------------------------------------------------------

func resolveQBOMDocument(ctx context.Context, tx db.Tx, projectID string) (string, error) {
	var id string
	err := tx.QueryRow(ctx, `
		SELECT id FROM normalize.bom_documents
		 WHERE scan_id = $1 AND bom_type = 'QBOM'
		 ORDER BY normalization_version DESC
		 LIMIT 1`, projectID).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("resolve qbom document: %w", err)
	}
	return id, nil
}

func nextQBOMVersion(ctx context.Context, tx db.Tx, projectID string) (int, error) {
	var version int
	err := tx.QueryRow(ctx, `
		SELECT COALESCE(MAX(normalization_version), 0) + 1
		  FROM normalize.bom_documents WHERE scan_id = $1 AND bom_type = 'QBOM'`,
		projectID).Scan(&version)
	if err != nil {
		return 0, fmt.Errorf("resolve next qbom version: %w", err)
	}
	return version, nil
}

// loadStoredQuantumDevice reads the project's current QBOM document — the
// nine captured columns plus the field_status this same code persisted at
// save time — and returns found=false when nothing has been saved yet.
//
// ⚠ THE TWO DERIVED FIELDS' REFERENCE LISTS ARE NOT REPOPULATED HERE. There
// is no column to read them back from (see this file's package comment);
// only their field_status ("provided"/not-provided, as of the last save)
// survives. A caller wanting the actual current crypto asset references
// should resolve them fresh via resolveCryptoAssetRefs (as SaveQuantumDevice
// does) rather than expect this function to reconstruct them.
func loadStoredQuantumDevice(ctx context.Context, tx db.Tx, projectID string) (*qbom.Device, bool, error) {
	docID, err := resolveQBOMDocument(ctx, tx, projectID)
	if err != nil {
		return nil, false, err
	}
	if docID == "" {
		return nil, false, nil
	}

	d := &qbom.Device{}
	var statusJSON []byte
	err = tx.QueryRow(ctx, quantumComponentColumns+` WHERE bom_document_id = $1`, docID).Scan(
		&d.ModelName, &d.Version, &d.VendorOrigin, &d.LicenseInfo,
		&d.CommunicationProtocol, &d.Hardware, &d.SoftwareDependencies,
		&d.EnvironmentalImpact, &d.AttestationSignature, &statusJSON)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("load quantum component: %w", err)
	}

	d.FieldStatus = map[string]string{}
	if len(statusJSON) > 0 {
		if err := json.Unmarshal(statusJSON, &d.FieldStatus); err != nil {
			return nil, false, fmt.Errorf("unmarshal qbom field_status: %w", err)
		}
	}
	return d, true, nil
}

// resolveCryptoAssetRefs finds the project's current CBOM discovery and
// returns the reference list QBOM Table 8 element 5 carries.
//
// ⚠ REFERENCES, NOT COPIES. Mirrors workers/qbom/derive.py's
// crypto_asset_refs() precedence exactly: asset_key, then id, then
// component_key, then name — whichever is present first.
//
// ⚠ asset_key FIRST (migrations/normalize/0020). A row id changes every time
// a CBOM is re-normalized — invariant 10 writes a NEW document, and the row id
// is derived from it — so a QBOM that referenced ids stopped resolving after
// every corrected pass. The asset key names the same asset across versions.
// It is NOT NULL since 0020, so in practice this always resolves to it; the
// fallback chain is kept for parity with the Python side.
//
// Ordered by asset_key (unique per document) so the stored list is the same
// for the same inventory, whichever normalization wrote it.
func resolveCryptoAssetRefs(ctx context.Context, tx db.Tx, projectID string) ([]string, error) {
	cbomDocID, err := resolveCurrentBOMDocument(ctx, tx, projectID, "CBOM")
	if err != nil {
		return nil, err
	}
	if cbomDocID == "" {
		return nil, nil
	}

	rows, err := tx.Query(ctx, `
		SELECT COALESCE(asset_key, ''), id, COALESCE(component_key, ''), name
		  FROM normalize.crypto_assets
		 WHERE bom_document_id = $1
		 ORDER BY asset_key, id`, cbomDocID)
	if err != nil {
		return nil, fmt.Errorf("list crypto assets: %w", err)
	}
	defer rows.Close()

	var refs []string
	for rows.Next() {
		var assetKey, id, componentKey, name string
		if err := rows.Scan(&assetKey, &id, &componentKey, &name); err != nil {
			return nil, fmt.Errorf("scan crypto asset ref: %w", err)
		}
		ref := assetKey
		if ref == "" {
			ref = id
		}
		if ref == "" {
			ref = componentKey
		}
		if ref == "" {
			ref = name
		}
		if ref != "" {
			refs = append(refs, ref)
		}
	}
	return refs, rows.Err()
}
