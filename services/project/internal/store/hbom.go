package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/axebom/axebom/libs/go-shared/platform/db"
	"github.com/axebom/axebom/services/project/internal/hbom"
)

// ---------------------------------------------------------------------------
// Hardware BOM
//
// ⚠ IMPORT PLUS STRUCTURED ENTRY. NOTHING HERE SCANS — see
// services/project/internal/hbom's package doc.
//
// normalize.hardware_components is owned by the normalizer domain, not this
// service's own `project` schema — but unlike normalize.components and
// normalize.findings (see dependencies.go, findings.go), HBOM has no scan and
// no Python normalizer writing to it: this service is the only writer,
// because import is the whole pipeline (CLAUDE.md; docs/phases/PHASE-15-hbom.md).
//
// ⚠ scan_id STANDS IN FOR THE PROJECT ID, DELIBERATELY, FOR THIS BOM TYPE
// ONLY. normalize.bom_documents.scan_id is `uuid NOT NULL -> scan.scans.id,
// no FK (cross-schema)` (migrations/normalize/0001_bom_components.sql) — the
// migration's own comment records that nothing enforces the reference. HBOM
// has no scan row to point at (source_type=manual carries no
// scan.scans.source_kind — see service.go's sourceTypes comment and
// GenerateFlow.tsx's sourceKindFor, which both treat "manual" as
// unscannable by design). Reusing the project id here gives each project
// exactly one HBOM document lineage to resolve by, with the same
// "highest normalization_version wins" rule every other BOM type uses (see
// services/scan-orchestrator/internal/orchestr/findings.go's
// resolveSBOMDocument).
// ---------------------------------------------------------------------------

// ErrComponentNotFound means a hardware component id does not exist within
// the project's current document — either it never existed, or (same
// tenant, different project) it belongs to someone else's hardware BOM.
//
// Kept distinct from ErrNotFound, which this file also uses for "no such
// project": collapsing the two would force every hardware-component error
// to be worded as if the PROJECT were missing, which is wrong exactly when
// it matters — a project that exists but does not own the component id a
// caller supplied.
var ErrComponentNotFound = errors.New("no such hardware component")

// projectExists confirms a project is visible IN THIS TENANT before a
// dependent write proceeds, matching the inline check already used by
// CreateConnection, CreateUpload and UpsertPractices above.
func projectExists(ctx context.Context, tx db.Tx, projectID string) error {
	var exists bool
	err := tx.QueryRow(ctx,
		`SELECT true FROM project.projects WHERE id = $1 AND deleted_at IS NULL`,
		projectID).Scan(&exists)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	return err
}

// GetHardwareTree reads a project's hardware BOM tree.
//
// ⚠ RETURNS AN EMPTY TREE, NOT ErrNotFound, WHEN NOTHING HAS BEEN RECORDED
// YET. "no hardware imported" is the ordinary starting state for a hardware
// project — HardwareTree.tsx renders it as an empty state, not an error.
func (s *Store) GetHardwareTree(ctx context.Context, tenantID, projectID string) ([]*hbom.Component, error) {
	var out []*hbom.Component
	err := s.pool.WithTenant(ctx, tenantID, func(ctx context.Context, tx db.Tx) error {
		if err := projectExists(ctx, tx, projectID); err != nil {
			return err
		}

		docID, err := resolveHBOMDocument(ctx, tx, projectID)
		if err != nil {
			return err
		}
		if docID == "" {
			return nil // nothing imported yet
		}

		nodes, err := loadHardwareNodes(ctx, tx, docID)
		if err != nil {
			return err
		}
		out = buildHardwareTree(nodes)
		return nil
	})
	return out, err
}

// SaveHardwareComponent upserts one component and its submitted descendants.
//
// A node with an ID updates the existing row (scoped to this project's
// current document, so a copied id from another project can never redirect
// the write); a node with no ID inserts a new one under ParentID.
func (s *Store) SaveHardwareComponent(ctx context.Context, tenantID, projectID string, node *hbom.Component) (*hbom.Component, error) {
	err := s.pool.WithTenant(ctx, tenantID, func(ctx context.Context, tx db.Tx) error {
		if err := projectExists(ctx, tx, projectID); err != nil {
			return err
		}
		docID, err := ensureHBOMDocument(ctx, tx, tenantID, projectID)
		if err != nil {
			return err
		}
		return upsertNodeRecursive(ctx, tx, tenantID, docID, node, node.ParentID)
	})
	if err != nil {
		return nil, err
	}
	return node, nil
}

// ReplaceHardwareTree stores a freshly-imported tree as a NEW normalization
// version, never mutating a previous import's rows in place — the same
// "raw artifacts are immutable, normalization is versioned" discipline
// CLAUDE.md invariant 10 states for the scanner pipeline, applied here to a
// full re-import.
func (s *Store) ReplaceHardwareTree(ctx context.Context, tenantID, projectID string, roots []*hbom.Component) (string, error) {
	var docID string
	err := s.pool.WithTenant(ctx, tenantID, func(ctx context.Context, tx db.Tx) error {
		if err := projectExists(ctx, tx, projectID); err != nil {
			return err
		}

		version, err := nextHBOMVersion(ctx, tx, projectID)
		if err != nil {
			return err
		}

		if err := tx.QueryRow(ctx, `
			INSERT INTO normalize.bom_documents
				(tenant_id, scan_id, bom_type, normalization_version,
				 ruleset_version, alias_snapshot_id, spdx_license_list_version)
			VALUES ($1, $2, 'HBOM', $3, '', app.uuid_v7(), '')
			RETURNING id`, tenantID, projectID, version).Scan(&docID); err != nil {
			return fmt.Errorf("create hbom document: %w", err)
		}

		for _, root := range roots {
			if err := insertHardwareTree(ctx, tx, tenantID, docID, root, ""); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	return docID, nil
}

// ---------------------------------------------------------------------------
// Document resolution
// ---------------------------------------------------------------------------

func resolveHBOMDocument(ctx context.Context, tx db.Tx, projectID string) (string, error) {
	var id string
	err := tx.QueryRow(ctx, `
		SELECT id FROM normalize.bom_documents
		 WHERE scan_id = $1 AND bom_type = 'HBOM'
		 ORDER BY normalization_version DESC
		 LIMIT 1`, projectID).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("resolve hbom document: %w", err)
	}
	return id, nil
}

func nextHBOMVersion(ctx context.Context, tx db.Tx, projectID string) (int, error) {
	var version int
	err := tx.QueryRow(ctx, `
		SELECT COALESCE(MAX(normalization_version), 0) + 1
		  FROM normalize.bom_documents WHERE scan_id = $1 AND bom_type = 'HBOM'`,
		projectID).Scan(&version)
	if err != nil {
		return 0, fmt.Errorf("resolve next hbom version: %w", err)
	}
	return version, nil
}

// ensureHBOMDocument returns the current document, creating an empty one on
// its first write — a component saved through the form before any CSV
// import needs somewhere to live.
func ensureHBOMDocument(ctx context.Context, tx db.Tx, tenantID, projectID string) (string, error) {
	id, err := resolveHBOMDocument(ctx, tx, projectID)
	if err != nil {
		return "", err
	}
	if id != "" {
		return id, nil
	}
	err = tx.QueryRow(ctx, `
		INSERT INTO normalize.bom_documents
			(tenant_id, scan_id, bom_type, normalization_version,
			 ruleset_version, alias_snapshot_id, spdx_license_list_version)
		VALUES ($1, $2, 'HBOM', 1, '', app.uuid_v7(), '')
		RETURNING id`, tenantID, projectID).Scan(&id)
	if err != nil {
		return "", fmt.Errorf("create hbom document: %w", err)
	}
	return id, nil
}

// ---------------------------------------------------------------------------
// Node read/write
// ---------------------------------------------------------------------------

const hardwareComponentColumns = `
	SELECT id, COALESCE(parent_id::text, ''),
	       product_name, COALESCE(product_version,''), COALESCE(product_details,''),
	       COALESCE(warranty_amc,''), COALESCE(manufacturer_name,''),
	       COALESCE(manufacturer_location,''), manufacturing_date,
	       COALESCE(supplier_info,''), COALESCE(supplier_location,''),
	       COALESCE(model_number,''), COALESCE(serial_number,''),
	       COALESCE(technical_specification,''), COALESCE(component_supplier_info,''),
	       COALESCE(component_supplier_location,''), COALESCE(technology_node,''),
	       compliance, COALESCE(power_supply,''), COALESCE(license_info,''),
	       COALESCE(test_result,''), COALESCE(firmware_version,''),
	       COALESCE(origin,''), COALESCE(criticality,'')
	  FROM normalize.hardware_components`

func loadHardwareNodes(ctx context.Context, tx db.Tx, docID string) ([]*hbom.Component, error) {
	rows, err := tx.Query(ctx, hardwareComponentColumns+` WHERE bom_document_id = $1 ORDER BY id`, docID)
	if err != nil {
		return nil, fmt.Errorf("load hardware components: %w", err)
	}
	defer rows.Close()

	var out []*hbom.Component
	for rows.Next() {
		c, err := scanHardwareNode(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func scanHardwareNode(row pgx.Row) (*hbom.Component, error) {
	c := &hbom.Component{Quantity: 1}
	var manufacturingDate *time.Time
	if err := row.Scan(&c.ID, &c.ParentID,
		&c.ProductName, &c.ProductVersion, &c.ProductDetails,
		&c.WarrantyAMC, &c.ManufacturerName, &c.ManufacturerLocation, &manufacturingDate,
		&c.SupplierInfo, &c.SupplierLocation, &c.ModelNumber, &c.SerialNumber,
		&c.TechnicalSpecification, &c.ComponentSupplierInfo, &c.ComponentSupplierLocation,
		&c.TechnologyNode, &c.Compliance, &c.PowerSupply, &c.LicenseInfo,
		&c.TestResult, &c.FirmwareVersion, &c.Origin, &c.Criticality,
	); err != nil {
		return nil, fmt.Errorf("scan hardware component: %w", err)
	}
	if manufacturingDate != nil {
		c.ManufacturingDate = manufacturingDate.Format("2006-01-02")
	}
	return c, nil
}

// buildHardwareTree assembles flat rows into a forest by parent_id.
func buildHardwareTree(nodes []*hbom.Component) []*hbom.Component {
	byID := make(map[string]*hbom.Component, len(nodes))
	for _, n := range nodes {
		n.Children = nil // rebuilt below; defends against a caller reusing a node
		byID[n.ID] = n
	}

	var roots []*hbom.Component
	for _, n := range nodes {
		if n.ParentID == "" {
			roots = append(roots, n)
			continue
		}
		if parent, ok := byID[n.ParentID]; ok {
			parent.Children = append(parent.Children, n)
		} else {
			// An orphaned row (parent deleted, or from a different document
			// than expected) is still shown rather than silently dropped —
			// dropping it would understate the BOM.
			roots = append(roots, n)
		}
	}
	return roots
}

// parseManufacturingDate returns a *time.Time for a YYYY-MM-DD string, or nil
// if the value is empty or not in that shape.
//
// ⚠ A KNOWN GAP, NOT SILENTLY PAPERED OVER: the CERT-In parts-list field is
// free text (workers/hbom/model.py's manufacturing_date is `str`), but
// normalize.hardware_components stores it as a SQL `date`
// (migrations/normalize/0003_specialized_boms.sql). A value that is not
// ISO-8601 cannot be stored as a date and is dropped rather than rejecting
// the whole import over one column — the same "do not fail the row over the
// least load-bearing field" choice csv_import.py makes for quantity.
func parseManufacturingDate(s string) any {
	if s == "" {
		return nil
	}
	if t, err := time.Parse("2006-01-02", s); err == nil {
		return t
	}
	return nil
}

func insertHardwareNode(ctx context.Context, tx db.Tx, tenantID, docID, parentID string, c *hbom.Component) (string, error) {
	var id string
	err := tx.QueryRow(ctx, `
		INSERT INTO normalize.hardware_components
			(tenant_id, bom_document_id, parent_id,
			 product_name, product_version, product_details, warranty_amc,
			 manufacturer_name, manufacturer_location, manufacturing_date,
			 supplier_info, supplier_location, model_number, serial_number,
			 technical_specification, component_supplier_info, component_supplier_location,
			 technology_node, compliance, power_supply, license_info, test_result,
			 firmware_version, origin, criticality)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25)
		RETURNING id`,
		tenantID, docID, nullIfEmpty(parentID),
		c.ProductName, nullIfEmpty(c.ProductVersion), nullIfEmpty(c.ProductDetails), nullIfEmpty(c.WarrantyAMC),
		nullIfEmpty(c.ManufacturerName), nullIfEmpty(c.ManufacturerLocation), parseManufacturingDate(c.ManufacturingDate),
		nullIfEmpty(c.SupplierInfo), nullIfEmpty(c.SupplierLocation), nullIfEmpty(c.ModelNumber), nullIfEmpty(c.SerialNumber),
		nullIfEmpty(c.TechnicalSpecification), nullIfEmpty(c.ComponentSupplierInfo), nullIfEmpty(c.ComponentSupplierLocation),
		nullIfEmpty(c.TechnologyNode), textArrayOrNil(c.Compliance), nullIfEmpty(c.PowerSupply), nullIfEmpty(c.LicenseInfo), nullIfEmpty(c.TestResult),
		nullIfEmpty(c.FirmwareVersion), nullIfEmpty(c.Origin), nullIfEmpty(c.Criticality),
	).Scan(&id)
	if err != nil {
		return "", fmt.Errorf("insert hardware component: %w", err)
	}
	return id, nil
}

// updateHardwareNode writes an existing node, scoped to the CALLER'S
// document — the WHERE clause is what stops a copied id from another
// project (same tenant, so RLS alone would not catch it) from redirecting
// the write.
func updateHardwareNode(ctx context.Context, tx db.Tx, docID, id string, c *hbom.Component) error {
	tag, err := tx.Exec(ctx, `
		UPDATE normalize.hardware_components SET
			product_name = $3, product_version = $4, product_details = $5, warranty_amc = $6,
			manufacturer_name = $7, manufacturer_location = $8, manufacturing_date = $9,
			supplier_info = $10, supplier_location = $11, model_number = $12, serial_number = $13,
			technical_specification = $14, component_supplier_info = $15, component_supplier_location = $16,
			technology_node = $17, compliance = $18, power_supply = $19, license_info = $20,
			test_result = $21, firmware_version = $22, origin = $23, criticality = $24
		 WHERE id = $1 AND bom_document_id = $2`,
		id, docID,
		c.ProductName, nullIfEmpty(c.ProductVersion), nullIfEmpty(c.ProductDetails), nullIfEmpty(c.WarrantyAMC),
		nullIfEmpty(c.ManufacturerName), nullIfEmpty(c.ManufacturerLocation), parseManufacturingDate(c.ManufacturingDate),
		nullIfEmpty(c.SupplierInfo), nullIfEmpty(c.SupplierLocation), nullIfEmpty(c.ModelNumber), nullIfEmpty(c.SerialNumber),
		nullIfEmpty(c.TechnicalSpecification), nullIfEmpty(c.ComponentSupplierInfo), nullIfEmpty(c.ComponentSupplierLocation),
		nullIfEmpty(c.TechnologyNode), textArrayOrNil(c.Compliance), nullIfEmpty(c.PowerSupply), nullIfEmpty(c.LicenseInfo),
		nullIfEmpty(c.TestResult), nullIfEmpty(c.FirmwareVersion), nullIfEmpty(c.Origin), nullIfEmpty(c.Criticality),
	)
	if err != nil {
		return fmt.Errorf("update hardware component: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrComponentNotFound
	}
	return nil
}

// upsertNodeRecursive writes node (update if it carries an id, insert
// otherwise) and then every child, wiring each child's parent to the id this
// call just resolved — so a brand-new subtree submitted alongside an
// existing node still links up correctly.
func upsertNodeRecursive(ctx context.Context, tx db.Tx, tenantID, docID string, node *hbom.Component, parentID string) error {
	if node.ID != "" {
		if err := updateHardwareNode(ctx, tx, docID, node.ID, node); err != nil {
			return err
		}
	} else {
		id, err := insertHardwareNode(ctx, tx, tenantID, docID, parentID, node)
		if err != nil {
			return err
		}
		node.ID = id
	}
	node.ParentID = parentID

	for _, child := range node.Children {
		if err := upsertNodeRecursive(ctx, tx, tenantID, docID, child, node.ID); err != nil {
			return err
		}
	}
	return nil
}

// insertHardwareTree inserts a freshly-parsed subtree (no ids yet) under
// parentID, used by ReplaceHardwareTree for a CSV import.
func insertHardwareTree(ctx context.Context, tx db.Tx, tenantID, docID string, node *hbom.Component, parentID string) error {
	id, err := insertHardwareNode(ctx, tx, tenantID, docID, parentID, node)
	if err != nil {
		return err
	}
	node.ID = id
	node.ParentID = parentID
	for _, child := range node.Children {
		if err := insertHardwareTree(ctx, tx, tenantID, docID, child, id); err != nil {
			return err
		}
	}
	return nil
}

// textArrayOrNil maps an empty slice to SQL NULL, matching nullIfEmpty's
// "absent means not-recorded, not recorded-as-empty" rule for the compliance
// text[] column.
func textArrayOrNil(v []string) any {
	if len(v) == 0 {
		return nil
	}
	return v
}
