package store

import (
	"context"
	"encoding/json"
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
// service's own `project` schema.
//
// ⚠ THIS SERVICE IS NO LONGER THE ONLY WRITER, AND THAT CHANGED DELIBERATELY.
//
// It used to be: HBOM was import-only, so import was the whole pipeline and
// there was no Python normalizer on the other side. `hbom-ecad` changed that
// — it parses the customer's own design files from an upload or a repo, which
// is a real scan producing real jobs, so workers/hbom now writes these tables
// too. What has NOT changed is the honest label: neither writer discovers
// physical hardware. One reads a CSV a person uploaded, the other reads a
// schematic they committed. See services/project/internal/hbom's package doc.
//
// ⚠ scan_id STILL STANDS IN FOR THE PROJECT ID ON THIS SERVICE'S WRITES, but
// it is no longer how a document is FOUND. normalize.bom_documents.scan_id is
// `uuid NOT NULL -> scan.scans.id, no FK (cross-schema)`
// (migrations/normalize/0001_bom_components.sql) — the migration's own comment
// records that nothing enforces the reference, which is what made borrowing it
// possible when an imported HBOM had no scan row to point at.
//
// Once hbom-ecad scans exist, both meanings are live in that one column: an
// imported document holds a project id there and a scanned one holds a real
// scan id. They cannot collide, but resolving by scan_id would find only half
// of them. migration 0012 added `project_id`, which BOTH writers set, and
// resolveHBOMDocument below reads that instead — see its comment for why the
// ordering rule had to change with it.
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

		// ⚠ project_id AND scan_id BOTH CARRY THE PROJECT ID HERE, and only
		// one of them is load-bearing. scan_id keeps the project id because
		// every HBOM document ever written did (see this file's header) and
		// nextHBOMVersion still counts the import lineage by it; project_id
		// is the column readers should use, and the one a SCANNED hardware
		// BOM also sets while carrying a real scan_id.
		//
		// alias_snapshot_id is NULL, not a fabricated app.uuid_v7(). An
		// import runs no alias-closure pipeline, so there is no snapshot to
		// point at — and since migration 0012 the column has a real FK, a
		// minted id would now be rejected rather than merely meaningless.
		if err := tx.QueryRow(ctx, `
			INSERT INTO normalize.bom_documents
				(tenant_id, scan_id, project_id, bom_type, normalization_version,
				 ruleset_version, alias_snapshot_id, spdx_license_list_version)
			VALUES ($1, $2, $2, 'HBOM', $3, '', NULL, '')
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
	// ⚠ project_id, NOT scan_id — AND newest-first, NOT highest-version-first.
	//
	// A project's hardware BOM now has two independent lineages: documents
	// imported through /v1/hbom/* (scan_id borrowed as the project id) and
	// documents produced by a real hbom-ecad scan (a genuine scan_id).
	// normalization_version counts WITHIN a lineage, so an import sitting at
	// v3 would outrank a fresh scan at v1 and the customer would be shown a
	// stale tree. Across two lineages the correct rule is newest wins;
	// version is only the tie-break within one.
	err := tx.QueryRow(ctx, `
		SELECT id FROM normalize.bom_documents
		 WHERE project_id = $1 AND bom_type = 'HBOM'
		 ORDER BY generated_at DESC, normalization_version DESC
		 LIMIT 1`, projectID).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("resolve hbom document: %w", err)
	}
	return id, nil
}

// nextHBOMVersion counts THIS SERVICE'S import lineage only.
//
// ⚠ scan_id HERE, project_id IN resolveHBOMDocument, AND THE DIFFERENCE IS THE
// POINT. A version number is meaningful only within one lineage: successive
// re-imports of a project's parts list are v1, v2, v3. A scanned document
// carries its own scan_id and gets its version from its own normalization
// trigger. Counting across both would make an import's next version depend on
// how many times somebody happened to scan, which is not a re-import.
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
	// Same two notes as ReplaceHardwareTree's insert above: project_id is the
	// real resolution key, and alias_snapshot_id is NULL because there is no
	// snapshot rather than because we could not find one.
	err = tx.QueryRow(ctx, `
		INSERT INTO normalize.bom_documents
			(tenant_id, scan_id, project_id, bom_type, normalization_version,
			 ruleset_version, alias_snapshot_id, spdx_license_list_version)
		VALUES ($1, $2, $2, 'HBOM', 1, '', NULL, '')
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
	       COALESCE(origin,''), COALESCE(criticality,''),
	       quantity, designators, COALESCE(package_footprint,''),
	       COALESCE(supplier_sku,''), COALESCE(preferred_supplier,''),
	       COALESCE(unit_price::text,''), COALESCE(currency,''),
	       do_not_populate, COALESCE(assembly_type,''),
	       COALESCE(lifecycle_status,''), COALESCE(datasheet_url,''),
	       enriched_fields
	  FROM normalize.hardware_components`

func loadHardwareNodes(ctx context.Context, tx db.Tx, docID string) ([]*hbom.Component, error) {
	rows, err := tx.Query(ctx, hardwareComponentColumns+` WHERE bom_document_id = $1 ORDER BY id`, docID)
	if err != nil {
		return nil, fmt.Errorf("load hardware components: %w", err)
	}
	defer rows.Close()

	var out []*hbom.Component
	index := map[string]*hbom.Component{}
	for rows.Next() {
		c, err := scanHardwareNode(rows)
		if err != nil {
			return nil, err
		}
		index[c.ID] = c
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	// ⚠ rows MUST BE DRAINED BEFORE THE NEXT QUERY ON THE SAME Tx. pgx holds
	// one connection per transaction, and issuing a second query while the
	// first result set is still open fails with "conn busy". The explicit
	// rows.Err() above plus the deferred Close is what makes that safe.
	if err := attachAlternates(ctx, tx, docID, index); err != nil {
		return nil, err
	}
	return out, nil
}

// attachAlternates loads each component's approved second sources.
//
// ⚠ THIS READ DID NOT EXIST, SO GET ALWAYS RETURNED `alternates: []`. The
// handler mapped the field in both directions and the store touched the table
// in neither — see replaceAlternates for the write half of the same hole.
//
// A separate query, not a join: an alternate is 1:N against a component, and
// joining would multiply every component row by its alternate count for the
// scan loop to de-duplicate — the shape that silently doubles a part count.
func attachAlternates(
	ctx context.Context, tx db.Tx, docID string, index map[string]*hbom.Component,
) error {
	if len(index) == 0 {
		return nil
	}
	rows, err := tx.Query(ctx, `
		SELECT a.hardware_component_id, a.ordinal,
		       COALESCE(a.manufacturer_name,''), COALESCE(a.model_number,''),
		       COALESCE(a.supplier_info,''), COALESCE(a.supplier_sku,''),
		       COALESCE(a.lifecycle_status,''), a.equivalence,
		       COALESCE(a.approval_note,'')
		  FROM normalize.hardware_component_alternates a
		  JOIN normalize.hardware_components h ON h.id = a.hardware_component_id
		 WHERE h.bom_document_id = $1
		 ORDER BY a.hardware_component_id, a.ordinal`, docID)
	if err != nil {
		return fmt.Errorf("load hardware alternates: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var (
			componentID string
			a           hbom.Alternate
		)
		if err := rows.Scan(&componentID, &a.Ordinal,
			&a.ManufacturerName, &a.ModelNumber, &a.SupplierInfo, &a.SupplierSKU,
			&a.LifecycleStatus, &a.Equivalence, &a.ApprovalNote); err != nil {
			return fmt.Errorf("scan hardware alternate: %w", err)
		}
		if c, ok := index[componentID]; ok {
			c.Alternates = append(c.Alternates, a)
		}
	}
	return rows.Err()
}

func scanHardwareNode(row pgx.Row) (*hbom.Component, error) {
	// ⚠ Quantity IS NO LONGER HARDCODED TO 1, AND THAT WAS A REAL DATA LOSS.
	// The column did not exist until migration 0011, so this line invented a
	// quantity for every row ever read — a CSV that said 100 rendered as 1,
	// silently, in a document a customer used for procurement.
	c := &hbom.Component{}
	var (
		manufacturingDate *time.Time
		enriched          []byte
	)
	if err := row.Scan(&c.ID, &c.ParentID,
		&c.ProductName, &c.ProductVersion, &c.ProductDetails,
		&c.WarrantyAMC, &c.ManufacturerName, &c.ManufacturerLocation, &manufacturingDate,
		&c.SupplierInfo, &c.SupplierLocation, &c.ModelNumber, &c.SerialNumber,
		&c.TechnicalSpecification, &c.ComponentSupplierInfo, &c.ComponentSupplierLocation,
		&c.TechnologyNode, &c.Compliance, &c.PowerSupply, &c.LicenseInfo,
		&c.TestResult, &c.FirmwareVersion, &c.Origin, &c.Criticality,
		&c.Quantity, &c.Designators, &c.PackageFootprint,
		&c.SupplierSKU, &c.PreferredSupplier, &c.UnitPrice, &c.Currency,
		&c.DoNotPopulate, &c.AssemblyType, &c.LifecycleStatus, &c.DatasheetURL,
		&enriched,
	); err != nil {
		return nil, fmt.Errorf("scan hardware component: %w", err)
	}
	if manufacturingDate != nil {
		c.ManufacturingDate = manufacturingDate.Format("2006-01-02")
	}
	if len(enriched) > 0 {
		// Provenance, not load-bearing: a malformed blob must not fail the read
		// of an otherwise good parts list.
		_ = json.Unmarshal(enriched, &c.EnrichedFields)
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
			 firmware_version, origin, criticality,
			 -- Manufacturing and procurement. NOT CERT-In elements; scored
			 -- separately (see migration 0011). ⚠ extended_price is ABSENT
			 -- because it is GENERATED ALWAYS and Postgres rejects an INSERT
			 -- that names it at all.
			 quantity, designators, package_footprint, supplier_sku,
			 preferred_supplier, unit_price, currency, do_not_populate,
			 assembly_type, lifecycle_status, datasheet_url)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,
		        $26,$27,$28,$29,$30,$31,$32,$33,$34,$35,$36)
		RETURNING id`,
		tenantID, docID, nullIfEmpty(parentID),
		c.ProductName, nullIfEmpty(c.ProductVersion), nullIfEmpty(c.ProductDetails), nullIfEmpty(c.WarrantyAMC),
		nullIfEmpty(c.ManufacturerName), nullIfEmpty(c.ManufacturerLocation), parseManufacturingDate(c.ManufacturingDate),
		nullIfEmpty(c.SupplierInfo), nullIfEmpty(c.SupplierLocation), nullIfEmpty(c.ModelNumber), nullIfEmpty(c.SerialNumber),
		nullIfEmpty(c.TechnicalSpecification), nullIfEmpty(c.ComponentSupplierInfo), nullIfEmpty(c.ComponentSupplierLocation),
		nullIfEmpty(c.TechnologyNode), textArrayOrNil(c.Compliance), nullIfEmpty(c.PowerSupply), nullIfEmpty(c.LicenseInfo), nullIfEmpty(c.TestResult),
		nullIfEmpty(c.FirmwareVersion), nullIfEmpty(c.Origin), nullIfEmpty(c.Criticality),
		// ⚠ CLAMPED TO AT LEAST 1, MATCHING THE IMPORTER. A Component built
		// somewhere other than Parse (the form, a partial edit) carries the Go
		// zero value, and 0 satisfies the CHECK but means "none of this part is
		// fitted" — which would silently zero every extended price.
		quantityOrOne(c.Quantity),
		// ⚠ AN EMPTY ARRAY, NOT NULL. `designators` is NOT NULL DEFAULT '{}';
		// textArrayOrNil returns nil for an empty slice, which is right for
		// `compliance` (nullable) and violates the constraint here.
		textArrayOrEmpty(c.Designators),
		nullIfEmpty(c.PackageFootprint),
		nullIfEmpty(c.SupplierSKU), nullIfEmpty(c.PreferredSupplier),
		// ⚠ THE PRICE GOES AS A STRING FOR POSTGRES TO CAST INTO numeric(18,6).
		// A float64 here would lose cents on values like 0.1, and the extended
		// price over a 4000-line BOM accumulates the error into a figure
		// somebody procures against. Same reasoning as bulk.py's
		// _hardware_price on the Python side.
		nullIfEmpty(c.UnitPrice), nullIfEmpty(c.Currency), c.DoNotPopulate,
		nullIfEmpty(c.AssemblyType), nullIfEmpty(c.LifecycleStatus), nullIfEmpty(c.DatasheetURL),
	).Scan(&id)
	if err != nil {
		return "", fmt.Errorf("insert hardware component: %w", err)
	}
	if err := replaceAlternates(ctx, tx, tenantID, id, c.Alternates); err != nil {
		return "", err
	}
	return id, nil
}

// replaceAlternates rewrites one component's approved second sources.
//
// ⚠ NOTHING IN THIS SERVICE WROTE THIS TABLE, AND THE API PRETENDED OTHERWISE.
//
// componentDTO has carried `alternates` in BOTH directions since the
// manufacturing fields landed — toAlternateDTOs on the way out,
// fromAlternateDTOs on the way in — and the store never touched
// normalize.hardware_component_alternates at all. So a client that sent
// alternates got 200 OK and silent discard, and a client that read them back
// always got `[]`. Only the report service ever read the table, and only the
// normalize pipeline ever filled it, which is why this looked like it worked:
// a SCANNED hardware BOM had alternates and an EDITED one lost them.
//
// ⚠ DELETE-THEN-INSERT, NOT AN UPSERT, and the whole point is the delete.
// Alternates are an ordered set belonging to one component, not independent
// rows with their own identity: removing a second source in the editor has to
// remove it from the database, and an upsert-only path silently keeps every
// alternate ever added. Both statements run inside the caller's transaction.
func replaceAlternates(
	ctx context.Context, tx db.Tx, tenantID, componentID string, alternates []hbom.Alternate,
) error {
	if _, err := tx.Exec(ctx,
		`DELETE FROM normalize.hardware_component_alternates WHERE hardware_component_id = $1`,
		componentID,
	); err != nil {
		return fmt.Errorf("clear hardware alternates: %w", err)
	}

	for i, a := range alternates {
		// Mirrors the hardware_alternate_identifiable CHECK. Skipped rather
		// than sent, so one blank row in the editor cannot fail the save.
		if a.ManufacturerName == "" && a.ModelNumber == "" && a.SupplierSKU == "" {
			continue
		}
		equivalence := a.Equivalence
		if equivalence == "" {
			// ⚠ `unverified` IS THE FLOOR, AND IT IS NEVER INFERRED UPWARD. An
			// alternate whose equivalence nobody stated is one nobody checked;
			// defaulting it to anything stronger would turn a blank field in a
			// spreadsheet into an approved substitution.
			equivalence = "unverified"
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO normalize.hardware_component_alternates
				(tenant_id, hardware_component_id, ordinal,
				 manufacturer_name, model_number, supplier_info, supplier_sku,
				 lifecycle_status, equivalence, approval_note)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
			tenantID, componentID, i,
			nullIfEmpty(a.ManufacturerName), nullIfEmpty(a.ModelNumber),
			nullIfEmpty(a.SupplierInfo), nullIfEmpty(a.SupplierSKU),
			nullIfEmpty(a.LifecycleStatus), equivalence, nullIfEmpty(a.ApprovalNote),
		); err != nil {
			return fmt.Errorf("insert hardware alternate: %w", err)
		}
	}
	return nil
}

// updateHardwareNode writes an existing node, scoped to the CALLER'S
// document — the WHERE clause is what stops a copied id from another
// project (same tenant, so RLS alone would not catch it) from redirecting
// the write.
func updateHardwareNode(
	ctx context.Context, tx db.Tx, tenantID, docID, id string, c *hbom.Component,
) error {
	// ⚠ THIS UPDATE SET ONLY THE CERT-In COLUMNS, AND THE INSERT NEXT TO IT
	// WROTE ELEVEN MORE.
	//
	// Quantity, designators, footprint, SKU, supplier, price, currency, DNP,
	// assembly type, lifecycle and datasheet were all writable on CREATE and
	// silently unwritable on EDIT — the API took them, returned 200, and left
	// the stored value exactly as it was. Nothing failed and nothing said so;
	// the user simply watched their change not happen. Every column the insert
	// writes, the update writes.
	tag, err := tx.Exec(ctx, `
		UPDATE normalize.hardware_components SET
			product_name = $3, product_version = $4, product_details = $5, warranty_amc = $6,
			manufacturer_name = $7, manufacturer_location = $8, manufacturing_date = $9,
			supplier_info = $10, supplier_location = $11, model_number = $12, serial_number = $13,
			technical_specification = $14, component_supplier_info = $15, component_supplier_location = $16,
			technology_node = $17, compliance = $18, power_supply = $19, license_info = $20,
			test_result = $21, firmware_version = $22, origin = $23, criticality = $24,
			-- Manufacturing and procurement. ⚠ extended_price stays absent: it
			-- is GENERATED ALWAYS and Postgres rejects an UPDATE naming it, the
			-- same reason the INSERT omits it.
			quantity = $25, designators = $26, package_footprint = $27, supplier_sku = $28,
			preferred_supplier = $29, unit_price = $30, currency = $31, do_not_populate = $32,
			assembly_type = $33, lifecycle_status = $34, datasheet_url = $35
		 WHERE id = $1 AND bom_document_id = $2`,
		id, docID,
		c.ProductName, nullIfEmpty(c.ProductVersion), nullIfEmpty(c.ProductDetails), nullIfEmpty(c.WarrantyAMC),
		nullIfEmpty(c.ManufacturerName), nullIfEmpty(c.ManufacturerLocation), parseManufacturingDate(c.ManufacturingDate),
		nullIfEmpty(c.SupplierInfo), nullIfEmpty(c.SupplierLocation), nullIfEmpty(c.ModelNumber), nullIfEmpty(c.SerialNumber),
		nullIfEmpty(c.TechnicalSpecification), nullIfEmpty(c.ComponentSupplierInfo), nullIfEmpty(c.ComponentSupplierLocation),
		nullIfEmpty(c.TechnologyNode), textArrayOrNil(c.Compliance), nullIfEmpty(c.PowerSupply), nullIfEmpty(c.LicenseInfo),
		nullIfEmpty(c.TestResult), nullIfEmpty(c.FirmwareVersion), nullIfEmpty(c.Origin), nullIfEmpty(c.Criticality),
		quantityOrOne(c.Quantity), textArrayOrEmpty(c.Designators), nullIfEmpty(c.PackageFootprint),
		nullIfEmpty(c.SupplierSKU), nullIfEmpty(c.PreferredSupplier),
		// A STRING for Postgres to cast into numeric(18,6) — see the insert.
		nullIfEmpty(c.UnitPrice), nullIfEmpty(c.Currency), c.DoNotPopulate,
		nullIfEmpty(c.AssemblyType), nullIfEmpty(c.LifecycleStatus), nullIfEmpty(c.DatasheetURL),
	)
	if err != nil {
		return fmt.Errorf("update hardware component: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrComponentNotFound
	}
	return replaceAlternates(ctx, tx, tenantID, id, c.Alternates)
}

// upsertNodeRecursive writes node (update if it carries an id, insert
// otherwise) and then every child, wiring each child's parent to the id this
// call just resolved — so a brand-new subtree submitted alongside an
// existing node still links up correctly.
func upsertNodeRecursive(ctx context.Context, tx db.Tx, tenantID, docID string, node *hbom.Component, parentID string) error {
	if node.ID != "" {
		if err := updateHardwareNode(ctx, tx, tenantID, docID, node.ID, node); err != nil {
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

// quantityOrOne floors a quantity at one.
//
// A part present in an assembly with no stated count is one of them. Zero
// satisfies the column's CHECK but means something different and would zero
// the extended price for that line.
func quantityOrOne(n int) int {
	if n < 1 {
		return 1
	}
	return n
}

// textArrayOrEmpty is textArrayOrNil for a NOT NULL text[] column.
//
// The distinction is not cosmetic: `compliance` is nullable, so NULL there
// means "not stated"; `designators` is NOT NULL DEFAULT '{}', so NULL is a
// constraint violation rather than an absence.
func textArrayOrEmpty(values []string) []string {
	if values == nil {
		return []string{}
	}
	return values
}
