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
// Hardware devices — project.hardware_devices
//
// ⚠ THIS TABLE IS IN THIS SERVICE'S OWN SCHEMA, AND THE PARTS LIST IS NOT.
// Identity lives here; the versioned tree lives in normalize.hardware_components
// and is linked by normalize.bom_documents.device_id — a plain uuid with no FK,
// because an FK across a schema boundary is a JOIN dependency that would block
// extracting this service later (ADR-0001). The two are joined in Go, never in
// SQL (invariant 11).
// ---------------------------------------------------------------------------

// ErrSerialTaken is returned when a serial number or asset tag is already
// registered to another device in this tenant.
//
// ⚠ A DISTINCT SENTINEL, BECAUSE IT IS A DIFFERENT ANSWER FROM "not found".
// A duplicate serial means the caller is registering a unit somebody already
// registered — that is a 409 and a pointer to the existing row, not a 404 and
// not a validation error about the shape of their input.
var ErrSerialTaken = errors.New("a device with this serial number or asset tag is already registered")

// ListDevices returns a project's registered devices, newest first, each with
// the size and date of its current parts list.
func (s *Store) ListDevices(ctx context.Context, tenantID, projectID string) ([]*hbom.Device, error) {
	var out []*hbom.Device
	err := s.pool.WithTenant(ctx, tenantID, func(ctx context.Context, tx db.Tx) error {
		if err := projectExists(ctx, tx, projectID); err != nil {
			return err
		}

		rows, err := tx.Query(ctx, deviceColumns+`
			  FROM project.hardware_devices
			 WHERE project_id = $1 AND deleted_at IS NULL
			 ORDER BY id DESC`, projectID)
		if err != nil {
			return fmt.Errorf("list devices: %w", err)
		}
		defer rows.Close()

		for rows.Next() {
			d, err := scanDevice(rows)
			if err != nil {
				return err
			}
			out = append(out, d)
		}
		if err := rows.Err(); err != nil {
			return fmt.Errorf("list devices: %w", err)
		}

		// ⚠ A SECOND QUERY, NOT A JOIN. normalize.bom_documents is another
		// schema; joining it here is exactly what invariant 11 forbids, and it
		// is the discipline that keeps this service extractable. The cost is one
		// extra round trip on a list that is tens of rows, not thousands.
		for _, d := range out {
			if err := attachPartsSummary(ctx, tx, d); err != nil {
				return err
			}
		}
		return nil
	})
	return out, err
}

// GetDevice reads one device.
//
// ⚠ SCOPED BY PROJECT AS WELL AS ID, SO THE URL CANNOT LIE. The route is
// /v1/hbom/{projectId}/devices/{deviceId}; a device id from a different project
// must 404 rather than quietly return a row the path says belongs elsewhere.
// RLS already handles the cross-TENANT case; this handles cross-project.
func (s *Store) GetDevice(ctx context.Context, tenantID, projectID, deviceID string) (*hbom.Device, error) {
	var out *hbom.Device
	err := s.pool.WithTenant(ctx, tenantID, func(ctx context.Context, tx db.Tx) error {
		row := tx.QueryRow(ctx, deviceColumns+`
			  FROM project.hardware_devices
			 WHERE id = $1 AND project_id = $2 AND deleted_at IS NULL`, deviceID, projectID)
		d, err := scanDevice(row)
		if errors.Is(err, pgx.ErrNoRows) {
			// Absent and another tenant's are the same answer, because RLS
			// makes them the same query result (invariant 6).
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		out = d
		return attachPartsSummary(ctx, tx, d)
	})
	return out, err
}

// CreateDevice registers a device.
func (s *Store) CreateDevice(ctx context.Context, tenantID, projectID, createdBy string,
	d *hbom.Device,
) (*hbom.Device, error) {
	var out *hbom.Device
	err := s.pool.WithTenant(ctx, tenantID, func(ctx context.Context, tx db.Tx) error {
		if err := projectExists(ctx, tx, projectID); err != nil {
			return err
		}

		row := tx.QueryRow(ctx, `
			INSERT INTO project.hardware_devices
				(tenant_id, project_id, name, manufacturer, model_number,
				 serial_number, lot_number, asset_tag, firmware_version,
				 location, criticality, notes, created_by)
			VALUES ($1,$2,$3,`+deviceNullables+`,$13)
			RETURNING `+deviceReturning,
			tenantID, projectID, d.Name,
			nullIfEmpty(d.Manufacturer), nullIfEmpty(d.ModelNumber),
			nullIfEmpty(d.SerialNumber), nullIfEmpty(d.LotNumber),
			nullIfEmpty(d.AssetTag), nullIfEmpty(d.FirmwareVersion),
			nullIfEmpty(d.Location), nullIfEmpty(d.Criticality),
			nullIfEmpty(d.Notes), createdBy)

		created, err := scanDevice(row)
		if err != nil {
			if isUniqueViolation(err, "hardware_devices_serial_idx") ||
				isUniqueViolation(err, "hardware_devices_asset_tag_idx") {
				return ErrSerialTaken
			}
			return err
		}
		created.ProjectID = projectID
		out = created
		return nil
	})
	return out, err
}

// UpdateDevice edits a device's registration fields.
//
// ⚠ IT DOES NOT TOUCH THE PARTS LIST. Re-importing parts is a separate action
// with its own versioning; editing the label on a device must not silently
// discard a tree, which is what a single "replace the device" write would do.
func (s *Store) UpdateDevice(ctx context.Context, tenantID, projectID, deviceID string,
	d *hbom.Device,
) (*hbom.Device, error) {
	var out *hbom.Device
	err := s.pool.WithTenant(ctx, tenantID, func(ctx context.Context, tx db.Tx) error {
		row := tx.QueryRow(ctx, `
			UPDATE project.hardware_devices
			   SET name = $2, manufacturer = $3, model_number = $4,
			       serial_number = $5, lot_number = $6, asset_tag = $7,
			       firmware_version = $8, location = $9, criticality = $10,
			       notes = $11
			 WHERE id = $1 AND project_id = $12 AND deleted_at IS NULL
			 RETURNING `+deviceReturning,
			deviceID, d.Name,
			nullIfEmpty(d.Manufacturer), nullIfEmpty(d.ModelNumber),
			nullIfEmpty(d.SerialNumber), nullIfEmpty(d.LotNumber),
			nullIfEmpty(d.AssetTag), nullIfEmpty(d.FirmwareVersion),
			nullIfEmpty(d.Location), nullIfEmpty(d.Criticality),
			nullIfEmpty(d.Notes), projectID)

		updated, err := scanDevice(row)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			if isUniqueViolation(err, "hardware_devices_serial_idx") ||
				isUniqueViolation(err, "hardware_devices_asset_tag_idx") {
				return ErrSerialTaken
			}
			return err
		}
		out = updated
		return attachPartsSummary(ctx, tx, updated)
	})
	return out, err
}

// DeleteDevice soft-deletes a device.
//
// ⚠ SOFT, AND THE PARTS DOCUMENTS ARE LEFT ALONE. A bom_document is an
// immutable normalization artifact (invariant 10); deleting the device it
// describes must not delete the evidence. The document keeps its device_id and
// simply stops being reachable through the device list.
func (s *Store) DeleteDevice(ctx context.Context, tenantID, projectID, deviceID string) error {
	return s.pool.WithTenant(ctx, tenantID, func(ctx context.Context, tx db.Tx) error {
		tag, err := tx.Exec(ctx, `
			UPDATE project.hardware_devices
			   SET deleted_at = now()
			 WHERE id = $1 AND project_id = $2 AND deleted_at IS NULL`, deviceID, projectID)
		if err != nil {
			return fmt.Errorf("delete device: %w", err)
		}
		if tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		return nil
	})
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const deviceColumns = `
	SELECT id, project_id, name,
	       COALESCE(manufacturer,''), COALESCE(model_number,''),
	       COALESCE(serial_number,''), COALESCE(lot_number,''),
	       COALESCE(asset_tag,''), COALESCE(firmware_version,''),
	       COALESCE(location,''), COALESCE(criticality,''), COALESCE(notes,''),
	       created_at, updated_at`

const deviceReturning = `id, project_id, name,
	       COALESCE(manufacturer,''), COALESCE(model_number,''),
	       COALESCE(serial_number,''), COALESCE(lot_number,''),
	       COALESCE(asset_tag,''), COALESCE(firmware_version,''),
	       COALESCE(location,''), COALESCE(criticality,''), COALESCE(notes,''),
	       created_at, updated_at`

const deviceNullables = `$4,$5,$6,$7,$8,$9,$10,$11,$12`

// rowScanner is satisfied by both pgx.Row and pgx.Rows.
type rowScanner interface{ Scan(dest ...any) error }

func scanDevice(row rowScanner) (*hbom.Device, error) {
	var d hbom.Device
	var createdAt, updatedAt time.Time
	if err := row.Scan(&d.ID, &d.ProjectID, &d.Name,
		&d.Manufacturer, &d.ModelNumber, &d.SerialNumber, &d.LotNumber,
		&d.AssetTag, &d.FirmwareVersion, &d.Location, &d.Criticality, &d.Notes,
		&createdAt, &updatedAt); err != nil {
		return nil, err
	}
	// RFC3339 with a literal Z. No local time anywhere, ever.
	d.CreatedAt = createdAt.UTC().Format(time.RFC3339)
	d.UpdatedAt = updatedAt.UTC().Format(time.RFC3339)
	return &d, nil
}

// attachPartsSummary fills in the device's current parts list, if it has one.
//
// ⚠ AN ABSENT DOCUMENT IS NOT AN ERROR, IT IS THE ORDINARY STARTING STATE.
// Registering a device and importing its parts are two separate acts, and a
// device with none is exactly what the UI has to be able to show — with an
// empty PartsUpdatedAt saying so rather than a zero component count implying
// the parts list was read and found empty.
func attachPartsSummary(ctx context.Context, tx db.Tx, d *hbom.Device) error {
	var docID string
	var generatedAt time.Time
	err := tx.QueryRow(ctx, `
		SELECT id, generated_at
		  FROM normalize.bom_documents
		 WHERE device_id = $1 AND bom_type = 'HBOM'
		 ORDER BY generated_at DESC, normalization_version DESC
		 LIMIT 1`, d.ID).Scan(&docID, &generatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("resolve device parts document: %w", err)
	}

	var count int
	if err := tx.QueryRow(ctx, `
		SELECT count(*) FROM normalize.hardware_components
		 WHERE bom_document_id = $1`, docID).Scan(&count); err != nil {
		return fmt.Errorf("count device parts: %w", err)
	}

	d.BOMDocumentID = docID
	d.PartsUpdatedAt = generatedAt.UTC().Format(time.RFC3339)
	d.ComponentCount = count
	return nil
}
