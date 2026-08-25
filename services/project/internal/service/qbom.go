package service

import (
	"context"

	"github.com/axebom/axebom/services/project/internal/qbom"
)

// ---------------------------------------------------------------------------
// Quantum BOM (QBOM) device metadata
//
// ⚠ CAPTURED, NOT DISCOVERED. NOTHING HERE SCANS — every method here only
// ever reads what a human typed and what the store resolved from the
// project's own CBOM discovery. See services/project/internal/qbom's
// package doc for why this logic is a Go-native port of
// workers/qbom/metadata.py rather than a call into it.
// ---------------------------------------------------------------------------

// QBOMForm is the payload GET /v1/qbom/{projectId}/form returns: the field
// definitions the frontend renders a form from, plus the disclosure text
// that must ship alongside it.
type QBOMForm struct {
	Fields     []qbom.FormField
	Disclosure string
}

// GetQBOMForm returns the Table 8 form field definitions, generated from
// the profile — no CERT-In field count or list is ever hand-typed
// (CLAUDE.md invariant 2).
func (s *Service) GetQBOMForm() QBOMForm {
	return QBOMForm{Fields: qbom.FormFields(), Disclosure: qbom.FormDisclosure}
}

// GetQuantumDevice returns a project's current QBOM device metadata and its
// gaps. There is no validation to perform on read — see GetHardwareTree's
// identical shape.
func (s *Service) GetQuantumDevice(ctx context.Context, tenantID, projectID string) (*qbom.Device, []qbom.FieldGap, error) {
	device, gaps, err := s.store.GetQuantumDevice(ctx, tenantID, projectID)
	return device, gaps, mapStoreError(err)
}

// SaveQuantumDevice normalizes and persists a project's QBOM device
// metadata as a new version. Unlike HBOM's hardware component (which
// requires a product name), Table 8 has no field CERT-In marks mandatory at
// the point of capture — every element may be left blank and is reported as
// not-provided rather than rejected, exactly as workers/qbom/metadata.py's
// normalize_device() never rejects a payload.
func (s *Service) SaveQuantumDevice(ctx context.Context, tenantID, projectID string, values qbom.DeviceValues) (*qbom.Device, []qbom.FieldGap, string, error) {
	device, gaps, docID, err := s.store.SaveQuantumDevice(ctx, tenantID, projectID, values)
	return device, gaps, docID, mapStoreError(err)
}
