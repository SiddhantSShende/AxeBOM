package handler

import (
	"net/http"

	"github.com/axebom/axebom/libs/go-shared/auth"
	"github.com/axebom/axebom/libs/go-shared/platform/errs"
	"github.com/axebom/axebom/services/project/internal/qbom"
)

// ---------------------------------------------------------------------------
// Quantum BOM (QBOM) device metadata
//
// ⚠ EVERY RESPONSE HERE IS LABELLED "CAPTURED", NEVER "SCANNED" — see
// services/project/internal/qbom's package doc. There is no open-source
// quantum-hardware scanner; the cryptographic-asset reference is derived
// from CBOM discovery, and the remaining ten elements of Table 8 come from
// this form.
// ---------------------------------------------------------------------------

// formFieldDTO mirrors one entry of qbom.FormFields() for the frontend.
type formFieldDTO struct {
	FieldID       string `json:"field_id"`
	Name          string `json:"name"`
	CanonicalPath string `json:"canonical_path"`
	Type          string `json:"type"`
	SourcePage    int    `json:"source_page"`
	Derived       bool   `json:"derived"`
}

func toFormFieldDTOs(fields []qbom.FormField) []formFieldDTO {
	out := make([]formFieldDTO, 0, len(fields))
	for _, f := range fields {
		out = append(out, formFieldDTO{
			FieldID:       f.FieldID,
			Name:          f.Name,
			CanonicalPath: f.CanonicalPath,
			Type:          f.Type,
			SourcePage:    f.SourcePage,
			Derived:       f.Derived,
		})
	}
	return out
}

// gapDTO mirrors one qbom.FieldGap.
type gapDTO struct {
	FieldID string `json:"field_id"`
	Name    string `json:"name"`
	Reason  string `json:"reason"`
}

func toGapDTOs(gaps []qbom.FieldGap) []gapDTO {
	out := make([]gapDTO, 0, len(gaps))
	for _, g := range gaps {
		out = append(out, gapDTO{FieldID: g.FieldID, Name: g.Name, Reason: g.Reason})
	}
	return out
}

// deviceDTO mirrors one normalize.quantum_components row, plus the two
// derived reference lists and every field's status.
type deviceDTO struct {
	ModelName             string   `json:"model_name"`
	Version               string   `json:"version"`
	VendorOrigin          string   `json:"vendor_origin"`
	LicenseInfo           string   `json:"license_info"`
	CommunicationProtocol string   `json:"communication_protocol"`
	Hardware              string   `json:"hardware"`
	SoftwareDependencies  []string `json:"software_dependencies"`
	EnvironmentalImpact   string   `json:"environmental_impact"`
	AttestationSignature  string   `json:"attestation_signature"`

	// CryptoAssetRefs and FindingRefs are REFERENCES into the project's CBOM
	// discovery, not copies — see qbom.Device's doc comment. FindingRefs is
	// always empty: this codebase has no concept of a vulnerability matched
	// against a crypto asset yet.
	CryptoAssetRefs []string `json:"crypto_asset_refs"`
	FindingRefs     []string `json:"finding_refs"`

	FieldStatus map[string]string `json:"field_status"`
	Gaps        []gapDTO          `json:"gaps"`
}

func toDeviceDTO(d *qbom.Device, gaps []qbom.FieldGap) deviceDTO {
	return deviceDTO{
		ModelName:             d.ModelName,
		Version:               d.Version,
		VendorOrigin:          d.VendorOrigin,
		LicenseInfo:           d.LicenseInfo,
		CommunicationProtocol: d.CommunicationProtocol,
		Hardware:              d.Hardware,
		SoftwareDependencies:  emptyIfNil(d.SoftwareDependencies),
		EnvironmentalImpact:   d.EnvironmentalImpact,
		AttestationSignature:  d.AttestationSignature,
		CryptoAssetRefs:       emptyIfNil(d.CryptoAssetRefs),
		FindingRefs:           emptyIfNil(d.FindingRefs),
		FieldStatus:           d.FieldStatus,
		Gaps:                  toGapDTOs(gaps),
	}
}

// deviceValuesDTO is the POST body for saving device metadata — the nine
// elements Table 8 captures by form or import. crypto_assets and findings
// are intentionally absent: a client cannot submit them, because they are
// derived server-side from the project's CBOM (qbom.IsDerived).
type deviceValuesDTO struct {
	ModelName             string   `json:"model_name"`
	Version               string   `json:"version"`
	VendorOrigin          string   `json:"vendor_origin"`
	LicenseInfo           string   `json:"license_info"`
	CommunicationProtocol string   `json:"communication_protocol"`
	Hardware              string   `json:"hardware"`
	SoftwareDependencies  []string `json:"software_dependencies"`
	EnvironmentalImpact   string   `json:"environmental_impact"`
	AttestationSignature  string   `json:"attestation_signature"`
}

func (dto deviceValuesDTO) toValues() qbom.DeviceValues {
	return qbom.DeviceValues{
		ModelName:             dto.ModelName,
		Version:               dto.Version,
		VendorOrigin:          dto.VendorOrigin,
		LicenseInfo:           dto.LicenseInfo,
		CommunicationProtocol: dto.CommunicationProtocol,
		Hardware:              dto.Hardware,
		SoftwareDependencies:  dto.SoftwareDependencies,
		EnvironmentalImpact:   dto.EnvironmentalImpact,
		AttestationSignature:  dto.AttestationSignature,
	}
}

// GetQBOMForm handles GET /v1/qbom/{projectId}/form.
//
// The field definitions do not depend on projectId today — Table 8 is the
// same form for every project — but the route carries the id anyway so a
// future per-tenant profile override (docs/06-COMPLIANCE-PROFILES.md) has
// somewhere to hang without a breaking route change, matching how
// GET /v1/hbom/provider is likewise project-independent today.
func (h *Handler) GetQBOMForm(w http.ResponseWriter, r *http.Request) {
	if _, err := auth.RequireTenant(r.Context()); err != nil {
		errs.Write(w, r, err)
		return
	}
	h.writeQBOMForm(w, r)
}

// GetQBOMRegistrationForm handles GET /v1/qbom/form.
//
// ⚠ THE PROJECT-LESS TWIN OF THE ROUTE ABOVE, AND IT EXISTS FOR THE ONE CALLER
// THAT HAS NO PROJECT ID: the registration wizard. Table 8's elements are the
// only part of a QBOM no scan can produce, and they were asked for on a screen
// reachable only AFTER the project existed — so registration asked a QBOM
// project exactly the same questions as an SBOM one, and the form a QBOM
// cannot do without became a checklist item read later, if at all.
//
// Both routes render the same generated list. GetQBOMForm keeps its projectId
// for the reason its own comment gives (somewhere for a future per-PROJECT
// profile override to hang); a per-TENANT override, which is the only kind that
// could apply before a project exists, has the tenant from the token either way.
func (h *Handler) GetQBOMRegistrationForm(w http.ResponseWriter, r *http.Request) {
	if _, err := auth.RequireTenant(r.Context()); err != nil {
		errs.Write(w, r, err)
		return
	}
	h.writeQBOMForm(w, r)
}

// writeQBOMForm is the one body both routes return. Two handlers assembling the
// same JSON by hand is how the registration form and the project form would
// come to disagree about what Table 8 contains.
func (h *Handler) writeQBOMForm(w http.ResponseWriter, _ *http.Request) {
	form := h.svc.GetQBOMForm()
	errs.WriteJSON(w, http.StatusOK, map[string]any{
		"fields":     toFormFieldDTOs(form.Fields),
		"disclosure": form.Disclosure,
	})
}

// GetQuantumDevice handles GET /v1/qbom/{projectId}.
func (h *Handler) GetQuantumDevice(w http.ResponseWriter, r *http.Request) {
	tenantID, err := auth.RequireTenant(r.Context())
	if err != nil {
		errs.Write(w, r, err)
		return
	}
	device, gaps, err := h.svc.GetQuantumDevice(r.Context(), tenantID, r.PathValue("projectId"))
	if err != nil {
		errs.Write(w, r, err)
		return
	}
	errs.WriteJSON(w, http.StatusOK, toDeviceDTO(device, gaps))
}

// SaveQuantumDevice handles POST /v1/qbom/{projectId}/device.
func (h *Handler) SaveQuantumDevice(w http.ResponseWriter, r *http.Request) {
	tenantID, err := auth.RequireTenant(r.Context())
	if err != nil {
		errs.Write(w, r, err)
		return
	}

	var dto deviceValuesDTO
	if err := decode(r, &dto); err != nil {
		errs.Write(w, r, err)
		return
	}

	device, gaps, docID, err := h.svc.SaveQuantumDevice(r.Context(), tenantID, r.PathValue("projectId"), dto.toValues())
	if err != nil {
		errs.Write(w, r, err)
		return
	}
	errs.WriteJSON(w, http.StatusCreated, map[string]any{
		"bom_document_id": docID,
		"device":          toDeviceDTO(device, gaps),
	})
}
