package handler

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/axebom/axebom/libs/go-shared/auth"
	"github.com/axebom/axebom/libs/go-shared/platform/errs"
	"github.com/axebom/axebom/services/project/internal/hbom"
)

// ---------------------------------------------------------------------------
// Hardware BOM
//
// ⚠ EVERY RESPONSE HERE IS LABELLED "IMPORT". NOTHING HERE SCANS — see
// services/project/internal/hbom's package doc and frontend/src/lib/hbom.ts's
// own header comment, which this surface exists to honour.
// ---------------------------------------------------------------------------

// maxHBOMFileBytes bounds a CSV upload before it is parsed. HBOM's own
// MaxRows (50,000) already caps row count; this caps the bytes read to get
// there, so a request body cannot be used to exhaust memory before that
// check ever runs.
const maxHBOMFileBytes = 32 << 20 // 32 MiB

// componentDTO mirrors frontend/src/lib/hbom.ts's HardwareComponent exactly.
//
// ⚠ NOT EVERY hbom.Component FIELD IS HERE. ProductDetails and
// ManufacturingDate exist in normalize.hardware_components and in
// workers/hbom/model.py's 24-field model, but the frontend's own
// HardwareComponent type does not expose them yet — this DTO matches the
// CONTRACT the frontend actually calls, not the full CERT-In field set. See
// the final report note on this gap.
type componentDTO struct {
	ID       string  `json:"id"`
	ParentID *string `json:"parent_id"`
	Depth    int     `json:"depth"`
	Quantity int     `json:"quantity"`

	ProductName    string `json:"product_name"`
	ProductVersion string `json:"product_version"`
	ModelNumber    string `json:"model_number"`
	SerialNumber   string `json:"serial_number"`

	ManufacturerName     string `json:"manufacturer_name"`
	ManufacturerLocation string `json:"manufacturer_location"`
	Origin               string `json:"origin"`

	SupplierInfo              string `json:"supplier_info"`
	SupplierLocation          string `json:"supplier_location"`
	ComponentSupplierInfo     string `json:"component_supplier_info"`
	ComponentSupplierLocation string `json:"component_supplier_location"`

	FirmwareVersion        string   `json:"firmware_version"`
	Criticality            string   `json:"criticality"`
	TechnologyNode         string   `json:"technology_node"`
	Compliance             []string `json:"compliance"`
	PowerSupply            string   `json:"power_supply"`
	TechnicalSpecification string   `json:"technical_specification"`

	WarrantyAMC string `json:"warranty_amc"`
	LicenseInfo string `json:"license_info"`
	TestResult  string `json:"test_result"`

	Findings       []string          `json:"findings"`
	EnrichedFields map[string]string `json:"enriched_fields"`

	Children []componentDTO `json:"children"`
}

func toComponentDTO(c *hbom.Component, depth int) componentDTO {
	dto := componentDTO{
		ID:                        c.ID,
		Depth:                     depth,
		Quantity:                  c.Quantity,
		ProductName:               c.ProductName,
		ProductVersion:            c.ProductVersion,
		ModelNumber:               c.ModelNumber,
		SerialNumber:              c.SerialNumber,
		ManufacturerName:          c.ManufacturerName,
		ManufacturerLocation:      c.ManufacturerLocation,
		Origin:                    c.Origin,
		SupplierInfo:              c.SupplierInfo,
		SupplierLocation:          c.SupplierLocation,
		ComponentSupplierInfo:     c.ComponentSupplierInfo,
		ComponentSupplierLocation: c.ComponentSupplierLocation,
		FirmwareVersion:           c.FirmwareVersion,
		Criticality:               c.Criticality,
		TechnologyNode:            c.TechnologyNode,
		Compliance:                emptyIfNil(c.Compliance),
		PowerSupply:               c.PowerSupply,
		TechnicalSpecification:    c.TechnicalSpecification,
		WarrantyAMC:               c.WarrantyAMC,
		LicenseInfo:               c.LicenseInfo,
		TestResult:                c.TestResult,
		Findings:                  emptyIfNil(c.Findings),
		EnrichedFields:            c.EnrichedFields,
	}
	if c.ParentID != "" {
		dto.ParentID = &c.ParentID
	}
	dto.Children = make([]componentDTO, 0, len(c.Children))
	for _, child := range c.Children {
		dto.Children = append(dto.Children, toComponentDTO(child, depth+1))
	}
	return dto
}

func emptyIfNil(v []string) []string {
	if v == nil {
		return []string{}
	}
	return v
}

func (dto componentDTO) toComponent() *hbom.Component {
	c := &hbom.Component{
		ID:                        dto.ID,
		Quantity:                  dto.Quantity,
		ProductName:               dto.ProductName,
		ProductVersion:            dto.ProductVersion,
		ModelNumber:               dto.ModelNumber,
		SerialNumber:              dto.SerialNumber,
		ManufacturerName:          dto.ManufacturerName,
		ManufacturerLocation:      dto.ManufacturerLocation,
		Origin:                    dto.Origin,
		SupplierInfo:              dto.SupplierInfo,
		SupplierLocation:          dto.SupplierLocation,
		ComponentSupplierInfo:     dto.ComponentSupplierInfo,
		ComponentSupplierLocation: dto.ComponentSupplierLocation,
		FirmwareVersion:           dto.FirmwareVersion,
		Criticality:               dto.Criticality,
		TechnologyNode:            dto.TechnologyNode,
		Compliance:                dto.Compliance,
		PowerSupply:               dto.PowerSupply,
		TechnicalSpecification:    dto.TechnicalSpecification,
		WarrantyAMC:               dto.WarrantyAMC,
		LicenseInfo:               dto.LicenseInfo,
		TestResult:                dto.TestResult,
	}
	if dto.ParentID != nil {
		c.ParentID = *dto.ParentID
	}
	if dto.Quantity == 0 {
		c.Quantity = 1
	}
	for _, child := range dto.Children {
		c.Children = append(c.Children, child.toComponent())
	}
	return c
}

func toComponentDTOs(roots []*hbom.Component) []componentDTO {
	out := make([]componentDTO, 0, len(roots))
	for _, r := range roots {
		out = append(out, toComponentDTO(r, 0))
	}
	return out
}

// importPreviewDTO mirrors frontend/src/lib/hbom.ts's ImportPreview.
type importPreviewDTO struct {
	Roots           []componentDTO `json:"roots"`
	ComponentCount  int            `json:"component_count"`
	MaxDepth        int            `json:"max_depth"`
	UnmappedHeaders []string       `json:"unmapped_headers"`
	Warnings        []string       `json:"warnings"`
}

func toImportPreviewDTO(r *hbom.ImportResult) importPreviewDTO {
	return importPreviewDTO{
		Roots:           toComponentDTOs(r.Roots),
		ComponentCount:  r.Total(),
		MaxDepth:        r.MaxDepthReached(),
		UnmappedHeaders: emptyIfNil(r.UnmappedHeaders),
		Warnings:        emptyIfNil(r.Warnings),
	}
}

// GetHardwareTree handles GET /v1/hbom/{projectId}.
func (h *Handler) GetHardwareTree(w http.ResponseWriter, r *http.Request) {
	tenantID, err := auth.RequireTenant(r.Context())
	if err != nil {
		errs.Write(w, r, err)
		return
	}
	roots, err := h.svc.GetHardwareTree(r.Context(), tenantID, r.PathValue("projectId"))
	if err != nil {
		errs.Write(w, r, err)
		return
	}
	errs.WriteJSON(w, http.StatusOK, map[string]any{"roots": toComponentDTOs(roots)})
}

// SaveHardwareComponent handles POST /v1/hbom/{projectId}/components.
func (h *Handler) SaveHardwareComponent(w http.ResponseWriter, r *http.Request) {
	tenantID, err := auth.RequireTenant(r.Context())
	if err != nil {
		errs.Write(w, r, err)
		return
	}

	var dto componentDTO
	if err := decode(r, &dto); err != nil {
		errs.Write(w, r, err)
		return
	}

	saved, err := h.svc.SaveHardwareComponent(r.Context(), tenantID, r.PathValue("projectId"), dto.toComponent())
	if err != nil {
		errs.Write(w, r, err)
		return
	}
	errs.WriteJSON(w, http.StatusOK, toComponentDTO(saved, 0))
}

// PreviewHBOMImport handles POST /v1/hbom/preview.
//
// Parses the file and returns the tree it WOULD produce. Nothing is stored —
// see HardwareImport.tsx's own comment on why the preview step exists.
func (h *Handler) PreviewHBOMImport(w http.ResponseWriter, r *http.Request) {
	if _, err := auth.RequireTenant(r.Context()); err != nil {
		errs.Write(w, r, err)
		return
	}

	data, mapping, err := readHBOMUpload(w, r)
	if err != nil {
		errs.Write(w, r, err)
		return
	}

	result, err := h.svc.PreviewHBOMImport(data, mapping)
	if err != nil {
		errs.Write(w, r, err)
		return
	}
	errs.WriteJSON(w, http.StatusOK, toImportPreviewDTO(result))
}

// ConfirmHBOMImport handles POST /v1/hbom/{projectId}/import.
func (h *Handler) ConfirmHBOMImport(w http.ResponseWriter, r *http.Request) {
	tenantID, err := auth.RequireTenant(r.Context())
	if err != nil {
		errs.Write(w, r, err)
		return
	}

	data, mapping, err := readHBOMUpload(w, r)
	if err != nil {
		errs.Write(w, r, err)
		return
	}

	// project_id also travels in the form body (see useConfirmImport in
	// hbom.ts), but the path value is what routes.go and every other handler
	// in this service treats as authoritative — a form field is not trusted
	// over it.
	docID, err := h.svc.ImportHBOM(r.Context(), tenantID, r.PathValue("projectId"), data, mapping)
	if err != nil {
		errs.Write(w, r, err)
		return
	}
	errs.WriteJSON(w, http.StatusCreated, map[string]any{"bom_document_id": docID})
}

// readHBOMUpload parses the multipart body every HBOM file endpoint shares:
// a `file` field and a `mapping` field holding a JSON object of
// header -> canonical column id.
func readHBOMUpload(w http.ResponseWriter, r *http.Request) ([]byte, map[string]string, error) {
	r.Body = http.MaxBytesReader(w, r.Body, maxHBOMFileBytes+(1<<20))

	//nolint:gosec // G120: the body is already bounded by the MaxBytesReader above.
	if err := r.ParseMultipartForm(8 << 20); err != nil {
		return nil, nil, errs.Wrap(err, errs.ValidationBodyMalformed,
			"could not read the upload; it may exceed the size limit")
	}
	defer func() {
		if r.MultipartForm != nil {
			_ = r.MultipartForm.RemoveAll()
		}
	}()

	file, _, err := r.FormFile("file")
	if err != nil {
		return nil, nil, errs.New(errs.ValidationFieldRequired,
			"attach the file in a form field named 'file'")
	}
	defer func() { _ = file.Close() }()

	data, err := io.ReadAll(io.LimitReader(file, maxHBOMFileBytes))
	if err != nil {
		return nil, nil, errs.Wrap(err, errs.ValidationBodyMalformed, "could not read the uploaded file")
	}

	mapping := map[string]string{}
	if raw := strings.TrimSpace(r.FormValue("mapping")); raw != "" {
		if err := json.Unmarshal([]byte(raw), &mapping); err != nil {
			return nil, nil, errs.Wrap(err, errs.ValidationBodyMalformed,
				"the 'mapping' field is not valid JSON")
		}
	}

	return data, mapping, nil
}

// LookupParts handles POST /v1/hbom/lookup.
func (h *Handler) LookupParts(w http.ResponseWriter, r *http.Request) {
	if _, err := auth.RequireTenant(r.Context()); err != nil {
		errs.Write(w, r, err)
		return
	}

	var req struct {
		MPNs []string `json:"mpns"`
	}
	if err := decode(r, &req); err != nil {
		errs.Write(w, r, err)
		return
	}

	provider, enrichments := h.svc.LookupParts(r.Context(), req.MPNs)

	out := make(map[string]map[string]any, len(enrichments))
	for mpn, e := range enrichments {
		fields := map[string]any{}
		if e.ManufacturerName != "" {
			fields["manufacturer_name"] = e.ManufacturerName
		}
		if e.ManufacturerLocation != "" {
			fields["manufacturer_location"] = e.ManufacturerLocation
		}
		if e.Origin != "" {
			fields["origin"] = e.Origin
		}
		if e.TechnologyNode != "" {
			fields["technology_node"] = e.TechnologyNode
		}
		if len(e.Compliance) > 0 {
			fields["compliance"] = e.Compliance
		}
		out[mpn] = fields
	}

	errs.WriteJSON(w, http.StatusOK, map[string]any{
		"provider":    provider,
		"enrichments": out,
	})
}

// PartProvider handles GET /v1/hbom/provider.
func (h *Handler) PartProvider(w http.ResponseWriter, r *http.Request) {
	if _, err := auth.RequireTenant(r.Context()); err != nil {
		errs.Write(w, r, err)
		return
	}
	provider, configured := h.svc.PartProvider()
	errs.WriteJSON(w, http.StatusOK, map[string]any{
		"provider":   provider,
		"configured": configured,
	})
}
