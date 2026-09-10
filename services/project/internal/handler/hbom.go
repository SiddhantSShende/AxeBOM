package handler

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/axebom/axebom/libs/go-shared/auth"
	"github.com/axebom/axebom/libs/go-shared/platform/ctxkey"
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
// ⚠ THIS COMMENT USED TO SAY ProductDetails AND ManufacturingDate WERE NOT
// HERE. They are — forty lines below, with a second comment correctly
// describing the gap in the past tense. Both fields round-trip through all
// three tiers now.
//
// It is left recorded rather than deleted because the failure it describes is
// the one this struct exists to prevent: a field the database stores, the
// model carries and this DTO omits is a field the UI silently discards on
// save. `extended_price` is the remaining instance — a generated column the
// report reads and this API does not return.
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

	// ⚠ TWO OF THE 24 CERT-In ELEMENTS THAT COULD NOT ROUND-TRIP THROUGH THIS
	// API. The database has both and the model has both; this DTO did not, so a
	// component edited through the UI came back without them and a save wrote
	// them away. A field the product stores and refuses to hand back is worse
	// than one it never had.
	ProductDetails    string `json:"product_details"`
	ManufacturingDate string `json:"manufacturing_date"`

	// --- manufacturing and procurement -------------------------------------
	// Not CERT-In elements; scored separately. See migration 0011.
	Designators       []string `json:"designators"`
	PackageFootprint  string   `json:"package_footprint"`
	SupplierSKU       string   `json:"supplier_sku"`
	PreferredSupplier string   `json:"preferred_supplier"`
	// A STRING, deliberately: JSON numbers are float64 and 0.0018 does not
	// survive the round trip exactly. The column is numeric(18,6).
	UnitPrice       string `json:"unit_price"`
	Currency        string `json:"currency"`
	DoNotPopulate   bool   `json:"do_not_populate"`
	AssemblyType    string `json:"assembly_type"`
	LifecycleStatus string `json:"lifecycle_status"`
	DatasheetURL    string `json:"datasheet_url"`

	Alternates []alternateDTO `json:"alternates"`

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
		ProductDetails:            c.ProductDetails,
		ManufacturingDate:         c.ManufacturingDate,
		Designators:               emptyIfNil(c.Designators),
		PackageFootprint:          c.PackageFootprint,
		SupplierSKU:               c.SupplierSKU,
		PreferredSupplier:         c.PreferredSupplier,
		UnitPrice:                 c.UnitPrice,
		Currency:                  c.Currency,
		DoNotPopulate:             c.DoNotPopulate,
		AssemblyType:              c.AssemblyType,
		LifecycleStatus:           c.LifecycleStatus,
		DatasheetURL:              c.DatasheetURL,
		Alternates:                toAlternateDTOs(c.Alternates),
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

// alternateDTO is one approved second source.
type alternateDTO struct {
	Ordinal          int    `json:"ordinal"`
	ManufacturerName string `json:"manufacturer_name"`
	ModelNumber      string `json:"model_number"`
	SupplierInfo     string `json:"supplier_info"`
	SupplierSKU      string `json:"supplier_sku"`
	LifecycleStatus  string `json:"lifecycle_status"`
	// ⚠ THE UI MUST ALWAYS SHOW THIS BESIDE THE PART NUMBER. An alternate's MPN
	// on its own reads as an approved substitution; "unverified" beside it is
	// the difference between a decision somebody made and one nobody has.
	Equivalence  string `json:"equivalence"`
	ApprovalNote string `json:"approval_note"`
}

func toAlternateDTOs(alternates []hbom.Alternate) []alternateDTO {
	out := make([]alternateDTO, 0, len(alternates))
	for _, a := range alternates {
		out = append(out, alternateDTO{
			Ordinal: a.Ordinal, ManufacturerName: a.ManufacturerName,
			ModelNumber: a.ModelNumber, SupplierInfo: a.SupplierInfo,
			SupplierSKU: a.SupplierSKU, LifecycleStatus: a.LifecycleStatus,
			Equivalence: a.Equivalence, ApprovalNote: a.ApprovalNote,
		})
	}
	return out
}

func fromAlternateDTOs(dtos []alternateDTO) []hbom.Alternate {
	out := make([]hbom.Alternate, 0, len(dtos))
	for _, d := range dtos {
		out = append(out, hbom.Alternate{
			Ordinal: d.Ordinal, ManufacturerName: d.ManufacturerName,
			ModelNumber: d.ModelNumber, SupplierInfo: d.SupplierInfo,
			SupplierSKU: d.SupplierSKU, LifecycleStatus: d.LifecycleStatus,
			Equivalence: d.Equivalence, ApprovalNote: d.ApprovalNote,
		})
	}
	return out
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
		ProductDetails:            dto.ProductDetails,
		ManufacturingDate:         dto.ManufacturingDate,
		Designators:               dto.Designators,
		PackageFootprint:          dto.PackageFootprint,
		SupplierSKU:               dto.SupplierSKU,
		PreferredSupplier:         dto.PreferredSupplier,
		UnitPrice:                 dto.UnitPrice,
		Currency:                  dto.Currency,
		DoNotPopulate:             dto.DoNotPopulate,
		AssemblyType:              dto.AssemblyType,
		LifecycleStatus:           dto.LifecycleStatus,
		DatasheetURL:              dto.DatasheetURL,
		Alternates:                fromAlternateDTOs(dto.Alternates),
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
	// Format is how the file was actually read — "csv", "tsv" or "xlsx".
	// Surfaced so the preview can say it, rather than leaving a customer to
	// infer it from whether the columns came out right.
	Format string `json:"format"`
	// Sheets are a workbook's tabs. Only the first is read; naming the rest is
	// what stops a parts list on sheet two reading as an empty import.
	Sheets []string `json:"sheets"`
}

func toImportPreviewDTO(r *hbom.ImportResult) importPreviewDTO {
	return importPreviewDTO{
		Roots:           toComponentDTOs(r.Roots),
		ComponentCount:  r.Total(),
		MaxDepth:        r.MaxDepthReached(),
		UnmappedHeaders: emptyIfNil(r.UnmappedHeaders),
		Warnings:        emptyIfNil(r.Warnings),
		Format:          r.Format,
		Sheets:          emptyIfNil(r.Sheets),
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

	data, mapping, filename, err := readHBOMUpload(w, r)
	if err != nil {
		errs.Write(w, r, err)
		return
	}

	result, err := h.svc.PreviewHBOMImport(data, mapping, filename)
	if err != nil {
		errs.Write(w, r, err)
		return
	}
	errs.WriteJSON(w, http.StatusOK, toImportPreviewDTO(result))
}

// ComponentForm handles GET /v1/hbom/component-form.
//
// The editable Table 11 elements, generated from the compliance profile, so the
// per-component editor renders inputs from data rather than hardcoding a field
// list that drifts from the guideline.
func (h *Handler) ComponentForm(w http.ResponseWriter, r *http.Request) {
	if _, err := auth.RequireTenant(r.Context()); err != nil {
		errs.Write(w, r, err)
		return
	}
	errs.WriteJSON(w, http.StatusOK, map[string]any{"fields": hbom.ComponentFormFields()})
}

// DeviceForm handles GET /v1/hbom/device-form.
//
// ⚠ THE SAME FIELDS ListDevices ALREADY RETURNS, REACHABLE WITHOUT A PROJECT.
//
// The device form travelled only alongside a project's device LIST, which
// means the one screen that cannot ask for it is the registration wizard —
// there is no project id until the create call returns. Registration therefore
// asked every BOM type the same questions and left "which device is this?" to
// a checklist item discovered later, on a project already created.
//
// Generated from the profile like every other form here, so this stays one
// field list with two routes rather than two lists that drift (invariant 2).
func (h *Handler) DeviceForm(w http.ResponseWriter, r *http.Request) {
	if _, err := auth.RequireTenant(r.Context()); err != nil {
		errs.Write(w, r, err)
		return
	}
	errs.WriteJSON(w, http.StatusOK, map[string]any{"fields": hbom.DeviceFormFields()})
}

// ReadImportHeaders handles POST /v1/hbom/headers.
//
// Returns the column names, the format the file was recognised as, and a
// workbook's sheet list. Stores nothing — the same "look before you commit"
// split the preview step already makes.
func (h *Handler) ReadImportHeaders(w http.ResponseWriter, r *http.Request) {
	if _, err := auth.RequireTenant(r.Context()); err != nil {
		errs.Write(w, r, err)
		return
	}

	data, _, filename, err := readHBOMUpload(w, r)
	if err != nil {
		errs.Write(w, r, err)
		return
	}

	headers, format, sheets, err := h.svc.ReadImportHeaders(data, filename)
	if err != nil {
		errs.Write(w, r, err)
		return
	}
	errs.WriteJSON(w, http.StatusOK, map[string]any{
		"headers": emptyIfNil(headers),
		"format":  format,
		"sheets":  emptyIfNil(sheets),
	})
}

// ConfirmHBOMImport handles POST /v1/hbom/{projectId}/import.
func (h *Handler) ConfirmHBOMImport(w http.ResponseWriter, r *http.Request) {
	tenantID, err := auth.RequireTenant(r.Context())
	if err != nil {
		errs.Write(w, r, err)
		return
	}

	data, mapping, filename, err := readHBOMUpload(w, r)
	if err != nil {
		errs.Write(w, r, err)
		return
	}

	// ⚠ THE PATH WINS WHEN IT HAS ONE; THE FORM FIELD IS THE FALLBACK, NEVER AN
	// OVERRIDE.
	//
	// Two routes reach here. `/v1/hbom/{projectId}/import` is the better shape
	// and is authoritative — a form field must never be trusted over a path
	// segment the route guard has already seen. `/v1/hbom/import` exists
	// because frontend/src/lib/hbom.ts has always called it, carrying
	// `project_id` in the multipart body, and always got a 404 for it.
	//
	// Reading the body only when the path is empty keeps the security property:
	// on the path-scoped route a hostile `project_id` field is ignored entirely
	// rather than compared, so there is no precedence bug to get wrong. Either
	// way, ImportHBOM re-checks the project belongs to this tenant, and RLS is
	// underneath that.
	projectID := r.PathValue("projectId")
	if projectID == "" {
		projectID = r.FormValue("project_id")
	}

	docID, err := h.svc.ImportHBOM(r.Context(), tenantID, projectID, data, mapping, filename)
	if err != nil {
		errs.Write(w, r, err)
		return
	}
	errs.WriteJSON(w, http.StatusCreated, map[string]any{"bom_document_id": docID})
}

// readHBOMUpload parses the multipart body every HBOM file endpoint shares:
// a `file` field and a `mapping` field holding a JSON object of
// header -> canonical column id.
func readHBOMUpload(w http.ResponseWriter, r *http.Request) ([]byte, map[string]string, string, error) {
	r.Body = http.MaxBytesReader(w, r.Body, maxHBOMFileBytes+(1<<20))

	//nolint:gosec // G120: the body is already bounded by the MaxBytesReader above.
	if err := r.ParseMultipartForm(8 << 20); err != nil {
		return nil, nil, "", errs.Wrap(err, errs.ValidationBodyMalformed,
			"could not read the upload; it may exceed the size limit")
	}
	defer func() {
		if r.MultipartForm != nil {
			_ = r.MultipartForm.RemoveAll()
		}
	}()

	file, fileHeader, err := r.FormFile("file")
	if err != nil {
		return nil, nil, "", errs.New(errs.ValidationFieldRequired,
			"attach the file in a form field named 'file'")
	}
	defer func() { _ = file.Close() }()

	data, err := io.ReadAll(io.LimitReader(file, maxHBOMFileBytes))
	if err != nil {
		return nil, nil, "", errs.Wrap(err, errs.ValidationBodyMalformed, "could not read the uploaded file")
	}

	mapping := map[string]string{}
	if raw := strings.TrimSpace(r.FormValue("mapping")); raw != "" {
		if err := json.Unmarshal([]byte(raw), &mapping); err != nil {
			return nil, nil, "", errs.Wrap(err, errs.ValidationBodyMalformed,
				"the 'mapping' field is not valid JSON")
		}
	}

	filename := ""
	if fileHeader != nil {
		filename = fileHeader.Filename
	}
	return data, mapping, filename, nil
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

// ---------------------------------------------------------------------------
// Devices
// ---------------------------------------------------------------------------

// deviceRequest is the registration body.
//
// ⚠ MIRRORS hbom.Device'S EDITABLE FIELDS ONLY. id, project_id, timestamps and
// the parts summary are server-owned; accepting them would let a caller claim a
// component count nobody counted. DisallowUnknownFields (see decode) turns a
// typo into a 400 rather than a silently ignored field.
type deviceRequest struct {
	Name            string `json:"name"`
	Manufacturer    string `json:"manufacturer,omitempty"`
	ModelNumber     string `json:"model_number,omitempty"`
	SerialNumber    string `json:"serial_number,omitempty"`
	LotNumber       string `json:"lot_number,omitempty"`
	AssetTag        string `json:"asset_tag,omitempty"`
	FirmwareVersion string `json:"firmware_version,omitempty"`
	Location        string `json:"location,omitempty"`
	Criticality     string `json:"criticality,omitempty"`
	Notes           string `json:"notes,omitempty"`
}

func (d deviceRequest) toDevice() *hbom.Device {
	return &hbom.Device{
		Name: strings.TrimSpace(d.Name), Manufacturer: d.Manufacturer,
		ModelNumber: d.ModelNumber, SerialNumber: d.SerialNumber,
		LotNumber: d.LotNumber, AssetTag: d.AssetTag,
		FirmwareVersion: d.FirmwareVersion, Location: d.Location,
		Criticality: d.Criticality, Notes: d.Notes,
	}
}

// ListDevices handles GET /v1/hbom/{projectId}/devices.
func (h *Handler) ListDevices(w http.ResponseWriter, r *http.Request) {
	tenantID, err := auth.RequireTenant(r.Context())
	if err != nil {
		errs.Write(w, r, err)
		return
	}
	devices, err := h.svc.ListDevices(r.Context(), tenantID, r.PathValue("projectId"))
	if err != nil {
		errs.Write(w, r, err)
		return
	}
	errs.WriteJSON(w, http.StatusOK, map[string]any{
		"devices": devices,
		// ⚠ THE FORM TRAVELS WITH THE LIST, generated from the compliance
		// profile. The frontend renders inputs from this rather than hardcoding
		// Table 11's element names, so a CERT-In revision changes the YAML and
		// the form follows without a frontend release (invariant 2).
		"form": hbom.DeviceFormFields(),
	})
}

// GetDevice handles GET /v1/hbom/{projectId}/devices/{deviceId}.
func (h *Handler) GetDevice(w http.ResponseWriter, r *http.Request) {
	tenantID, err := auth.RequireTenant(r.Context())
	if err != nil {
		errs.Write(w, r, err)
		return
	}
	d, err := h.svc.GetDevice(r.Context(), tenantID, r.PathValue("projectId"), r.PathValue("deviceId"))
	if err != nil {
		errs.Write(w, r, err)
		return
	}
	errs.WriteJSON(w, http.StatusOK, d)
}

// CreateDevice handles POST /v1/hbom/{projectId}/devices.
func (h *Handler) CreateDevice(w http.ResponseWriter, r *http.Request) {
	tenantID, err := auth.RequireTenant(r.Context())
	if err != nil {
		errs.Write(w, r, err)
		return
	}
	var req deviceRequest
	if err := decode(r, &req); err != nil {
		errs.Write(w, r, err)
		return
	}

	created, err := h.svc.CreateDevice(r.Context(), tenantID,
		r.PathValue("projectId"), ctxkey.UserID(r.Context()), req.toDevice())
	if err != nil {
		errs.Write(w, r, err)
		return
	}
	errs.WriteJSON(w, http.StatusCreated, created)
}

// UpdateDevice handles PUT /v1/hbom/{projectId}/devices/{deviceId}.
func (h *Handler) UpdateDevice(w http.ResponseWriter, r *http.Request) {
	tenantID, err := auth.RequireTenant(r.Context())
	if err != nil {
		errs.Write(w, r, err)
		return
	}

	var req deviceRequest
	if err := decode(r, &req); err != nil {
		errs.Write(w, r, err)
		return
	}

	updated, err := h.svc.UpdateDevice(r.Context(), tenantID,
		r.PathValue("projectId"), r.PathValue("deviceId"), req.toDevice())
	if err != nil {
		errs.Write(w, r, err)
		return
	}
	errs.WriteJSON(w, http.StatusOK, updated)
}

// DeleteDevice handles DELETE /v1/hbom/{projectId}/devices/{deviceId}.
func (h *Handler) DeleteDevice(w http.ResponseWriter, r *http.Request) {
	tenantID, err := auth.RequireTenant(r.Context())
	if err != nil {
		errs.Write(w, r, err)
		return
	}
	if err := h.svc.DeleteDevice(r.Context(), tenantID, r.PathValue("projectId"), r.PathValue("deviceId")); err != nil {
		errs.Write(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
