// Device registration — the identity half of a hardware BOM.
//
// ⚠ A DEVICE USED TO BE A CONVENTION: the level-0 row of a versioned parts
// list. That row carries everything a device needs (model, serial, manufacturer,
// origin) and none of what makes it addressable — ReplaceHardwareTree writes a
// whole new document on every re-import, so no identity survived one, nothing
// was unique on serial, and a project could hold exactly one hardware tree.
//
// ⚠ THE FORM IS GENERATED FROM THE PROFILE, NOT HAND-TYPED (invariant 2).
// The CERT-In-backed fields carry their Table 11 element id, name and page
// citation straight from model.HBOMFields; the four AxeBOM-only fields are
// labelled as such so nobody mistakes an asset tag for a compliance element.
// Same mechanism as internal/qbom's FormFields().
package hbom

import (
	"fmt"
	"strings"

	"github.com/axebom/axebom/libs/go-shared/model"
)

// Device is a registered piece of hardware. Identity and registration only —
// the parts tree lives in normalize.hardware_components, versioned.
type Device struct {
	ID        string `json:"id"`
	ProjectID string `json:"project_id"`

	Name            string `json:"name"`
	Manufacturer    string `json:"manufacturer"`
	ModelNumber     string `json:"model_number"`
	SerialNumber    string `json:"serial_number"`
	LotNumber       string `json:"lot_number"`
	AssetTag        string `json:"asset_tag"`
	FirmwareVersion string `json:"firmware_version"`
	Location        string `json:"location"`
	Criticality     string `json:"criticality"`
	Notes           string `json:"notes"`

	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`

	// ComponentCount is how many parts the device's current BOM document
	// holds, and BOMDocumentID which document that is. Both are read-only
	// projections of the tree, present so a device list does not need a
	// second round trip per row.
	ComponentCount int    `json:"component_count"`
	BOMDocumentID  string `json:"bom_document_id,omitempty"`
	// PartsUpdatedAt is when that document was generated. A device registered
	// months ago whose parts were never imported is a real and important state,
	// and an empty value here is what says so.
	PartsUpdatedAt string `json:"parts_updated_at,omitempty"`
}

// Criticalities is the closed set the column's CHECK constraint allows.
//
// ⚠ IT MUST MATCH normalize.hardware_components.criticality. A device assessed
// `critical` whose parts table cannot express that value would report two
// different criticalities for one thing.
var Criticalities = []string{"critical", "high", "medium", "low", "unknown"}

// deviceFieldMap ties each editable device attribute to its CERT-In element,
// where one exists.
//
// ⚠ FOUR ATTRIBUTES HAVE NO ELEMENT, AND SAYING SO IS THE POINT. Table 11
// describes a product; `asset_tag`, `location`, `lot_number` and `notes` are
// asset-management facts AxeBOM adds. Rendering them beside a compliance
// element with no distinction would let a customer believe filling them in
// moved a coverage number, which it does not — the same separation
// docs/reference/hbom-manufacturing-v1.yaml already draws for the procurement
// fields.
var deviceFieldMap = []struct {
	attr    string
	fieldID string
}{
	{"name", model.FieldCertinHbom01ProductName},
	{"manufacturer", model.FieldCertinHbom05ManufacturerName},
	{"model_number", model.FieldCertinHbom10ModelNumber},
	{"serial_number", model.FieldCertinHbom11SerialNumber},
	{"firmware_version", model.FieldCertinHbom21FirmwareVersion},
	{"criticality", model.FieldCertinHbom23Criticality},
	{"lot_number", ""},
	{"asset_tag", ""},
	{"location", ""},
	{"notes", ""},
}

// DeviceFormField describes one input the registration form renders.
type DeviceFormField struct {
	Attr string `json:"attr"`
	Name string `json:"name"`
	// FieldID is the CERT-In element this attribute satisfies, or "" when the
	// attribute is an AxeBOM addition.
	FieldID string `json:"field_id,omitempty"`
	// SourcePage cites the guideline. Zero when FieldID is empty.
	SourcePage int `json:"source_page,omitempty"`
	// CertIn is false for the four asset-management attributes. The UI groups
	// on this so a coverage-relevant field never sits unlabelled beside one
	// that scores nothing.
	CertIn   bool     `json:"certin"`
	Required bool     `json:"required"`
	Values   []string `json:"values,omitempty"`
	// Multiline asks the form for a textarea.
	//
	// ⚠ A SERVER-SIDE FACT, NOT A FRONTEND SPECIAL CASE. The form is rendered
	// from this list, so "notes is long-form" belongs beside the field it
	// describes rather than as an `if (attr === 'notes')` in a component —
	// which is where it would have to be re-decided the next time a long-form
	// field is added. CERT-In's own `text` type maps here too when one of those
	// elements becomes editable on a device.
	Multiline bool `json:"multiline,omitempty"`
}

// DeviceFormFields is the registration form, generated.
//
// ⚠ NO COUNT IS WRITTEN ANYWHERE. A CERT-In revision that renames Table 11's
// element 10 renames this input, with no Go change (invariant 2).
func DeviceFormFields() []DeviceFormField {
	byID := make(map[string]model.ProfileField, len(model.HBOMFields))
	for _, f := range model.HBOMFields {
		byID[f.ID] = f
	}

	out := make([]DeviceFormField, 0, len(deviceFieldMap))
	for _, m := range deviceFieldMap {
		ff := DeviceFormField{
			Attr:     m.attr,
			Name:     humanizeAttr(m.attr),
			Required: m.attr == "name",
		}
		if f, ok := byID[m.fieldID]; ok {
			ff.Name = f.Name
			ff.FieldID = f.ID
			ff.SourcePage = f.SourcePage
			ff.CertIn = true
		}
		if m.attr == "criticality" {
			ff.Values = Criticalities
		}
		// The profile's own `text` type means long-form; `string` means a line.
		if m.attr == "notes" || (ff.FieldID != "" && byID[m.fieldID].Type == "text") {
			ff.Multiline = true
		}
		out = append(out, ff)
	}
	return out
}

// humanizeAttr is the fallback label for an attribute with no profile entry.
func humanizeAttr(attr string) string {
	parts := strings.Split(attr, "_")
	for i, p := range parts {
		if p == "" {
			continue
		}
		parts[i] = strings.ToUpper(p[:1]) + p[1:]
	}
	return strings.Join(parts, " ")
}

// ValidateDevice checks what can be checked without the database.
//
// ⚠ UNIQUENESS IS NOT CHECKED HERE. Two requests can pass this function
// simultaneously and only one can win; the partial unique index on
// (tenant_id, serial_number) is the real guarantee, and the store turns its
// violation into a 409. A pre-check would be a race with a friendlier error
// message, which is the worst of both.
func ValidateDevice(d *Device) error {
	if strings.TrimSpace(d.Name) == "" {
		return fmt.Errorf("a device needs a name: it is how anybody finds it again")
	}
	if len(d.Name) > 200 {
		return fmt.Errorf("name is longer than 200 characters")
	}
	if d.Criticality != "" {
		ok := false
		for _, c := range Criticalities {
			if d.Criticality == c {
				ok = true
				break
			}
		}
		if !ok {
			return fmt.Errorf("criticality %q is not one of %s",
				d.Criticality, strings.Join(Criticalities, ", "))
		}
	}
	return nil
}
