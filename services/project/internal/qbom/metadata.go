// Package qbom implements QBOM device metadata — CERT-In Table 8's eleven
// elements — for services/project.
//
// ⚠ CAPTURED, NOT DISCOVERED. There is no quantum-hardware scanner, so every
// value here comes from a form or an import. The product says so at the
// point of entry rather than letting a user wait for a scan that will never
// populate it. See FormDisclosure.
//
// WHY A GO PORT, RATHER THAN CALLING THE PYTHON: every worker under workers/
// is invoked exclusively as a NATS-driven scan job (docs/02-CONTRACTS.md);
// there is no HTTP or CLI bridge anywhere in this codebase that lets a Go
// service call into Python-owned logic for a synchronous REST response, and
// QBOM device metadata has no scan job at all — same situation as HBOM (see
// services/project/internal/hbom's package doc, which states the identical
// constraint). services/project is Go, like every other REST handler in
// this repo, so the logic is re-implemented here rather than shelled out to
// a script.
//
// The behaviour below is cross-checked field-for-field and rule-for-rule
// against workers/qbom/metadata.py. A future change to either side must
// keep both in step — there is no golden-file sharing mechanism between the
// two languages, so metadata_test.go mirrors the intent of that module by
// hand.
//
// ⚠ THE FIELD LIST COMES FROM THE PROFILE, NEVER HAND-TYPED (CLAUDE.md
// invariant 2). model.QBOMFields is generated from docs/reference/
// certin-v2.0.yaml; a CERT-In revision that adds an element changes that
// generated file, not this one.
package qbom

import (
	"strings"

	"github.com/axebom/axebom/libs/go-shared/model"
)

// NotProvided is the explicit sentinel stored for an element nobody
// recorded. CLAUDE.md invariant 3: unknown fields are stored explicitly,
// never silently omitted, and score present = 0 either way.
const NotProvided = "not-provided"

// derivedFields are the two of Table 8's eleven elements that are not
// free-form device metadata.
//
// `crypto_assets` REFERENCES the CBOM-derived assets — a QBOM does not
// re-discover them — and `findings` references vulnerabilities matched
// against them. Both are populated by derivation, so a form that asked a
// user to type them would be asking them to duplicate the scan.
var derivedFields = map[string]bool{
	model.FieldCertinQbom05CryptographicAsset: true,
	model.FieldCertinQbom10Vulnerabilities:    true,
}

// IsDerived reports whether fieldID is populated by derivation rather than
// by form or import.
func IsDerived(fieldID string) bool { return derivedFields[fieldID] }

// FormDisclosure is the sentence the UI shows above the device form.
//
// ⚠ THIS IS A PRODUCT COMMITMENT, NOT COPY. Implying that a scan will fill
// these in leaves a customer waiting for results that are never coming, and
// the empty QBOM then reads as a broken product rather than an honest one.
// Mirrors workers/qbom/metadata.py's FORM_DISCLOSURE verbatim.
const FormDisclosure = "There is no open-source scanner for quantum hardware. The cryptographic " +
	"assets in this QBOM are DERIVED from CBOM discovery with quantum-" +
	"vulnerability rules applied; the device metadata below is captured here, " +
	"by you. Anything you leave blank is recorded as `not-provided` and counts " +
	"as a gap rather than being hidden."

// FieldGap is one element that carries no substantive value, and why.
type FieldGap struct {
	FieldID string
	Name    string
	Reason  string
}

// FormField describes one element a user is asked to supply, for the
// frontend to render the form from.
//
// ⚠ GENERATED FROM THE PROFILE. No count is written anywhere — a CERT-In
// revision that adds an element adds a form field, without a Go code change
// (CLAUDE.md invariant 2).
type FormField struct {
	FieldID       string
	Name          string
	CanonicalPath string
	Type          string
	SourcePage    int
	Derived       bool
}

// FormFields returns the elements a user is asked to supply, generated from
// model.QBOMFields. Mirrors workers/qbom/metadata.py's form_fields().
func FormFields() []FormField {
	out := make([]FormField, 0, len(model.QBOMFields))
	for _, f := range model.QBOMFields {
		out = append(out, FormField{
			FieldID:       f.ID,
			Name:          f.Name,
			CanonicalPath: f.CanonicalPath,
			Type:          f.Type,
			SourcePage:    f.SourcePage,
			Derived:       IsDerived(f.ID),
		})
	}
	return out
}

// DeviceValues is what a caller supplies for the nine elements that are
// captured by form or import — everything in Table 8 except the two
// derived reference fields (crypto_assets, findings).
//
// ⚠ NOT EVERY COLUMN IS A PLAIN STRING. software_dependencies is Table 8's
// only free-form list element (CanonicalPath ends in "[]" and
// Type == "ref_list"); every other captured element is scalar text.
type DeviceValues struct {
	ModelName             string
	Version               string
	VendorOrigin          string
	LicenseInfo           string
	CommunicationProtocol string
	Hardware              string
	SoftwareDependencies  []string
	EnvironmentalImpact   string
	AttestationSignature  string
}

// Device is one normalize.quantum_components row, plus the two derived
// reference lists that have no column of their own (see
// docs/01-DATA-MODEL.md's quantum_components entry: "+ crypto_assets via
// bom_document_id, findings via normalize.findings") and the per-field
// status every normalization pass records.
type Device struct {
	ModelName             string
	Version               string
	VendorOrigin          string
	LicenseInfo           string
	CommunicationProtocol string
	Hardware              string
	SoftwareDependencies  []string
	EnvironmentalImpact   string
	AttestationSignature  string

	// CryptoAssetRefs and FindingRefs are REFERENCES, not copies (CERT-In
	// Table 8 elements 5 and 10) — resolved by the store layer from the
	// project's current CBOM discovery, never persisted as a column, and
	// never hand-typed by a user. See services/project/internal/store/
	// qbom.go's resolveCryptoAssetRefs.
	CryptoAssetRefs []string
	FindingRefs     []string

	// FieldStatus covers all eleven elements, including the two derived
	// ones, keyed by field id ("provided" or NotProvided). Persisted as
	// normalize.quantum_components.field_status.
	FieldStatus map[string]string
}

// NormalizeDevice builds a quantum component row, recording every gap
// explicitly. Mirrors workers/qbom/metadata.py's normalize_device().
//
// Returns (device, gaps). The gaps are what a report renders; they are not
// an error, and a device with ten of eleven elements unrecorded is a
// legitimate state that must be visible rather than hidden behind a
// percentage.
//
// An empty derived list (cryptoAssetRefs or findingRefs) is NotProvided, not
// provided — a QBOM whose CBOM found nothing has no crypto assets to
// reference, and recording that as present would score a field that carries
// no information.
func NormalizeDevice(values DeviceValues, cryptoAssetRefs, findingRefs []string) (*Device, []FieldGap) {
	device := &Device{FieldStatus: map[string]string{}}

	for _, f := range model.QBOMFields {
		column := stripCanonicalPath(f.CanonicalPath)

		if IsDerived(f.ID) {
			derived := findingRefs
			if f.ID == model.FieldCertinQbom05CryptographicAsset {
				derived = cryptoAssetRefs
			}
			if derived == nil {
				derived = []string{}
			}
			setDeviceListField(device, column, derived)
			if len(derived) > 0 {
				device.FieldStatus[f.ID] = "provided"
			} else {
				device.FieldStatus[f.ID] = NotProvided
			}
			continue
		}

		if f.Type == "ref_list" {
			got := values.SoftwareDependencies
			if len(got) > 0 {
				setDeviceListField(device, column, got)
				device.FieldStatus[f.ID] = "provided"
			} else {
				setDeviceListField(device, column, []string{})
				device.FieldStatus[f.ID] = NotProvided
			}
			continue
		}

		value := deviceStringValue(values, column)
		if isSubstantiveString(value) {
			setDeviceStringField(device, column, value)
			device.FieldStatus[f.ID] = "provided"
		} else {
			// ⚠ STORED EXPLICITLY, NEVER OMITTED. Omission hides the gap; the
			// explicit value is what makes it countable and reportable.
			setDeviceStringField(device, column, NotProvided)
			device.FieldStatus[f.ID] = NotProvided
		}
	}

	return device, GapsFromStatus(device.FieldStatus)
}

// GapsFromStatus rebuilds the gap list — field id, name and a reason a
// report or the UI can show — from a field_status map alone. Used both by
// NormalizeDevice, right after it computes that map, and by the store layer
// when reading back a previously-persisted normalize.quantum_components row
// (see services/project/internal/store/qbom.go's GetQuantumDevice): the
// persisted field_status IS the versioned, immutable record of what was
// true when this device was last saved (CLAUDE.md invariant 10), so a GET
// reports gaps from it directly rather than recomputing derived-field
// status against whatever the CBOM looks like right now.
func GapsFromStatus(fieldStatus map[string]string) []FieldGap {
	var gaps []FieldGap
	for _, f := range model.QBOMFields {
		if fieldStatus[f.ID] == "provided" {
			continue
		}
		if IsDerived(f.ID) {
			gaps = append(gaps, FieldGap{
				FieldID: f.ID,
				Name:    f.Name,
				Reason: "Derived from CBOM discovery, which found nothing to reference. " +
					"Run a CBOM scan for this project.",
			})
			continue
		}
		gaps = append(gaps, FieldGap{
			FieldID: f.ID,
			Name:    f.Name,
			Reason: "Not recorded. There is no quantum-hardware scanner; this " +
				"element is captured by form or import.",
		})
	}
	return gaps
}

// isSubstantiveString mirrors the normalizer's rule, deliberately.
//
// `not-provided`, `unknown`, `""` and `[]` all score present = 0. A user who
// types "not-provided" into a form has DECLARED the gap, which is a real
// act — and it still counts as zero. Mirrors workers/qbom/metadata.py's
// _is_substantive() for the string case; the list case is handled inline
// above (len(v) > 0) since Go's captured elements only ever mix the two.
func isSubstantiveString(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", NotProvided, "noassertion", "unknown", "n/a":
		return false
	default:
		return true
	}
}

// stripCanonicalPath turns a Table-8 canonical path
// ("quantum_component.software_dependencies[]") into the bare column name
// ("software_dependencies") normalize.quantum_components uses.
func stripCanonicalPath(canonicalPath string) string {
	column := strings.TrimPrefix(canonicalPath, "quantum_component.")
	return strings.TrimSuffix(column, "[]")
}

// deviceStringValue and setDeviceStringField/setDeviceListField are a
// narrow reflect-free get/set over Device's columns, matching
// services/project/internal/hbom/model.go's attrValue/setAttr: the field set
// is small, fixed, and worth being able to grep.
func deviceStringValue(v DeviceValues, column string) string {
	switch column {
	case "model_name":
		return v.ModelName
	case "version":
		return v.Version
	case "vendor_origin":
		return v.VendorOrigin
	case "license_info":
		return v.LicenseInfo
	case "communication_protocol":
		return v.CommunicationProtocol
	case "hardware":
		return v.Hardware
	case "environmental_impact":
		return v.EnvironmentalImpact
	case "attestation_signature":
		return v.AttestationSignature
	default:
		return ""
	}
}

func setDeviceStringField(d *Device, column, value string) {
	switch column {
	case "model_name":
		d.ModelName = value
	case "version":
		d.Version = value
	case "vendor_origin":
		d.VendorOrigin = value
	case "license_info":
		d.LicenseInfo = value
	case "communication_protocol":
		d.CommunicationProtocol = value
	case "hardware":
		d.Hardware = value
	case "environmental_impact":
		d.EnvironmentalImpact = value
	case "attestation_signature":
		d.AttestationSignature = value
	}
}

func setDeviceListField(d *Device, column string, value []string) {
	switch column {
	case "software_dependencies":
		d.SoftwareDependencies = value
	case "crypto_assets":
		d.CryptoAssetRefs = value
	case "findings":
		d.FindingRefs = value
	}
}
