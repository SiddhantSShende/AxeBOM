package render

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/axebom/axebom/libs/go-shared/model"
)

// ─── QBOM ───────────────────────────────────────────────────────────────────
//
// ⚠ A QBOM IS TWO THINGS JOINED, AND THE PRODUCT MUST NOT IMPLY EITHER IS A
// SCAN OF QUANTUM HARDWARE — BECAUSE NEITHER IS.
//
//	crypto assets   REFERENCED from the CBOM, with quantum rules applied
//	device metadata CAPTURED by form or import (CERT-In Table 8's elements)
//
// (workers/qbom/derive.py's own module docstring, restated here because this
// file is the other half of the same decision.) No open-source tool
// discovers quantum hardware, so QuantumDevice is a data-entry record, not a
// discovery result, and QuantumReadinessSheet groups crypto assets the CBOM
// normalizer already classified rather than re-running any rule.

// QuantumDevice is CERT-In Table 8's device-metadata elements
// (migrations/normalize/0003, normalize.quantum_components) — ONE row, not
// many. A project has one current device-metadata document, replaced by
// re-import, not accumulated as a history the way scan runs are.
//
// ⚠ CAPTURED, NOT DISCOVERED. Every value here came from a form or an import
// (workers/qbom/metadata.py). This struct deliberately does NOT carry Table
// 8's elements 5 and 10 (Cryptographic Asset, Vulnerabilities): those are
// REFERENCE lists into the CBOM-derived crypto assets, they have no columns
// of their own on normalize.quantum_components, and this report represents
// them with QuantumReadinessSheet instead of a device-metadata field —
// duplicating them here would be the same "reference vs. copy" drift
// derive.py's crypto_asset_refs comment warns about.
type QuantumDevice struct {
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

// QBOMFormDisclosure ports workers/qbom/metadata.py's FORM_DISCLOSURE.
//
// ⚠ A PRODUCT COMMITMENT, NOT COPY. Implying that a scan will fill the device
// fields in leaves a customer waiting for results that are never coming, and
// the empty QBOM then reads as a broken product rather than an honest one —
// exactly the failure metadata.py's own comment names.
const QBOMFormDisclosure = "There is no open-source scanner for quantum " +
	"hardware. The cryptographic assets in this QBOM are DERIVED from CBOM " +
	"discovery with quantum-vulnerability rules applied; the device metadata " +
	"below is captured separately, by form or import. Anything left blank is " +
	"recorded as `" + model.NotProvided + "` and counted as a gap rather than " +
	"hidden."

// QBOMSheets are the QBOM-specific sheets, appended in place of the generic
// componentSheet Sheets() builds for every other type (fieldCoverageSheet
// still runs for a QBOM — see Sheets — because Table 8 IS one flat field
// list; only the per-row shape does not fit a Component).
func QBOMSheets(b BOM) []Sheet {
	return []Sheet{
		quantumDeviceSheet(b.QuantumDevice),
		quantumReadinessSheet(b.CryptoAssets),
	}
}

// qbomFieldName looks up a Table 8 element's current name from the profile,
// rather than hardcoding it — the same reasoning as everywhere else in this
// package that a CERT-In revision must be a data change, not a code change.
func qbomFieldName(id string) string {
	for _, f := range model.QBOMFields {
		if f.ID == id {
			return f.Name
		}
	}
	return id
}

// quantumDeviceSheet renders Table 8's nine free-form device elements, plus a
// stated pointer to where elements 5 and 10 (the two reference lists) live.
//
// ⚠ ABSENT IS A STATED GAP, NOT A SKIPPED SECTION. A project classified QBOM
// before anybody filled in the device form has a legitimate "not filled in
// yet" state (CLAUDE.md invariant 3) — the sheet still appears, every element
// reads `not-provided`, and the reason is on the sheet, not left for the
// reader to guess.
func quantumDeviceSheet(d *QuantumDevice) Sheet {
	var rows [][]string

	if d == nil {
		for _, id := range deviceFieldOrder {
			rows = append(rows, []string{qbomFieldName(id), model.NotProvided})
		}
		rows = append(rows, []string{"", ""}, []string{
			"Gap", "No device metadata has been recorded for this project yet. " + QBOMFormDisclosure,
		})
		return Sheet{
			Name: "Quantum Device", Header: []string{"Element", "Value"}, Rows: StaticRows(rows), Width: 50,
		}
	}

	values := map[string]string{
		model.FieldCertinQbom01ModelName:             d.ModelName,
		model.FieldCertinQbom02Version:               d.Version,
		model.FieldCertinQbom03VendorOrigin:          d.VendorOrigin,
		model.FieldCertinQbom04LicenseInformation:    d.LicenseInfo,
		model.FieldCertinQbom06CommunicationProtocol: d.CommunicationProtocol,
		model.FieldCertinQbom07Hardware:              d.Hardware,
		model.FieldCertinQbom09EnvironmentalImpact:   d.EnvironmentalImpact,
		model.FieldCertinQbom11Attestations:          d.AttestationSignature,
	}
	for _, id := range deviceFieldOrder {
		rows = append(rows, []string{qbomFieldName(id), orNotProvided(values[id])})
	}
	rows = append(rows, []string{
		qbomFieldName(model.FieldCertinQbom08SoftwareDependencies), joinList(d.SoftwareDependencies),
	})

	rows = append(rows, []string{"", ""},
		[]string{
			qbomFieldName(model.FieldCertinQbom05CryptographicAsset),
			"A reference list into the CBOM's crypto assets, not device metadata — see the Quantum Readiness sheet.",
		},
		[]string{
			qbomFieldName(model.FieldCertinQbom10Vulnerabilities),
			"Tracked against the referenced crypto assets, not recorded on this device.",
		},
	)

	return Sheet{
		Name: "Quantum Device", Header: []string{"Element", "Value"}, Rows: StaticRows(rows), Width: 50,
	}
}

// deviceFieldOrder is the nine free-form Table 8 elements this struct holds,
// in profile order, minus the two reference-list elements handled separately
// above and minus SoftwareDependencies, which is appended after this loop
// because it is a list rather than a scalar `values` lookup can hold as a
// plain string.
var deviceFieldOrder = []string{
	model.FieldCertinQbom01ModelName,
	model.FieldCertinQbom02Version,
	model.FieldCertinQbom03VendorOrigin,
	model.FieldCertinQbom04LicenseInformation,
	model.FieldCertinQbom06CommunicationProtocol,
	model.FieldCertinQbom07Hardware,
	model.FieldCertinQbom09EnvironmentalImpact,
	model.FieldCertinQbom11Attestations,
}

// ─── Quantum readiness ──────────────────────────────────────────────────────

// quantumReadinessSheet groups CryptoAssets into the four buckets
// axebom_shared.crypto.quantum_rules.readiness_group computes ONCE, in
// Python, at CBOM-normalization time (migrations/normalize/0005).
//
// ⚠ IT COUNTS AND LISTS. IT NEVER RE-CLASSIFIES. See CryptoAsset.
// QuantumReadinessGroup's own comment for why a Go re-implementation of the
// vulnerable/grover_note/post_quantum/unassessed branch is exactly the
// mistake that lets the CBOM and this QBOM view disagree about the same
// asset the first time either rule changes.
func quantumReadinessSheet(assets []CryptoAsset) Sheet {
	vulnerable, postQuantum, grover, unassessed := groupByReadiness(assets)

	rows := [][]string{
		{"Summary", "", readinessNote(len(vulnerable), len(postQuantum), len(grover), len(unassessed))},
	}
	rows = append(rows, readinessGroupRows(
		"Vulnerable to Shor's algorithm — migration required", vulnerable)...)
	rows = append(rows, readinessGroupRows(
		"Already post-quantum (NIST PQC family in use)", postQuantum)...)
	rows = append(rows, readinessGroupRows(
		"Symmetric, Grover note only — a sizing observation, NOT a vulnerability", grover)...)
	rows = append(rows, readinessGroupRows(
		"Unassessed — matched no quantum rule", unassessed)...)

	return Sheet{
		Name:   "Quantum Readiness",
		Header: []string{"Bucket", "Asset", "Detail"},
		Rows:   StaticRows(rows),
		Width:  40,
	}
}

// groupByReadiness buckets crypto assets by the classification the CBOM
// normalizer already computed. An asset whose QuantumReadinessGroup matches
// none of the four bucket names — empty, or a value written before this
// column existed — appears in none of them, which is a different, honest
// state from being assessed as safe.
func groupByReadiness(assets []CryptoAsset) (vulnerable, postQuantum, grover, unassessed []CryptoAsset) {
	for _, a := range assets {
		switch a.QuantumReadinessGroup {
		case "vulnerable":
			vulnerable = append(vulnerable, a)
		case "post_quantum":
			postQuantum = append(postQuantum, a)
		case "grover_note":
			grover = append(grover, a)
		case "unassessed":
			unassessed = append(unassessed, a)
		}
	}
	return vulnerable, postQuantum, grover, unassessed
}

func readinessGroupRows(label string, assets []CryptoAsset) [][]string {
	rows := [][]string{{label, "", fmt.Sprintf("%d asset(s)", len(assets))}}
	for _, a := range assets {
		detail := orNotProvided(a.QuantumRationale)
		if a.GroverNote != "" {
			detail = a.GroverNote
		}
		rows = append(rows, []string{label, orNotProvided(a.Name), detail})
	}
	return rows
}

// readinessNote ports workers/qbom/derive.py's QuantumReadiness.readiness_note()
// prose exactly, in counts rather than slices, so the CBOM's own report and
// this QBOM view never describe the same grouping in different words.
//
// ⚠ NEVER A PERCENTAGE. A "quantum readiness: 72%" would be a number this
// product invented, weighted by judgements it never published, about a threat
// with no agreed migration timeline — derive.py's own docstring is explicit
// that inventing one is the mistake this function exists to not make. Counts
// are the honest form.
func readinessNote(vulnerable, postQuantum, grover, unassessed int) string {
	if vulnerable+postQuantum+grover == 0 && unassessed == 0 {
		return "No cryptographic assets were discovered, so nothing could be " +
			"assessed for quantum vulnerability. That is not the same as having " +
			"no quantum-vulnerable cryptography — check Engine Coverage for " +
			"whether a CBOM engine ran at all."
	}

	parts := []string{fmt.Sprintf(
		"%d asset(s) use primitives broken by Shor's algorithm and require migration.",
		vulnerable)}
	if postQuantum > 0 {
		parts = append(parts, fmt.Sprintf("%d already use NIST post-quantum algorithms.", postQuantum))
	}
	if grover > 0 {
		parts = append(parts, fmt.Sprintf(
			"%d symmetric asset(s) carry a Grover note on effective key strength. "+
				"Those are sizing observations, NOT vulnerabilities, and they are "+
				"deliberately excluded from the migration list.", grover))
	}
	if unassessed > 0 {
		parts = append(parts, fmt.Sprintf(
			"%d asset(s) matched no rule and were not assessed — recorded as a gap "+
				"rather than reported as safe.", unassessed))
	}
	return strings.Join(parts, " ")
}

// ─── PDF (minimum-bar treatment — see cbom.go for the shared scope decision) ─

// quantumPage is QBOM's PDF page: device metadata (Table 8's free-form
// elements) plus the readiness paragraph, never a fabricated percentage.
func (r *pdfRender) quantumPage() {
	r.doc.AddPage()
	r.heading("Quantum Readiness")
	r.note(QBOMFormDisclosure)
	r.doc.Ln(2)

	r.heading("Device metadata")
	d := r.bom.QuantumDevice
	if d == nil {
		r.body("No device metadata has been recorded for this project yet. " +
			"Every Table 8 element is a stated gap, not a scan result — there is " +
			"no quantum-hardware scanner.")
	} else {
		r.keyValues([][2]string{
			{qbomFieldName(model.FieldCertinQbom01ModelName), d.ModelName},
			{qbomFieldName(model.FieldCertinQbom02Version), d.Version},
			{qbomFieldName(model.FieldCertinQbom03VendorOrigin), d.VendorOrigin},
			{qbomFieldName(model.FieldCertinQbom04LicenseInformation), d.LicenseInfo},
			{qbomFieldName(model.FieldCertinQbom06CommunicationProtocol), d.CommunicationProtocol},
			{qbomFieldName(model.FieldCertinQbom07Hardware), d.Hardware},
			{qbomFieldName(model.FieldCertinQbom08SoftwareDependencies), joinList(d.SoftwareDependencies)},
			{qbomFieldName(model.FieldCertinQbom09EnvironmentalImpact), d.EnvironmentalImpact},
			{qbomFieldName(model.FieldCertinQbom11Attestations), d.AttestationSignature},
		})
	}

	r.doc.Ln(4)
	r.heading("Quantum readiness (from CBOM-derived crypto assets)")
	vulnerable, postQuantum, grover, unassessed := groupByReadiness(r.bom.CryptoAssets)
	r.body(readinessNote(len(vulnerable), len(postQuantum), len(grover), len(unassessed)))

	widths := []float64{80, 30}
	r.doc.Ln(2)
	r.tableHeader([]string{"Bucket", "Count"}, widths)
	r.tableRow([]string{"Vulnerable to Shor's algorithm", strconv.Itoa(len(vulnerable))}, widths)
	r.tableRow([]string{"Already post-quantum", strconv.Itoa(len(postQuantum))}, widths)
	r.tableRow([]string{"Grover note (symmetric, not a vulnerability)", strconv.Itoa(len(grover))}, widths)
	r.tableRow([]string{"Unassessed", strconv.Itoa(len(unassessed))}, widths)
}
