package render

import (
	"strings"
	"testing"

	"github.com/axebom/axebom/libs/go-shared/model"
)

func qbomSample(device *QuantumDevice) BOM {
	return BOM{
		ReportID: "0199-qbom", ProjectName: "acme-quantum", BOMType: model.BOMTypeQBOM,
		GeneratedAt: "2026-08-17T09:14:03Z", ToolName: "AxeBOM", ToolVersion: "0.1.0",
		Coverage: Coverage{
			CompletenessPct: 30, DeclarationPct: 60,
			Formula: "sum(weight × substantive) / sum(weight × entities)",
		},
		QuantumDevice: device,
		CryptoAssets:  cryptoAssets(), // one of each of the four readiness buckets
	}
}

// TestAnAbsentQuantumDeviceIsAStatedGapNotAnOmittedSection.
//
// ⚠ CLAUDE.md INVARIANT 3: absent is reported, never silently skipped. A
// project classified QBOM before anybody filled in the device form has
// genuinely recorded nothing — the sheet must still appear, every element
// explicit `not-provided`, with a reason a reader does not have to guess at.
func TestAnAbsentQuantumDeviceIsAStatedGapNotAnOmittedSection(t *testing.T) {
	sheets, err := Sheets(qbomSample(nil))
	if err != nil {
		t.Fatalf("building sheets: %v", err)
	}

	sheet := findSheet(t, sheets, "Quantum Device")
	rows := rowsOf(t, sheet)
	if len(rows) == 0 {
		t.Fatal("the Quantum Device sheet is missing entirely for a nil device; " +
			"absence must be a stated gap, not an omitted section")
	}

	joined := flatten(rows)
	for _, want := range []string{model.NotProvided, "No device metadata has been recorded"} {
		if !strings.Contains(joined, want) {
			t.Errorf("the sheet does not say %q", want)
		}
	}
}

// TestAPopulatedQuantumDeviceRendersItsElements.
func TestAPopulatedQuantumDeviceRendersItsElements(t *testing.T) {
	device := &QuantumDevice{
		ModelName: "QKD-Node-7", Version: "2.1", VendorOrigin: "ID Quantique, Switzerland",
		CommunicationProtocol: "BB84", Hardware: "Photon detector array",
		SoftwareDependencies: []string{"libqkd"}, EnvironmentalImpact: "not-provided",
		AttestationSignature: "sig:abcd",
	}
	sheets, err := Sheets(qbomSample(device))
	if err != nil {
		t.Fatalf("building sheets: %v", err)
	}

	joined := flatten(collect(t, findSheet(t, sheets, "Quantum Device")))
	for _, want := range []string{"QKD-Node-7", "BB84", "libqkd", "sig:abcd"} {
		if !strings.Contains(joined, want) {
			t.Errorf("the populated device sheet is missing %q", want)
		}
	}
}

// TestTheReadinessSheetsFourBucketsSumCorrectly.
//
// ⚠ NO ASSET COUNTED TWICE, NO ASSET DROPPED. cryptoAssets() has exactly one
// asset in each of the four QuantumReadinessGroup buckets; the sheet's
// per-bucket counts must add up to the total, and the summary row's counts
// must match the per-bucket detail rows below it.
func TestTheReadinessSheetsFourBucketsSumCorrectly(t *testing.T) {
	assets := cryptoAssets()
	vulnerable, postQuantum, grover, unassessed := groupByReadiness(assets)

	total := len(vulnerable) + len(postQuantum) + len(grover) + len(unassessed)
	if total != len(assets) {
		t.Fatalf("the four buckets hold %d assets, want %d (every asset must land "+
			"in exactly one bucket)", total, len(assets))
	}
	for name, n := range map[string]int{
		"vulnerable": len(vulnerable), "post_quantum": len(postQuantum),
		"grover_note": len(grover), "unassessed": len(unassessed),
	} {
		if n != 1 {
			t.Errorf("bucket %s has %d assets, want 1 (the fixture has one of each)", name, n)
		}
	}

	sheets, err := Sheets(qbomSample(nil))
	if err != nil {
		t.Fatalf("building sheets: %v", err)
	}
	rows := rowsOf(t, findSheet(t, sheets, "Quantum Readiness"))
	joined := flatten(rows)
	if !strings.Contains(joined, "1 asset(s) use primitives broken by Shor") {
		t.Error("the summary row does not report the vulnerable count")
	}
	if !strings.Contains(joined, "1 already use NIST post-quantum") {
		t.Error("the summary row does not report the post-quantum count")
	}
	if !strings.Contains(joined, "1 symmetric asset(s) carry a Grover note") {
		t.Error("the summary row does not report the Grover-note count")
	}
	if !strings.Contains(joined, "1 asset(s) matched no rule") {
		t.Error("the summary row does not report the unassessed count")
	}
}

// TestReadinessNoteNeverContainsAPercentage — derive.py's own docstring is
// explicit that a "quantum readiness: 72%" figure would be invented; the Go
// port must not introduce one.
func TestReadinessNoteNeverContainsAPercentage(t *testing.T) {
	for _, v := range []int{0, 1, 5, 100} {
		note := readinessNote(v, v, v, v)
		if strings.Contains(note, "%") {
			t.Fatalf("the readiness note contains a percentage sign: %q", note)
		}
	}
	empty := readinessNote(0, 0, 0, 0)
	if !strings.Contains(empty, "No cryptographic assets were discovered") {
		t.Errorf("the zero-asset note does not say so: %q", empty)
	}
}

// TestQBOMFormDisclosureAppearsInTheNotes — the honesty label about there
// being no quantum-hardware scanner must reach the workbook, not just exist
// as an unused constant.
func TestQBOMFormDisclosureAppearsInTheNotes(t *testing.T) {
	sheets, err := Sheets(qbomSample(nil))
	if err != nil {
		t.Fatalf("building sheets: %v", err)
	}
	joined := flatten(collect(t, findSheet(t, sheets, "Notes")))
	if !strings.Contains(joined, "no open-source scanner for quantum hardware") {
		t.Error("the QBOM form-disclosure note is missing from the Notes sheet")
	}
}

// TestQBOMStillUsesTheGenericFieldCoverageSheet — unlike CBOM, a QBOM has one
// flat Table 8 field list (FieldsFor succeeds for it), so the generic sheet
// stays; only the per-row component shape is replaced.
func TestQBOMStillUsesTheGenericFieldCoverageSheet(t *testing.T) {
	sheets, err := Sheets(qbomSample(nil))
	if err != nil {
		t.Fatalf("building sheets: %v", err)
	}
	names := map[string]bool{}
	for _, s := range sheets {
		names[s.Name] = true
	}
	if !names["Field Coverage"] {
		t.Error("a QBOM report is missing the generic Field Coverage sheet")
	}
	if names["Components"] {
		t.Error("a QBOM report carries the generic Components sheet, which does " +
			"not fit one piece of device metadata")
	}
	if !names["Quantum Device"] || !names["Quantum Readiness"] {
		t.Errorf("a QBOM report is missing its dedicated sheets: %v", names)
	}
}
