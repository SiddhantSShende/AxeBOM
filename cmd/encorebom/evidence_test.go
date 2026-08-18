package main

import (
	"strings"
	"testing"

	"github.com/encorebom/encorebom/libs/go-shared/compliance"
)

func loadProfile(t *testing.T) *compliance.Profile {
	t.Helper()
	p, err := compliance.Load(resolveFromRepoRoot(defaultProfilePath))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// everyProfileElement returns every field id in the profile.
func everyProfileElement(p *compliance.Profile) []string {
	var out []string
	for _, f := range p.SBOM.DataFields {
		out = append(out, f.ID)
	}
	for _, f := range p.QBOM.Elements {
		out = append(out, f.ID)
	}
	for _, f := range p.AIBOM.Elements {
		out = append(out, f.ID)
	}
	for _, f := range p.HBOM.Elements {
		out = append(out, f.ID)
	}
	for _, f := range p.HBOM.AdditionalRequiredElements.Elements {
		out = append(out, f.ID)
	}
	for _, t := range p.CryptoAsset.Types {
		for _, f := range t.Fields {
			out = append(out, f.ID)
		}
	}
	return out
}

// TestEveryProfileElementIsClassified.
//
// ⚠ THE COVERAGE MAP IS THE ONE PART OF THE EVIDENCE PACK THAT CAN LIE.
//
// Everything else is generated from the profile and cannot drift. This map is
// hand-maintained and says how the product obtains each element; nothing forces
// it to stay true. When CERT-In revises the guideline and the profile gains an
// element, an unclassified element would silently appear in the pack as
// `not-implemented` — which is the safe direction, but a SILENT one. This makes
// it loud.
func TestEveryProfileElementIsClassified(t *testing.T) {
	p := loadProfile(t)

	var missing []string
	for _, id := range everyProfileElement(p) {
		if _, ok := elementCoverage[id]; !ok {
			missing = append(missing, id)
		}
	}

	if len(missing) > 0 {
		t.Fatalf("%d profile element(s) are not classified in elementCoverage:\n  %s\n\n"+
			"They would appear in the evidence pack as `not-implemented`. That is the\n"+
			"safe default, but classify them deliberately — an auditor reads this.",
			len(missing), strings.Join(missing, "\n  "))
	}
}

// TestNoStaleClassificationSurvives — the other direction.
//
// An entry for a field the profile no longer has is dead weight that reads as
// coverage. It cannot affect the rendered pack (which iterates the profile), but
// it misleads the next person to read the map.
func TestNoStaleClassificationSurvives(t *testing.T) {
	p := loadProfile(t)
	known := map[string]bool{}
	for _, id := range everyProfileElement(p) {
		known[id] = true
	}

	for id := range elementCoverage {
		if !known[id] {
			t.Errorf("elementCoverage classifies %q, which is not in the profile", id)
		}
	}
}

// TestEveryHardwareElementIsImportedOrUserSupplied.
//
// ⚠ NO OPEN-SOURCE TOOL INSPECTS A DEVICE AND ENUMERATES ITS PARTS. Marking any
// hardware element `automated` is exactly the claim the HBOM phase exists to
// avoid, and it would appear in the document a customer hands to an auditor.
func TestEveryHardwareElementIsImportedOrUserSupplied(t *testing.T) {
	p := loadProfile(t)

	hardware := append([]compliance.Field(nil), p.HBOM.Elements...)
	hardware = append(hardware, p.HBOM.AdditionalRequiredElements.Elements...)

	for _, f := range hardware {
		switch elementCoverage[f.ID] {
		case compliance.CoverageImported,
			compliance.CoverageUserSupplied,
			compliance.CoverageNotImplemented:
			// All honest.
		default:
			t.Errorf("%s (%s) is classified %q. Hardware is not discoverable: "+
				"`imported` or `user-supplied` are the only honest answers.",
				f.ID, f.Name, elementCoverage[f.ID])
		}
	}
}

// TestQBOMIsMostlyDerivedOrUserSupplied.
//
// ⚠ QBOM IS LARGELY A DERIVATION. Crypto assets come from CBOM discovery with
// quantum-vulnerability rules applied; there is no quantum-hardware scanner, and
// Table 8's device metadata is a form. Classifying these `automated` would imply
// a scanner that does not exist.
func TestQBOMIsMostlyDerivedOrUserSupplied(t *testing.T) {
	p := loadProfile(t)

	for _, f := range p.QBOM.Elements {
		if elementCoverage[f.ID] == compliance.CoverageAutomated {
			t.Errorf("%s (%s) is classified `automated`. There is no quantum-hardware "+
				"scanner — QBOM is a derivation from CBOM discovery plus device metadata "+
				"the customer supplies.", f.ID, f.Name)
		}
	}
}

// TestTheEvidencePackNeverAssertsCompliance.
//
// ⚠ THIS IS THE DOCUMENT MOST LIKELY TO BE QUOTED BACK TO US. It is generated
// for an auditor, so the one word it must not contain is the one an auditor is
// deciding.
func TestTheEvidencePackNeverAssertsCompliance(t *testing.T) {
	pack := compliance.BuildEvidencePack(loadProfile(t), elementCoverage)

	// ⚠ CHECKED PER SENTENCE, NOT PER LINE. The denial — "it does not assert
	// that any project is compliant" — wraps across a line break in the rendered
	// markdown, so a line-by-line check splits the negation from the word and
	// reports the denial as a violation of itself.
	flattened := strings.Join(strings.Fields(strings.ToLower(pack.Markdown())), " ")

	for _, sentence := range strings.Split(flattened, ". ") {
		if !strings.Contains(sentence, "compliant") {
			continue
		}
		// The pack legitimately contains "compliance" — it IS a compliance
		// evidence pack. Only an unqualified "compliant" is a claim.
		if strings.Contains(sentence, "does not assert") ||
			strings.Contains(sentence, "not assert") ||
			strings.Contains(sentence, "never asserts") {
			continue
		}
		t.Errorf("the evidence pack uses the word outside its denial: %q", sentence)
	}
}

// TestThePackStatesBothCoverageNumbers.
func TestThePackStatesBothCoverageNumbers(t *testing.T) {
	rendered := compliance.BuildEvidencePack(loadProfile(t), elementCoverage).Markdown()

	for _, required := range []string{"completeness_pct", "declaration_pct"} {
		if !strings.Contains(rendered, required) {
			t.Errorf("the pack does not mention %s; publishing one number and calling "+
				"it coverage is how a tool reports 100%% for a BOM full of not-provided",
				required)
		}
	}
}

// TestThePackSaysTheWeightsAreOurs.
//
// CERT-In assigns no weights. A reader who assumes the weighting is the
// regulator's would treat our judgement as theirs.
func TestThePackSaysTheWeightsAreOurs(t *testing.T) {
	rendered := compliance.BuildEvidencePack(loadProfile(t), elementCoverage).Markdown()
	if !strings.Contains(rendered, "not CERT-In's") {
		t.Error("the pack does not say the weights are EncoreBOM's judgement")
	}
}

// TestThePackCitesAPageForEveryElement.
//
// ⚠ THE CITATION IS THE DIFFERENCE BETWEEN AN EVIDENCE PACK AND A MARKETING
// TABLE. An auditor opens page 27 and checks.
func TestThePackCitesAPageForEveryElement(t *testing.T) {
	pack := compliance.BuildEvidencePack(loadProfile(t), elementCoverage)

	for _, section := range pack.Sections {
		for _, row := range section.Rows {
			if row.SourcePage <= 0 {
				t.Errorf("%s cites no source page", row.FieldID)
			}
		}
	}
}

// TestCryptoSectionsAreSplitByAssetType.
//
// ⚠ CERT-In TABLE 9 IS TYPE-DISCRIMINATED. One combined section implies a
// certificate is scored against `key_size`, which is the misreading that reports
// every CBOM at roughly 30% coverage — falsely, in a compliance document.
func TestCryptoSectionsAreSplitByAssetType(t *testing.T) {
	pack := compliance.BuildEvidencePack(loadProfile(t), elementCoverage)

	crypto := map[string]compliance.EvidenceSection{}
	for _, s := range pack.Sections {
		if strings.HasPrefix(s.BOMType, "CBOM/") {
			crypto[s.BOMType] = s
		}
	}

	if len(crypto) < 4 {
		t.Fatalf("only %d crypto sections; algorithms, keys, protocols and "+
			"certificates each have a distinct field set", len(crypto))
	}

	// The field sets genuinely differ — if they did not, splitting would be
	// theatre rather than correctness.
	sizes := map[int]bool{}
	for _, s := range crypto {
		sizes[s.ElementCount()] = true
	}
	if len(sizes) < 2 {
		t.Error("every crypto asset type has the same element count, which would " +
			"mean the type discrimination is not real")
	}
}

// TestTheHBOMSectionCountsBothSources.
func TestTheHBOMSectionCountsBothSources(t *testing.T) {
	pack := compliance.BuildEvidencePack(loadProfile(t), elementCoverage)

	for _, s := range pack.Sections {
		if s.BOMType != "HBOM" {
			continue
		}
		// Table 11's elements PLUS §10.4.1.4's additions. A section carrying
		// only Table 11 would report the product as complete while missing four
		// required elements.
		if !strings.Contains(s.SourceTable, "10.4.1.4") {
			t.Errorf("the HBOM section cites %q, which omits the §10.4.1.4 additions",
				s.SourceTable)
		}
		if s.ElementCount() <= len(loadProfile(t).HBOM.Elements) {
			t.Error("the HBOM section does not include the §10.4.1.4 additions")
		}
		return
	}
	t.Fatal("there is no HBOM section")
}
