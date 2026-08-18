package compliance

import (
	"fmt"
	"sort"
	"strings"
)

// ─── The evidence pack ──────────────────────────────────────────────────────
//
// ⚠ THIS IS THE ARTIFACT A CUSTOMER'S AUDITOR ACTUALLY ASKS FOR, and producing
// it is the honest test of whether the product does what it claims.
//
// It answers one question per element: **where does this value come from, and
// can it be traced to the page of the guideline that requires it?** Not "are we
// compliant" — we never answer that, and §16.1's guardrail audit enforces the
// silence. The pack states what the product covers, how, and where it does not.
//
// Every row cites a page of the source PDF. That citation is the difference
// between an evidence pack and a marketing table: an auditor can open page 27
// and check.

// Coverage classifies how EncoreBOM obtains an element.
type Coverage string

const (
	// CoverageAutomated means a scanner or derivation populates it.
	CoverageAutomated Coverage = "automated"
	// CoverageDerived means EncoreBOM computes it from other data.
	CoverageDerived Coverage = "derived"
	// CoverageImported means it comes from a customer's structured import.
	//
	// ⚠ NOT A WEAKER FORM OF AUTOMATED. For hardware it is the ONLY form: no
	// tool discovers physical parts. Labelling it "automated" would be the lie
	// the HBOM phase exists to avoid.
	CoverageImported Coverage = "imported"
	// CoverageUserSupplied means only the customer can answer.
	//
	// ⚠ AND THAT IS INFORMATION, NOT A GAP IN THE PRODUCT. Intended usage,
	// out-of-scope usage, warranty terms and criticality are judgements about
	// somebody's own system. A tool that guessed them would be inventing facts
	// and reporting a higher coverage number for doing so.
	CoverageUserSupplied Coverage = "user-supplied"
	// CoverageNotImplemented means the product does not populate it yet.
	//
	// ⚠ PRESENT IN THE PACK BY DESIGN. An evidence pack that omits what is not
	// covered is a sales document. The gap is the most useful row on the page.
	CoverageNotImplemented Coverage = "not-implemented"
)

// EvidenceRow is one element's entry.
type EvidenceRow struct {
	FieldID string
	Ordinal int
	Name    string
	// SourcePage is the page of the CERT-In PDF that requires this element.
	// An auditor opens it and checks.
	SourcePage int
	// Status is `verified` or `assumed` — whether a human read that page.
	Status string
	// Weight is EncoreBOM's, NOT CERT-In's. The guideline assigns none.
	Weight        int
	Scored        bool
	Coverage      Coverage
	CanonicalPath string
	CycloneDXPath string
	SPDXPath      string
	Note          string
}

// EvidenceSection is one BOM type's elements.
type EvidenceSection struct {
	BOMType     string
	SourceTable string
	Rows        []EvidenceRow
}

// ElementCount is rendered rather than written. Never print a literal.
func (s EvidenceSection) ElementCount() int { return len(s.Rows) }

// ByCoverage counts the rows in each coverage class.
func (s EvidenceSection) ByCoverage() map[Coverage]int {
	out := map[Coverage]int{}
	for _, r := range s.Rows {
		out[r.Coverage]++
	}
	return out
}

// EvidencePack is the whole document.
type EvidencePack struct {
	ProfileID       string
	ProfileRevision int
	SourceDocument  string
	Authority       string
	Published       string
	AllVerified     bool
	Sections        []EvidenceSection
	// AssumedFields are elements no human has checked against the PDF.
	//
	// ⚠ LISTED SEPARATELY AND PROMINENTLY. An unverified assumption that is
	// visible is a manageable risk; one that is invisible is how a compliance
	// product lies without anybody deciding to.
	AssumedFields []string
}

// BuildEvidencePack assembles the pack from the profile and a coverage map.
//
// `coverage` maps a field id to how the product obtains it. A field absent from
// the map is `not-implemented` — the DEFAULT IS THE PESSIMISTIC ONE, so
// forgetting to classify a new element understates the product rather than
// overstating it.
func BuildEvidencePack(p *Profile, coverage map[string]Coverage) EvidencePack {
	pack := EvidencePack{
		ProfileID:       p.Meta.ID,
		ProfileRevision: p.Meta.Revision,
		SourceDocument:  p.Meta.SourceDocument,
		Authority:       p.Meta.Authority,
		Published:       p.Meta.Published,
		AllVerified:     p.Meta.AllEntriesVerified,
	}

	add := func(bomType, sourceTable string, fields []Field) {
		if len(fields) == 0 {
			return
		}
		section := EvidenceSection{BOMType: bomType, SourceTable: sourceTable}
		for _, f := range fields {
			how, ok := coverage[f.ID]
			if !ok {
				how = CoverageNotImplemented
			}
			section.Rows = append(section.Rows, EvidenceRow{
				FieldID: f.ID, Ordinal: f.Ordinal, Name: f.Name,
				SourcePage: f.SourcePage, Status: f.Status,
				Weight: f.Weight, Scored: f.IsScored(), Coverage: how,
				CanonicalPath: f.CanonicalPath,
				CycloneDXPath: f.CycloneDXPath,
				SPDXPath:      f.SPDXPath,
				Note:          f.Note,
			})
			if f.Status != "verified" {
				pack.AssumedFields = append(pack.AssumedFields, f.ID)
			}
		}
		pack.Sections = append(pack.Sections, section)
	}

	add("SBOM", "CERT-In Table 5 (data fields)", p.SBOM.DataFields)
	add("QBOM", "CERT-In Table 8", p.QBOM.Elements)
	add("AIBOM", "CERT-In Table 10", p.AIBOM.Elements)

	hbom := append([]Field(nil), p.HBOM.Elements...)
	hbom = append(hbom, p.HBOM.AdditionalRequiredElements.Elements...)
	add("HBOM", p.HBOM.SourceTable+" plus §"+p.HBOM.AdditionalRequiredElements.SourceSection, hbom)

	// ⚠ CBOM IS SECTIONED BY ASSET TYPE, NOT FLATTENED. CERT-In Table 9
	// discriminates: algorithms, keys, protocols and certificates have
	// DIFFERENT field sets. One combined section would imply a certificate is
	// scored against `key_size`, which is exactly the misreading that reports
	// every CBOM at roughly 30% coverage.
	for _, key := range SortedKeys(p.CryptoAsset.Types) {
		t := p.CryptoAsset.Types[key]
		add("CBOM/"+t.AssetTypeValue, p.CryptoAsset.SourceTable+" ("+t.AssetTypeValue+")", t.Fields)
	}

	sort.Strings(pack.AssumedFields)
	return pack
}

// Markdown renders the pack.
//
// ⚠ NO FIELD COUNT IS WRITTEN. Every number comes from len(). The word
// "compliant" does not appear, and `profile guardrails` fails the build if it
// ever does.
func (pack EvidencePack) Markdown() string {
	var b strings.Builder

	b.WriteString("# CERT-In coverage evidence\n\n")
	fmt.Fprintf(&b, "Profile `%s` revision %d, generated from `docs/reference/certin-v2.0.yaml`.\n\n",
		pack.ProfileID, pack.ProfileRevision)
	fmt.Fprintf(&b, "| | |\n|---|---|\n")
	fmt.Fprintf(&b, "| Source | %s |\n", pack.SourceDocument)
	fmt.Fprintf(&b, "| Authority | %s |\n", pack.Authority)
	fmt.Fprintf(&b, "| Published | %s |\n", pack.Published)
	fmt.Fprintf(&b, "| Every entry verified against the PDF | %t |\n\n", pack.AllVerified)

	b.WriteString(readingNote)

	if len(pack.AssumedFields) > 0 {
		b.WriteString("\n## Unverified entries\n\n")
		b.WriteString("⚠ The following elements are recorded as `assumed` rather than " +
			"verified against the source document. Every report that scores them says so.\n\n")
		for _, id := range pack.AssumedFields {
			fmt.Fprintf(&b, "- `%s`\n", id)
		}
		b.WriteString("\n")
	}

	for _, section := range pack.Sections {
		fmt.Fprintf(&b, "\n## %s — %d elements\n\n", section.BOMType, section.ElementCount())
		fmt.Fprintf(&b, "Source: %s\n\n", section.SourceTable)

		counts := section.ByCoverage()
		b.WriteString("| How obtained | Elements |\n|---|---|\n")
		for _, how := range []Coverage{
			CoverageAutomated, CoverageDerived, CoverageImported,
			CoverageUserSupplied, CoverageNotImplemented,
		} {
			if counts[how] > 0 {
				fmt.Fprintf(&b, "| %s | %d |\n", how, counts[how])
			}
		}

		b.WriteString("\n| # | Element | Page | Status | How obtained | Canonical path |\n")
		b.WriteString("|---|---|---|---|---|---|\n")
		for _, r := range section.Rows {
			scored := ""
			if !r.Scored {
				scored = " *(not scored)*"
			}
			fmt.Fprintf(&b, "| %d | %s%s | p.%d | %s | %s | `%s` |\n",
				r.Ordinal, r.Name, scored, r.SourcePage, r.Status, r.Coverage, r.CanonicalPath)
		}
	}

	b.WriteString(closingNote)
	return b.String()
}

const readingNote = `
## How to read this

**Two coverage numbers, always.** Every generated report publishes
` + "`completeness_pct`" + ` (substantive values only — the honest signal) and
` + "`declaration_pct`" + ` (any value, including an explicit ` + "`not-provided`" + `).
A value of ` + "`not-provided`" + ` is *reported* but scores zero for completeness,
because omitting a field hides a gap while declaring it states one.

**Weights are EncoreBOM's judgement, not CERT-In's.** The guideline assigns no
weights. They exist so a single percentage can be produced; the per-element
table below is the unweighted evidence, and it is the part to check.

**"How obtained" is a claim about this product, not about the guideline.**
` + "`user-supplied`" + ` means only you can answer — a judgement about your own
system that a tool guessing would get wrong while reporting a higher number for
having guessed. ` + "`imported`" + ` means structured entry; for hardware it is the
only form, because no tool discovers physical parts.

**What this document does not say.** It does not assert that any project is
compliant. EncoreBOM reports violations against a configured policy; compliance
is a determination an auditor makes about an organisation.

`

const closingNote = `

## Engine coverage

Every generated report carries a mandatory Engine Coverage section listing each
requested engine, its terminal status, the ecosystems it covered, and any
ecosystem detected with **no available engine**.

⚠ That last line is the one to read. An SBOM that silently omits an ecosystem is
worse than no SBOM, because it converts an unknown into a false negative the
reader trusts. ` + "`partial`" + ` is a first-class status here, not an error.
`
