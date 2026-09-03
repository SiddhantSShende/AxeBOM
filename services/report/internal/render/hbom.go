package render

import (
	"math/big"
	"sort"
	"strconv"
	"strings"

	"github.com/axebom/axebom/libs/go-shared/model"
)

// ─── HBOM ───────────────────────────────────────────────────────────────────
//
// ⚠ AN HBOM IS A SUPPLY-CHAIN PROVENANCE DOCUMENT, NOT A PARTS LIST.
//
// §10.2.1 is explicit about why the fields exist: manufacturer location and
// origin are what let a reader answer "where did this hardware come from?".
// The generic component sheet renders all of them as columns, which is correct
// and unreadable — twenty-four columns wide, with the assembly structure
// flattened away.
//
// So HBOM gets two extra sheets. Neither adds a fact; both make a fact that is
// already in the data possible to see.

// HardwareComponent is one node of a hardware bill of materials.
//
// ⚠ NOTHING HERE WAS DISCOVERED BY LOOKING AT HARDWARE. There is no
// open-source tool that inspects a device and enumerates its parts. A row
// reaches this struct from one of three places, all of them documents the
// customer produced: a design file they committed (hbom-ecad), an inventory
// their own machine reported (hbom-cdxgen-host), or a spreadsheet or form they
// filled in. The provenance line on the summary sheet says so in as many
// words, because this is the report a customer hands to an auditor.
type HardwareComponent struct {
	// ID and ParentID are the database identity, and they are what makes a
	// standards export possible at all.
	//
	// ⚠ Depth ALONE CANNOT RECONSTRUCT THE TREE SAFELY. A spreadsheet reader
	// can infer a parent from "the nearest preceding row one level shallower",
	// and hardwareTreeSheet does exactly that — fine for a rendered table where
	// the order is the document. A CycloneDX `contains` relationship is a
	// machine-readable assertion about how the product is built; deriving it
	// from row order would mean any reordering anywhere silently re-parents
	// parts, and a structurally valid BOM that is factually wrong is the one
	// failure nothing downstream can detect.
	ID       string
	ParentID string

	// Depth is the level in the assembly. 0 is the product itself.
	Depth int
	// Quantity is how many the parent contains.
	Quantity int

	Name         string
	Version      string
	Description  string
	ModelNumber  string
	SerialNumber string

	ManufacturerName     string
	ManufacturerLocation string
	Origin               string

	// The two supplier relationships Table 11 distinguishes by listing them
	// twice. See the Suppliers sheet for why they are never merged.
	SupplierInfo              string
	SupplierLocation          string
	ComponentSupplierInfo     string
	ComponentSupplierLocation string

	Criticality     string
	FirmwareVersion string
	Compliance      []string

	// Findings are vulnerability cluster display ids, matched rather than
	// imported — §10.4.1.4's fourth addition.
	Findings []string

	// VulnMatchStatus says HOW Findings came to be what it is:
	// matched | no-match | no-cpe | not-attempted.
	//
	// ⚠ WITHOUT THIS, AN EMPTY Findings IS AMBIGUOUS IN THE ONE DIRECTION
	// THAT HURTS. "We searched and found nothing" and "no vulnerability
	// source is configured" render identically as a blank cell, and a reader
	// takes the blank as reassurance. The Vulnerabilities sheet prints this
	// for every component precisely so the blank cannot be misread.
	VulnMatchStatus string

	// CPE23Candidates are the CPEs the matcher searched, or would have
	// searched. Rendered so an advisory match is auditable rather than magic,
	// and so a customer with no NVD key can see what enabling one would buy.
	CPE23Candidates []string

	// Vulnerabilities is the detail behind Findings — one row per advisory
	// match, each carrying the basis and confidence it was found on.
	Vulnerabilities []HardwareFinding

	// EnrichedFields maps an attribute to the provider that supplied it, so a
	// reader can tell a distributor's claim from the customer's own record.
	EnrichedFields map[string]string

	// --- manufacturing and procurement -------------------------------------
	//
	// ⚠ NOT CERT-In ELEMENTS. They are rendered and exported, and they are
	// scored against a SEPARATE profile — never into completeness_pct. See
	// docs/reference/hbom-manufacturing-v1.yaml.
	Designators       []string
	PackageFootprint  string
	SupplierSKU       string
	PreferredSupplier string
	UnitPrice         string
	Currency          string
	// ExtendedPrice is quantity x unit price, computed by Postgres as a
	// GENERATED column so it can never disagree with its own inputs. Empty
	// when either input is absent — the extended price of an unknown unit
	// price is not zero, and rendering it as zero would understate a total.
	ExtendedPrice          string
	DoNotPopulate          bool
	AssemblyType           string
	LifecycleStatus        string
	DatasheetURL           string
	TechnicalSpecification string

	// SourceEngine names which engine produced this row, or is empty for a row
	// entered through the import screen or the form. Provenance, not
	// decoration: a parts list assembled from a schematic and a host inventory
	// in one scan holds two different KINDS of claim.
	SourceEngine string

	// Alternates are approved second sources — the field that decides whether
	// an obsolete part delays a build or stops it.
	Alternates []HardwareAlternate
}

// HardwareAlternate is one approved second source for a part.
// HardwareFinding is one ADVISORY CVE match against a hardware component.
//
// ⚠ EVERY FIELD AFTER CVEID EXISTS TO STOP THIS BEING READ AS AN SBOM FINDING.
//
// An SBOM finding is keyed on a purl the ecosystem itself minted, and saying
// "this build contains CVE-X" is a fact. This one is keyed on a CPE assembled
// from a manufacturer string somebody typed into a spreadsheet and a model
// number off a datasheet, matched against NVD's own vocabulary that was never
// reconciled with either. MatchBasis and MatchConfidence travel with it all
// the way to the rendered cell, because a reader shown only a severity cannot
// tell a match on all three parts from one on a wildcarded vendor.
type HardwareFinding struct {
	CVEID string
	// CPE23 is what was actually searched with.
	CPE23 string
	// MatchBasis is vendor+product+version | vendor+product | firmware-version.
	MatchBasis string
	// MatchConfidence is medium or low. There is no high-confidence hardware
	// CPE match, and the schema does not offer one here by accident.
	MatchConfidence string

	Severity    string
	CVSSScore   string
	CVSSVector  string
	Description string
	Source      string
}

type HardwareAlternate struct {
	Ordinal          int
	ManufacturerName string
	ModelNumber      string
	SupplierInfo     string
	SupplierSKU      string
	LifecycleStatus  string
	// Equivalence is drop-in | functional | unverified, defaulting to
	// unverified — asserting a drop-in replacement is a substitution decision
	// about somebody's hardware, and defaulting to the flattering value would
	// make AxeBOM the author of a claim it never checked.
	Equivalence  string
	ApprovalNote string
}

// HBOMSheets are the hardware-specific sheets, appended to the standard set.
//
// ⚠ FIVE SHEETS, EACH ANSWERING A DIFFERENT PERSON'S QUESTION.
//
// One wide table containing every column would be technically complete and
// unreadable — forty columns is not a document anybody uses. The split is by
// AUDIENCE, which is what a hardware BOM actually serves:
//
//	Tree                 how the product is assembled          (engineering)
//	Origin and Suppliers where it came from                     (compliance, §10.2.1)
//	Engineering          what goes where on the board           (assembly)
//	Procurement          what to buy, from whom, at what price  (purchasing)
//	Lifecycle            what will stop being buyable           (the one that bites)
//
// None of them adds a fact. Every one makes a fact already in the data possible
// to see.
func HBOMSheets(components []HardwareComponent) []Sheet {
	return []Sheet{
		hardwareTreeSheet(components),
		hardwareOriginSheet(components),
		hardwareEngineeringSheet(components),
		hardwareProcurementSheet(components),
		hardwareLifecycleSheet(components),
		hardwareVulnerabilitySheet(components),
	}
}

// hardwareVulnerabilitySheet is CERT-In element 24 — and the sheet whose
// hardest job is making sure a BLANK ROW IS NOT READ AS "CLEAR".
//
// ⚠ EVERY COMPONENT APPEARS, INCLUDING THE ONES WITH NO MATCHES. A sheet
// listing only the parts that matched something would be a list of found
// vulnerabilities with no way to tell how many parts were actually searched —
// so a report generated with no NVD credential would render an empty
// Vulnerabilities sheet that reads exactly like a clean bill of health. Every
// component gets a row, and the row states which of the four things happened.
//
// ⚠ AND THE MATCH IS ADVISORY, SAID IN THE COLUMNS RATHER THAN A FOOTNOTE.
// Basis and Confidence sit beside the CVE because a match on a wildcarded
// vendor and a match on all three parts are different claims, and a reader
// shown only "CVE-2021-1472 / critical" cannot tell them apart.
func hardwareVulnerabilitySheet(components []HardwareComponent) Sheet {
	header := []string{
		"Component", "Part Number", "Manufacturer", "Status",
		"CVE", "Severity", "CVSS", "Match Basis", "Confidence", "Searched CPE", "Description",
	}

	rows := RowSource(func(emit func([]string) error) error {
		for _, c := range components {
			if len(c.Vulnerabilities) == 0 {
				if err := emit([]string{
					orNotProvided(c.Name),
					orNotProvided(c.ModelNumber),
					orNotProvided(c.ManufacturerName),
					vulnStatusLabel(c.VulnMatchStatus),
					"", "", "", "", "",
					joinList(c.CPE23Candidates),
					"",
				}); err != nil {
					return err
				}
				continue
			}
			for _, f := range c.Vulnerabilities {
				if err := emit([]string{
					orNotProvided(c.Name),
					orNotProvided(c.ModelNumber),
					orNotProvided(c.ManufacturerName),
					vulnStatusLabel(c.VulnMatchStatus),
					f.CVEID,
					orNotProvided(f.Severity),
					f.CVSSScore,
					f.MatchBasis,
					f.MatchConfidence,
					f.CPE23,
					f.Description,
				}); err != nil {
					return err
				}
			}
		}
		return nil
	})

	return Sheet{Name: "Vulnerabilities", Header: header, Rows: rows, Width: 22}
}

// vulnStatusLabel turns a status code into a sentence a reader cannot
// misinterpret.
//
// ⚠ THE `not-attempted` WORDING IS THE WHOLE REASON THIS FUNCTION EXISTS. A
// cell reading "not-attempted" next to an empty CVE column is read as "nothing
// found" by anybody skimming. It has to say, in words, that nobody looked.
func vulnStatusLabel(status string) string {
	switch status {
	case "matched":
		return "Matched — advisory, confirm before acting"
	case "no-match":
		return "Searched, no match"
	case "no-cpe":
		return "NOT SEARCHED — too little detail to identify this part"
	case "not-attempted", "":
		return "NOT SEARCHED — no vulnerability source configured"
	default:
		return status
	}
}

// hardwareEngineeringSheet is the assembly view: what is placed where.
//
// ⚠ THE DESIGNATORS ARE THE POINT. A line item without them cannot be placed
// on a board — "three 10k resistors" is not an instruction, "R1, R4, R17" is.
func hardwareEngineeringSheet(components []HardwareComponent) Sheet {
	header := []string{
		"Component", "Part Number", "Qty", "Designators", "Footprint",
		"Assembly", "Fitted", "Description", "Specification",
	}

	rows := RowSource(func(emit func([]string) error) error {
		for _, c := range components {
			// ⚠ "No" RATHER THAN "true"/"false", AND THE COLUMN IS "Fitted"
			// RATHER THAN "DNP". A boolean column headed with an initialism is
			// exactly what a reader gets backwards, and backwards here means a
			// factory omitting a part the design needs.
			fitted := "Yes"
			if c.DoNotPopulate {
				fitted = "No — do not populate"
			}
			if err := emit([]string{
				orNotProvided(c.Name),
				orNotProvided(c.ModelNumber),
				strconv.Itoa(c.Quantity),
				joinList(c.Designators),
				orNotProvided(c.PackageFootprint),
				orNotProvided(c.AssemblyType),
				fitted,
				orNotProvided(c.Description),
				orNotProvided(c.TechnicalSpecification),
			}); err != nil {
				return err
			}
		}
		return nil
	})

	return Sheet{Name: "Engineering", Header: header, Rows: rows, Width: 18}
}

// hardwareProcurementSheet is the buying view, with a costed roll-up.
//
// ⚠ THE TOTALS ARE LITERAL NUMBERS, NOT SPREADSHEET FORMULAS, AND THAT IS
// DELIBERATE TWICE OVER.
//
// First, `render/safe` escapes any cell beginning with `=` unconditionally in
// the writer (CLAUDE.md invariant 8) — a formula would be written as text, and
// weakening that guard for a convenience is not a trade worth making on a
// product whose entire output surface is spreadsheets.
//
// Second, and more importantly: a live formula RECALCULATES. A report is a
// statement about what was true when it was generated and is signed as such;
// a cell that quietly produces a different number when somebody edits a
// quantity is no longer the artifact that was signed. The arithmetic is stated
// in the sheet so a reader can check it, the same way the coverage formula is
// published rather than hidden.
//
// An interactive calculator belongs in the frontend, where recalculating is
// honest because nothing is being handed to an auditor.
func hardwareProcurementSheet(components []HardwareComponent) Sheet {
	header := []string{
		"Component", "Part Number", "Qty", "Supplier SKU", "Preferred Supplier",
		"Unit Price", "Extended Price", "Currency", "Alternates", "Datasheet",
	}

	rows := RowSource(func(emit func([]string) error) error {
		for _, c := range components {
			if err := emit([]string{
				orNotProvided(c.Name),
				orNotProvided(c.ModelNumber),
				strconv.Itoa(c.Quantity),
				orNotProvided(c.SupplierSKU),
				orNotProvided(c.PreferredSupplier),
				orNotProvided(c.UnitPrice),
				orNotProvided(c.ExtendedPrice),
				orNotProvided(c.Currency),
				alternatesSummary(c.Alternates),
				orNotProvided(c.DatasheetURL),
			}); err != nil {
				return err
			}
		}

		for _, total := range rollUp(components) {
			if err := emit(total); err != nil {
				return err
			}
		}
		return nil
	})

	return Sheet{Name: "Procurement", Header: header, Rows: rows, Width: 18}
}

// rollUp totals the extended prices, per currency.
//
// ⚠ PER CURRENCY, AND NEVER SUMMED ACROSS THEM. Adding 4.10 USD to 3.20 EUR
// produces a number that is not money. A BOM priced in two currencies gets two
// totals and no grand total, because there is no exchange rate in this data and
// inventing one would put a fabricated figure in a procurement document.
//
// ⚠ AND THE COUNT OF UNPRICED LINES IS STATED. A total over a parts list where
// half the prices are missing is not the cost of the product, and a reader who
// is not told that will treat it as one.
func rollUp(components []HardwareComponent) [][]string {
	totals := map[string]*big.Rat{}
	unpriced := 0

	for _, c := range components {
		if c.ExtendedPrice == "" || c.ExtendedPrice == model.NotProvided {
			unpriced++
			continue
		}
		amount, ok := new(big.Rat).SetString(c.ExtendedPrice)
		if !ok {
			unpriced++
			continue
		}
		// ⚠ big.Rat, NOT float64. The prices arrive as exact decimal strings
		// from a numeric(18,6) column precisely so they never pass through
		// binary floating point; summing them as floats here would reintroduce
		// the error the column type exists to avoid, in the one place it
		// accumulates across every line.
		currency := c.Currency
		if currency == "" {
			currency = model.NotProvided
		}
		if totals[currency] == nil {
			totals[currency] = new(big.Rat)
		}
		totals[currency].Add(totals[currency], amount)
	}

	if len(totals) == 0 && unpriced == 0 {
		return nil
	}

	currencies := make([]string, 0, len(totals))
	for c := range totals {
		currencies = append(currencies, c)
	}
	sort.Strings(currencies)

	out := make([][]string, 0, len(currencies)+1)
	for _, currency := range currencies {
		label := "TOTAL (" + currency + ")"
		if unpriced > 0 {
			label += " — " + strconv.Itoa(unpriced) + " line(s) unpriced"
		}
		out = append(out, []string{
			label, "", "", "", "",
			"", totals[currency].FloatString(6), currency, "", "",
		})
	}
	if len(currencies) > 1 {
		out = append(out, []string{
			"No grand total: this BOM is priced in more than one currency, and " +
				"there is no exchange rate in this data to combine them with.",
			"", "", "", "", "", "", "", "", "",
		})
	}
	return out
}

// hardwareLifecycleSheet is the sheet that prompts a redesign.
//
// ⚠ IT LEADS WITH THE PARTS THAT ARE A PROBLEM. An obsolete part in a shipping
// product is the finding; burying it among four hundred `active` rows in
// alphabetical order is how it goes unnoticed until a build stops. NRND sorts
// with it deliberately — Not Recommended for New Designs is buyable today and
// refused at the next respin, which is precisely the window in which acting is
// still cheap.
func hardwareLifecycleSheet(components []HardwareComponent) Sheet {
	header := []string{
		"Status", "Component", "Part Number", "Qty", "Designators",
		"Manufacturer", "Alternates", "Action",
	}

	rank := map[string]int{"obsolete": 0, "eol": 1, "nrnd": 2, "preview": 3, "unknown": 4, "active": 5}
	ordered := append([]HardwareComponent(nil), components...)
	sort.SliceStable(ordered, func(i, j int) bool {
		ri, ok := rank[ordered[i].LifecycleStatus]
		if !ok {
			ri = 6
		}
		rj, ok := rank[ordered[j].LifecycleStatus]
		if !ok {
			rj = 6
		}
		return ri < rj
	})

	rows := RowSource(func(emit func([]string) error) error {
		for _, c := range ordered {
			if err := emit([]string{
				orNotProvided(c.LifecycleStatus),
				orNotProvided(c.Name),
				orNotProvided(c.ModelNumber),
				strconv.Itoa(c.Quantity),
				joinList(c.Designators),
				orNotProvided(c.ManufacturerName),
				alternatesSummary(c.Alternates),
				lifecycleAction(c),
			}); err != nil {
				return err
			}
		}
		return nil
	})

	return Sheet{Name: "Lifecycle", Header: header, Rows: rows, Width: 20}
}

// lifecycleAction says what the status means for this specific part.
//
// ⚠ IT NAMES THE CONSEQUENCE, NOT THE STATUS. "obsolete" is a label; "cannot be
// bought, and no alternate is recorded" is the thing somebody has to act on.
func lifecycleAction(c HardwareComponent) string {
	hasAlternate := len(c.Alternates) > 0
	switch c.LifecycleStatus {
	case "obsolete", "eol":
		if hasAlternate {
			return "No longer manufactured. An approved alternate is recorded — " +
				"verify it before the next build."
		}
		return "No longer manufactured, and NO alternate is recorded. This line " +
			"will stop a build."
	case "nrnd":
		if hasAlternate {
			return "Buyable now, refused at the next respin. An alternate is recorded."
		}
		return "Buyable now, refused at the next respin. No alternate is recorded — " +
			"the cheapest moment to find one is before it is needed."
	case "preview":
		return "Pre-production. Availability and specification may still change."
	case "unknown", "":
		return "No lifecycle status was supplied. This is not the same as `active` — " +
			"nothing has been checked."
	default:
		return ""
	}
}

// alternatesSummary lists second sources with their equivalence attached.
//
// ⚠ THE EQUIVALENCE TRAVELS WITH THE PART NUMBER, ALWAYS. An alternate's MPN
// on its own reads as an approved substitution; "(unverified)" beside it is the
// difference between a decision somebody made and one nobody has.
func alternatesSummary(alternates []HardwareAlternate) string {
	if len(alternates) == 0 {
		return model.NotProvided
	}
	out := make([]string, 0, len(alternates))
	for _, a := range alternates {
		id := a.ModelNumber
		if id == "" {
			id = a.SupplierSKU
		}
		if id == "" {
			id = a.ManufacturerName
		}
		equivalence := a.Equivalence
		if equivalence == "" {
			equivalence = "unverified"
		}
		out = append(out, id+" ("+equivalence+")")
	}
	return strings.Join(out, "; ")
}

// hardwareTreeSheet renders the assembly as a tree.
//
// ⚠ THE INDENT IS A SEPARATE COLUMN, NOT LEADING SPACES IN THE NAME.
//
// Padding a name with spaces is the obvious way to show nesting in a
// spreadsheet and it is wrong twice: the indented value no longer matches the
// component's actual name, so a filter or a lookup against it fails, and a
// leading space is one of the characters a formula-injection check has to
// consider. The depth is a number, the name is the name.
func hardwareTreeSheet(components []HardwareComponent) Sheet {
	header := []string{
		"Depth",
		"Assembly",
		"Component",
		"Part Number",
		"Qty",
		"Manufacturer",
		"Criticality",
		"Firmware",
		"Vulnerabilities",
		"Enriched From",
	}

	rows := RowSource(func(emit func([]string) error) error {
		for _, c := range components {
			row := []string{
				strconv.Itoa(c.Depth),
				// A visual guide that is NOT part of any value.
				strings.Repeat("· ", c.Depth),
				orNotProvided(c.Name),
				orNotProvided(c.ModelNumber),
				strconv.Itoa(c.Quantity),
				orNotProvided(c.ManufacturerName),
				orNotProvided(c.Criticality),
				orNotProvided(c.FirmwareVersion),
				joinList(c.Findings),
				enrichmentSummary(c.EnrichedFields),
			}
			if err := emit(row); err != nil {
				return err
			}
		}
		return nil
	})

	return Sheet{Name: "Hardware Tree", Header: header, Rows: rows, Width: 20}
}

// hardwareOriginSheet is the provenance view §10.2.1 asks for.
//
// ⚠ BOTH SUPPLIER RELATIONSHIPS, SIDE BY SIDE, NEVER MERGED.
//
// Table 11 lists "Supplier Information" and "Supplier Location" twice with
// different descriptions: the company that sold the customer the PRODUCT, and
// the company that supplied a COMPONENT to that product's manufacturer.
// Rendering them in one column would assert that a distributor sold the
// customer a gateway — false, and unfalsifiable from the output.
func hardwareOriginSheet(components []HardwareComponent) Sheet {
	header := []string{
		"Component",
		"Part Number",
		"Manufacturer",
		"Manufacturer Location",
		"Origin",
		"Product Supplier",
		"Product Supplier Location",
		"Component Supplier",
		"Component Supplier Location",
		"Compliance",
	}

	rows := RowSource(func(emit func([]string) error) error {
		for _, c := range components {
			row := []string{
				orNotProvided(c.Name),
				orNotProvided(c.ModelNumber),
				orNotProvided(c.ManufacturerName),
				orNotProvided(c.ManufacturerLocation),
				orNotProvided(c.Origin),
				orNotProvided(c.SupplierInfo),
				orNotProvided(c.SupplierLocation),
				orNotProvided(c.ComponentSupplierInfo),
				orNotProvided(c.ComponentSupplierLocation),
				joinList(c.Compliance),
			}
			if err := emit(row); err != nil {
				return err
			}
		}
		return nil
	})

	return Sheet{Name: "Origin and Suppliers", Header: header, Rows: rows, Width: 26}
}

// enrichmentSummary names the providers that filled in blank fields.
//
// ⚠ PROVENANCE, NOT DECORATION. A datasheet's claim about a manufacturer is a
// different kind of fact from a serial number the customer read off the device,
// and a compliance document that presents both identically is overstating one
// of them.
func enrichmentSummary(enriched map[string]string) string {
	if len(enriched) == 0 {
		return "customer-supplied"
	}
	sources := map[string]bool{}
	for _, source := range enriched {
		sources[source] = true
	}
	out := make([]string, 0, len(sources))
	for source := range sources {
		out = append(out, source)
	}
	// Sorted so the same input renders the same bytes. Map iteration order is
	// randomized in Go, and a report whose bytes differ between runs cannot be
	// diffed, checksummed, or signed to mean anything.
	sort.Strings(out)
	return strings.Join(out, ", ")
}

// HBOMProvenanceNote is the line every HBOM report carries.
//
// ⚠ IT SAYS WHAT THIS DOCUMENT IS NOT, AND IT IS NOT OPTIONAL.
//
// It used to say the BOM was "IMPORTED from structured entry", which was the
// whole truth while a CSV and a form were the only ways in. They are not any
// more — `hbom-ecad` parses design files out of a repository, which is a real
// scan — so the note was rewritten rather than left to quietly overstate its
// own caveat in one direction and understate the product in the other.
//
// ⚠ WHAT DID NOT CHANGE IS THE CLAIM THE NOTE EXISTS TO PREVENT: that anything
// here examined physical hardware. A reader who assumes the automated coverage
// the SBOM sections have will discover otherwise at an audit, which is the
// worst possible moment.
const HBOMProvenanceNote = "AxeBOM did not examine any hardware to produce this " +
	"document, and no open-source tool can: nothing inspects a physical device " +
	"and enumerates its parts. Every value here comes from something you " +
	"supplied — a design file, a parts list, a form, or an inventory your own " +
	"machine reported — or, where marked, from a parts-data provider. A design " +
	"file states what was DESIGNED, not what was built or what is currently " +
	"fitted. Coverage below reflects what was supplied, not what exists in the " +
	"hardware."

// hardwareSourceNote names which engines produced this document.
//
// ⚠ A SCHEMATIC PARSE AND A SELF-REPORTED HOST INVENTORY ARE DIFFERENT KINDS OF
// CLAIM, and a reader who cannot tell them apart will read one as the other. A
// design file describes an intent; a host inventory describes what an operating
// system could see on one machine at one moment. Neither is the other.
func hardwareSourceNote(components []HardwareComponent) string {
	sources := map[string]bool{}
	for _, c := range components {
		if c.SourceEngine != "" {
			sources[c.SourceEngine] = true
		}
	}
	switch {
	case sources["hbom-ecad"] && sources["hbom-cdxgen-host"]:
		return "This document combines two kinds of source: hardware DESIGN FILES " +
			"from your repository or upload (what was designed), and a HOST " +
			"INVENTORY your own machine reported (what one operating system could " +
			"see). The `Detected By` provenance distinguishes them per row; they " +
			"describe different objects and are not reconciled with each other."
	case sources["hbom-ecad"]:
		return "This parts list was parsed from hardware DESIGN FILES you committed " +
			"or uploaded — schematics, netlists or BOM exports. It states what was " +
			"designed. It is not a record of what was built, and a component marked " +
			"do-not-populate is deliberately absent from the assembled product."
	case sources["hbom-cdxgen-host"]:
		return "This inventory was produced by running cdxgen on the device itself " +
			"and uploading the result. AxeBOM never reached the device. It lists " +
			"what that machine's operating system could see, which is not the same " +
			"as everything on the board."
	default:
		return ""
	}
}

// HBOMNotes returns the notes an HBOM report must carry.
func HBOMNotes(components []HardwareComponent) []string {
	notes := []string{HBOMProvenanceNote}
	if source := hardwareSourceNote(components); source != "" {
		notes = append(notes, source)
	}

	// The four elements no parts list contains. Saying WHY they are empty is
	// the difference between a gap a customer can close and one they read as a
	// product defect.
	missing := 0
	for _, c := range components {
		if c.Criticality == "" || c.Criticality == model.NotProvided {
			missing++
		}
	}
	if missing == len(components) && len(components) > 0 {
		notes = append(notes,
			"No component declares a criticality rating. §10.4.1.4 requires one for "+
				"hardware supplied to government and public-sector entities. No CAD or "+
				"ERP export contains it — it is a judgement about your hardware, and "+
				"the manual entry form is where it is recorded.")
	}

	// ⚠ AN OBSOLETE PART WITH NO ALTERNATE IS THE MOST ACTIONABLE FACT IN A
	// HARDWARE BOM, and it is one row among hundreds on the Lifecycle sheet. It
	// is repeated here because the notes are what a reader sees first.
	var stranded int
	for _, c := range components {
		if (c.LifecycleStatus == "obsolete" || c.LifecycleStatus == "eol") &&
			len(c.Alternates) == 0 {
			stranded++
		}
	}
	if stranded > 0 {
		notes = append(notes, strconv.Itoa(stranded)+
			" component(s) are obsolete or end-of-life with NO approved alternate "+
			"recorded. Each will stop a build when remaining stock runs out. See the "+
			"Lifecycle sheet.")
	}

	if note := vulnerabilityNote(components); note != "" {
		notes = append(notes, note)
	}

	return notes
}

// vulnerabilityNote states what CERT-In element 24 actually scores.
//
// ⚠ THE ELEMENT SCORES "A VULNERABILITY REFERENCE IS PRESENT", NOT "WE
// CHECKED", AND THE SCORING IS BACKWARDS IF YOU DO NOT KNOW THAT.
//
// Element 24 is a ref_list, and coverage scoring treats an empty list as
// absent. So a component with NO known vulnerability scores ZERO on element 24
// while a component with three scores full marks — a part that is clean drags
// the compliance percentage DOWN. That is genuinely how the guideline's field
// is defined (it asks whether the BOM DECLARES vulnerability information), and
// it is not something the coverage code should quietly "fix": widening
// is_substantive to count an empty list as present would change what
// `not-provided` means for every BOM type at once.
//
// So the arithmetic stays honest and the report explains it, in the same place
// the reader sees the number.
func vulnerabilityNote(components []HardwareComponent) string {
	if len(components) == 0 {
		return ""
	}

	counts := map[string]int{}
	for _, c := range components {
		status := c.VulnMatchStatus
		if status == "" {
			status = "not-attempted"
		}
		counts[status]++
	}

	// ⚠ THE UNSEARCHED CASE COMES FIRST AND SAYS SO IN THE FIRST CLAUSE. If
	// every part went unsearched, an empty Vulnerabilities column is the ONLY
	// thing the reader sees, and it reads as a clean result.
	unsearched := counts["not-attempted"] + counts["no-cpe"]
	if unsearched == len(components) {
		return "NO VULNERABILITY LOOKUP WAS PERFORMED for any component in this " +
			"document, so the absence of CVEs below means nothing was checked — not " +
			"that nothing was found. CERT-In element 24 therefore scores zero for " +
			"every component. Note that the element scores whether the BOM DECLARES " +
			"vulnerability information, not whether a check was run: a part with no " +
			"known vulnerability scores the same zero as one nobody looked at. The " +
			"Vulnerabilities sheet states which of the two applies per component."
	}

	parts := []string{
		"Hardware vulnerability matching is ADVISORY. A hardware component has no " +
			"package identifier, so each match is a string comparison between the " +
			"manufacturer and part number you supplied and NVD's own vendor and " +
			"product vocabulary, which was never reconciled with either. Confirm " +
			"every match against the manufacturer's own advisory before acting on it.",
		"CERT-In element 24 scores whether a component DECLARES vulnerability " +
			"information, not whether a check was run — so a component searched and " +
			"found clean scores the same zero as one nobody looked at. The " +
			"Vulnerabilities sheet distinguishes the two per component; the " +
			"percentage cannot.",
	}

	if unsearched > 0 {
		parts = append(parts, strconv.Itoa(unsearched)+" of "+
			strconv.Itoa(len(components))+" component(s) were NOT searched at all — "+
			"either no vulnerability source is configured, or the component states "+
			"too little to identify. Their empty rows are not a clean result.")
	}

	return strings.Join(parts, " ")
}

// ---------------------------------------------------------------------------
// PDF
// ---------------------------------------------------------------------------

// hardwareInventoryPage replaces the generic component page for an HBOM.
//
// ⚠ "INSTEAD OF, NOT ALONGSIDE" — the same rule cbom.go and aibom.go follow.
// componentSheet's identity columns (PURL, Depth, Orphan, Scope, Detected By)
// describe a position in a dependency graph; a capacitor has none of them, and
// rendering a parts list through them produces a page of `not-provided`.
//
// ⚠ AND IT SHOWS THE COLUMNS THAT PROMPT AN ACTION. A page budget forces a
// choice, and the choice is deliberate: designators (where it goes), quantity
// (how many), lifecycle (whether it can still be bought). Manufacturer and
// origin have their own page in the XLSX; a part that cannot be bought is the
// one a reader has to see in the PDF they actually open.
func (r *pdfRender) hardwareInventoryPage() {
	r.doc.AddPage()
	r.heading("Hardware")
	r.note("Designator, quantity and lifecycle only, to fit the page budget. " +
		"The full parts list — procurement, cost roll-up, origin and supplier — " +
		"is in the XLSX and JSON exports, which are not page-capped.")
	r.doc.Ln(2)

	widths := []float64{45, 35, 15, 30, 25}
	r.tableHeader([]string{"Component", "Designators", "Qty", "Part Number", "Lifecycle"}, widths)
	for i, h := range r.bom.Hardware {
		if r.overCap() {
			r.markTruncated("hardware components", i, len(r.bom.Hardware))
			return
		}
		lifecycle := orNotProvided(h.LifecycleStatus)
		if h.DoNotPopulate {
			// The one flag that changes what a factory does.
			lifecycle += " · DNP"
		}
		r.tableRow([]string{
			orNotProvided(h.Name),
			joinList(h.Designators),
			strconv.Itoa(h.Quantity),
			orNotProvided(h.ModelNumber),
			lifecycle,
		}, widths)
	}
}
