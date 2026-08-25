package render

import (
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

// HardwareComponent is one node of an imported hardware tree.
//
// ⚠ IMPORTED. There is no open-source tool that inspects a device and
// enumerates its parts, and nothing in this product discovers hardware. The
// provenance line on the summary sheet says so in as many words, because this
// is the report a customer hands to an auditor.
type HardwareComponent struct {
	// Depth is the level in the assembly. 0 is the product itself.
	Depth int
	// Quantity is how many the parent contains.
	Quantity int

	Name        string
	ModelNumber string

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

	// EnrichedFields maps an attribute to the provider that supplied it, so a
	// reader can tell a distributor's claim from the customer's own record.
	EnrichedFields map[string]string
}

// HBOMSheets are the hardware-specific sheets, appended to the standard set.
func HBOMSheets(components []HardwareComponent) []Sheet {
	return []Sheet{
		hardwareTreeSheet(components),
		hardwareOriginSheet(components),
	}
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
// ⚠ IT SAYS "IMPORT", AND IT IS NOT OPTIONAL.
//
// The rest of this product scans. An HBOM does not, because nothing can — and a
// report that leaves that ambiguous invites a reader to assume the same
// automated coverage the SBOM sections have. That assumption is discovered at
// an audit, which is the worst possible moment.
const HBOMProvenanceNote = "This hardware BOM was IMPORTED from structured entry — " +
	"a parts list, a form, or both. AxeBOM does not discover physical " +
	"components, and no open-source tool does; every value here was supplied by " +
	"the customer or, where marked, by a parts-data provider. Coverage below " +
	"reflects what was supplied, not what exists in the hardware."

// HBOMNotes returns the notes an HBOM report must carry.
func HBOMNotes(components []HardwareComponent) []string {
	notes := []string{HBOMProvenanceNote}

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

	return notes
}
