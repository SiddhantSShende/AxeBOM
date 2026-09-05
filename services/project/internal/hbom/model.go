// Package hbom implements hardware-bill-of-materials import and structured
// entry for services/project.
//
// ⚠ EVERY LABEL HERE SAYS "IMPORT". NOTHING HERE SCANS.
//
// There is no open-source tool that inspects a physical device and
// enumerates its parts. See CLAUDE.md's honest-labels section and
// workers/hbom/__init__.py, which states the identical constraint for the
// Python model this package is a Go-native port of.
//
// WHY A PORT, RATHER THAN CALLING THE PYTHON: every worker under workers/ is
// invoked exclusively as a NATS-driven scan job (docs/02-CONTRACTS.md); there
// is no HTTP or CLI bridge anywhere in this codebase that lets a Go service
// call into Python-owned logic for a synchronous REST response, and HBOM has
// no scan job at all (it is import-only by design — CLAUDE.md invariant and
// docs/phases/PHASE-15-hbom.md). services/project is Go, like every other
// REST handler in this repo, so the logic is re-implemented here in Go rather
// than shelled out to a script — which CLAUDE.md invariant 7 forbids as a
// general pattern for untrusted input handling, and which would also require
// standing up a process-execution path that does not exist for any other
// service.
//
// The behaviour below is cross-checked field-for-field and rule-for-rule
// against workers/hbom/{model,csv_import,providers/*}.py. A future change to
// either side must keep both in step — there is no golden-file sharing
// mechanism between the two languages, so `csvimport_test.go` mirrors the
// cases in workers/hbom/test_hbom.py by hand.
//
// ⚠ NO GPL. django-bom is GPL-3.0 and is never imported here, exactly as in
// the Python module (CLAUDE.md invariant 9). This model is ours.
package hbom

import "strings"

// MaxDepth caps how deep a sub-component tree may go before import stops
// descending, matching workers/hbom/model.py's MAX_DEPTH.
const MaxDepth = 10

// CriticalityValues is the closed set, as a set, for the component validator.
//
// ⚠ IT WAS THE SECOND OF FOUR HAND-WRITTEN COPIES, and the only reason it did
// not drift is luck: Criticalities in device.go carried a fifth value under a
// comment claiming both matched normalize.hardware_components. Both now derive
// from the compliance profile, which is where CERT-In's answer is written down
// once (element 23, p.23, transcribed verbatim).
var CriticalityValues = criticalitySet()

func criticalitySet() map[string]bool {
	out := make(map[string]bool, len(Criticalities))
	for _, v := range Criticalities {
		out[v] = true
	}
	return out
}

// AssemblyTypes is the closed set for how a part is mounted.
var AssemblyTypes = map[string]bool{"smt": true, "tht": true, "mechanical": true}

// LifecycleValues is the closed set for a part's availability.
//
// ⚠ "nrnd" IS NOT A SYNONYM FOR EITHER NEIGHBOUR. Not Recommended for New
// Designs means buyable today and refused at the next respin — the one status
// that prompts a redesign while acting is still cheap.
//
// ⚠ "unknown" IS STORABLE AND SCORES ZERO. It is in the normalizer's
// NON_SUBSTANTIVE set, so a distributor answering "unknown" is reported
// without counting as knowledge.
var LifecycleValues = map[string]bool{
	"active": true, "nrnd": true, "obsolete": true,
	"eol": true, "preview": true, "unknown": true,
}

// EquivalenceValues is how confident we are that an alternate substitutes.
//
// ⚠ "unverified" IS THE DEFAULT, NOT "drop-in". Asserting a drop-in
// replacement is a substitution decision about somebody's hardware, and
// defaulting to the flattering value would make AxeBOM the author of a claim
// it never checked.
var EquivalenceValues = map[string]bool{
	"drop-in": true, "functional": true, "unverified": true,
}

// Alternate is an approved second source for a part. Mirrors
// normalize.hardware_component_alternates and workers/hbom/model.py's
// Alternate.
type Alternate struct {
	// Ordinal is the customer's own preference order, preserved rather than
	// re-sorted: which second source they would use is a procurement judgement.
	Ordinal          int
	ManufacturerName string
	ModelNumber      string
	SupplierInfo     string
	SupplierSKU      string
	LifecycleStatus  string
	Equivalence      string
	ApprovalNote     string
}

// IdentifiesAPart reports whether this names anything at all, mirroring the
// hardware_alternate_identifiable CHECK. An alternate naming no manufacturer,
// no MPN and no SKU is not an alternate.
func (a Alternate) IdentifiesAPart() bool {
	return a.ManufacturerName != "" || a.ModelNumber != "" || a.SupplierSKU != ""
}

// Component is one node in a hardware bill of materials. Mirrors
// normalize.hardware_components (docs/01-DATA-MODEL.md §6) and
// workers/hbom/model.py's HardwareComponent dataclass.
type Component struct {
	// LocalID and ParentLocalID wire up the tree before database ids exist —
	// during CSV parsing and while a form payload is being validated. ID and
	// ParentID are the database identity, once persisted; both may be present
	// at once while a fetched tree is being re-submitted for a partial edit.
	LocalID       string
	ParentLocalID string

	ID       string
	ParentID string

	Level     int
	SourceRow int // 0 when this node did not come from an import
	Quantity  int

	ProductName          string
	ProductVersion       string
	ProductDetails       string
	WarrantyAMC          string
	ManufacturerName     string
	ManufacturerLocation string
	ManufacturingDate    string

	// The PRODUCT's supplier — who sold this item.
	SupplierInfo     string
	SupplierLocation string

	ModelNumber            string
	SerialNumber           string
	TechnicalSpecification string

	// The COMPONENT's supplier — who supplied this part to the manufacturer of
	// the larger product. A DIFFERENT RELATIONSHIP from the pair above.
	ComponentSupplierInfo     string
	ComponentSupplierLocation string

	TechnologyNode string
	Compliance     []string
	PowerSupply    string
	LicenseInfo    string
	TestResult     string

	// §10.4.1.4, absent from Table 11.
	FirmwareVersion string
	Origin          string
	Criticality     string
	Findings        []string

	// --- manufacturing and procurement -------------------------------------
	//
	// ⚠ NOT CERT-In ELEMENTS, AND THEY MUST NEVER MOVE completeness_pct.
	// Scored separately against docs/reference/hbom-manufacturing-v1.yaml.
	// Mirrors workers/hbom/model.py's block of the same name; the two are kept
	// in step by test_the_go_port_understands_the_same_columns, which reads
	// this file's canonicalColumns rather than trusting a comment.

	// Designators is a LIST because one line item covers many placements:
	// "R1, R4, R17" is one part with quantity 3.
	Designators       []string
	PackageFootprint  string
	SupplierSKU       string
	PreferredSupplier string
	// UnitPrice stays a STRING all the way to the writer. A float would lose
	// cents on values like 0.1, and the error accumulates across a 4000-line
	// BOM into a figure somebody procures against.
	UnitPrice string
	// Currency is ISO 4217, upper-cased by Normalize. Never defaulted — a
	// guessed currency turns an unusable number into a wrong one.
	Currency string
	// DoNotPopulate: the part is on the schematic and deliberately not fitted.
	// Distinct from absent.
	DoNotPopulate   bool
	AssemblyType    string
	LifecycleStatus string
	DatasheetURL    string

	// Alternates are approved second sources.
	Alternates []Alternate

	// EnrichedFields records which fields a lookup provider supplied, so a
	// report can say where a value came from.
	EnrichedFields map[string]string

	Children []*Component
}

// Walk calls fn for this node and every descendant, depth-first, parents
// before children, stopping recursion past MaxDepth. Mirrors
// HardwareComponent.walk() in workers/hbom/model.py.
func (c *Component) Walk(depth int, fn func(depth int, node *Component)) {
	fn(depth, c)
	if depth >= MaxDepth {
		return
	}
	for _, child := range c.Children {
		child.Walk(depth+1, fn)
	}
}

// Count returns the total nodes in this subtree, including this one.
func (c *Component) Count() int {
	n := 0
	c.Walk(0, func(int, *Component) { n++ })
	return n
}

// Depth returns the deepest level reached below this node.
func (c *Component) Depth() int {
	max := 0
	c.Walk(0, func(d int, _ *Component) {
		if d > max {
			max = d
		}
	})
	return max
}

// attrValue and setAttr are a narrow reflect-free get/set over the fields an
// import or a lookup may populate, keyed by the same attribute names
// CANONICAL_COLUMNS uses in workers/hbom/csv_import.py. A switch rather than
// reflection: the field set is small, fixed, and worth being able to grep.
func attrValue(c *Component, attribute string) string {
	switch attribute {
	case "model_number":
		return c.ModelNumber
	case "product_details":
		return c.ProductDetails
	case "manufacturer_name":
		return c.ManufacturerName
	case "component_supplier_info":
		return c.ComponentSupplierInfo
	case "product_name":
		return c.ProductName
	case "product_version":
		return c.ProductVersion
	case "serial_number":
		return c.SerialNumber
	case "manufacturer_location":
		return c.ManufacturerLocation
	case "component_supplier_location":
		return c.ComponentSupplierLocation
	case "supplier_info":
		return c.SupplierInfo
	case "supplier_location":
		return c.SupplierLocation
	case "firmware_version":
		return c.FirmwareVersion
	case "origin":
		return c.Origin
	case "criticality":
		return c.Criticality
	case "technology_node":
		return c.TechnologyNode
	case "power_supply":
		return c.PowerSupply
	case "license_info":
		return c.LicenseInfo
	case "test_result":
		return c.TestResult
	case "technical_specification":
		return c.TechnicalSpecification
	case "manufacturing_date":
		return c.ManufacturingDate
	case "warranty_amc":
		return c.WarrantyAMC
	case "package_footprint":
		return c.PackageFootprint
	case "supplier_sku":
		return c.SupplierSKU
	case "preferred_supplier":
		return c.PreferredSupplier
	case "unit_price":
		return c.UnitPrice
	case "currency":
		return c.Currency
	case "assembly_type":
		return c.AssemblyType
	case "lifecycle_status":
		return c.LifecycleStatus
	case "datasheet_url":
		return c.DatasheetURL
	default:
		return ""
	}
}

func setAttr(c *Component, attribute, value string) {
	switch attribute {
	case "model_number":
		c.ModelNumber = value
	case "product_details":
		c.ProductDetails = value
	case "manufacturer_name":
		c.ManufacturerName = value
	case "component_supplier_info":
		c.ComponentSupplierInfo = value
	case "product_name":
		c.ProductName = value
	case "product_version":
		c.ProductVersion = value
	case "serial_number":
		c.SerialNumber = value
	case "manufacturer_location":
		c.ManufacturerLocation = value
	case "component_supplier_location":
		c.ComponentSupplierLocation = value
	case "supplier_info":
		c.SupplierInfo = value
	case "supplier_location":
		c.SupplierLocation = value
	case "firmware_version":
		c.FirmwareVersion = value
	case "origin":
		c.Origin = value
	case "criticality":
		c.Criticality = value
	case "technology_node":
		c.TechnologyNode = value
	case "power_supply":
		c.PowerSupply = value
	case "license_info":
		c.LicenseInfo = value
	case "test_result":
		c.TestResult = value
	case "technical_specification":
		c.TechnicalSpecification = value
	case "manufacturing_date":
		c.ManufacturingDate = value
	case "warranty_amc":
		c.WarrantyAMC = value
	case "package_footprint":
		c.PackageFootprint = value
	case "supplier_sku":
		c.SupplierSKU = value
	case "preferred_supplier":
		c.PreferredSupplier = value
	case "unit_price":
		c.UnitPrice = value
	case "currency":
		c.Currency = value
	case "assembly_type":
		c.AssemblyType = value
	case "lifecycle_status":
		c.LifecycleStatus = value
	case "datasheet_url":
		c.DatasheetURL = value
	}
}

// Normalize trims whitespace, lower-cases criticality and drops empty
// compliance entries, recursively. It does not guess: an absent value stays
// absent. Mirrors workers/hbom/model.py's normalize().
func Normalize(c *Component) *Component {
	c.ProductName = strings.TrimSpace(c.ProductName)
	c.Criticality = strings.ToLower(strings.TrimSpace(c.Criticality))
	if c.Criticality != "" && !CriticalityValues[c.Criticality] {
		// An unrecognised rating is dropped rather than coerced — mapping
		// "urgent" onto "critical" would be a guess about severity that is
		// not ours to make in a compliance document.
		c.Criticality = ""
	}

	for _, f := range []*string{
		&c.ProductVersion, &c.ProductDetails, &c.WarrantyAMC,
		&c.ManufacturerName, &c.ManufacturerLocation, &c.ManufacturingDate,
		&c.SupplierInfo, &c.SupplierLocation, &c.ModelNumber, &c.SerialNumber,
		&c.TechnicalSpecification, &c.ComponentSupplierInfo, &c.ComponentSupplierLocation,
		&c.TechnologyNode, &c.PowerSupply, &c.LicenseInfo, &c.TestResult,
		&c.FirmwareVersion, &c.Origin,
	} {
		*f = strings.TrimSpace(*f)
	}

	// --- manufacturing enums, same drop-rather-than-coerce rule -------------
	c.AssemblyType = strings.ToLower(strings.TrimSpace(c.AssemblyType))
	if c.AssemblyType != "" && !AssemblyTypes[c.AssemblyType] {
		c.AssemblyType = ""
	}
	c.LifecycleStatus = strings.ToLower(strings.TrimSpace(c.LifecycleStatus))
	if c.LifecycleStatus != "" && !LifecycleValues[c.LifecycleStatus] {
		c.LifecycleStatus = ""
	}

	// ⚠ UPPER-CASED, BECAUSE THE COLUMN IS CHECKed ON `^[A-Z]{3}$`. A file that
	// writes "usd" is not wrong about the currency, only about the case, and
	// rejecting the row over that would lose a real price. Anything that is not
	// three letters IS dropped: "US Dollars" is not an ISO 4217 code, and
	// storing it would make the column unusable to everything that reads it.
	c.Currency = strings.ToUpper(strings.TrimSpace(c.Currency))
	if len(c.Currency) != 3 || !isAlpha(c.Currency) {
		c.Currency = ""
	}

	for _, f := range []*string{
		&c.PackageFootprint, &c.SupplierSKU, &c.PreferredSupplier,
		&c.UnitPrice, &c.DatasheetURL,
	} {
		*f = strings.TrimSpace(*f)
	}

	designators := c.Designators[:0]
	for _, d := range c.Designators {
		if t := strings.TrimSpace(d); t != "" {
			designators = append(designators, t)
		}
	}
	c.Designators = designators

	alternates := c.Alternates[:0]
	for _, a := range c.Alternates {
		if !a.IdentifiesAPart() {
			continue
		}
		a.Equivalence = strings.ToLower(strings.TrimSpace(a.Equivalence))
		if !EquivalenceValues[a.Equivalence] {
			a.Equivalence = "unverified"
		}
		alternates = append(alternates, a)
	}
	c.Alternates = alternates

	compliance := c.Compliance[:0]
	for _, v := range c.Compliance {
		if t := strings.TrimSpace(v); t != "" {
			compliance = append(compliance, t)
		}
	}
	c.Compliance = compliance

	for _, child := range c.Children {
		Normalize(child)
	}
	return c
}

// isAlpha reports whether every rune is an ASCII letter.
func isAlpha(s string) bool {
	for _, r := range s {
		if r < 'A' || r > 'Z' {
			return false
		}
	}
	return s != ""
}
