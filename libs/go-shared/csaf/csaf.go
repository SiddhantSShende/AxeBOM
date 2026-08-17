// Package csaf builds and reads CSAF 2.0 VEX documents.
//
// ⚠ THE FULL DOCUMENT IS STORED, NOT REBUILT FROM COLUMNS.
//
// CSAF 2.0 defines far more than this product models. Reconstructing a document
// from the handful of columns we keep would silently drop every field we do not
// know about — and a consumer's validator is precisely what notices. So the
// generated JSON is stored verbatim in `csaf_advisories.document`, and
// `Parse` reads it back without loss.
//
// ⚠ CSAF FOLLOWS VEX IN THE SEQUENCE, NOT ALONGSIDE IT.
//
// The guideline's Figure 7 (p.35) is explicit: discovery → VEX → CSAF →
// mitigation → ongoing updates → SBOM integration. A CSAF advisory is the
// PUBLISHED form of a triage decision already made; generating one without a
// VEX statement behind it would be publishing an assertion nobody recorded.
//
// This package lives in libs/go-shared because two services need it: the
// orchestrator owns the VEX statements and the report service publishes them.
package csaf

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Version is the only CSAF version this build produces or accepts.
const Version = "2.0"

// Document is a CSAF 2.0 advisory.
//
// ⚠ IT CARRIES `Extra` FOR EVERY FIELD WE DO NOT MODEL. A document parsed and
// re-serialized must come back byte-equivalent, or storing it "for round-trip
// fidelity" is a claim the code does not keep.
type Document struct {
	DocumentMeta DocumentMeta    `json:"document"`
	ProductTree  *ProductTree    `json:"product_tree,omitempty"`
	Vulns        []Vulnerability `json:"vulnerabilities,omitempty"`
	Extra        map[string]any  `json:"-"`
}

// DocumentMeta is the `document` object.
type DocumentMeta struct {
	Category    string    `json:"category"`
	CSAFVersion string    `json:"csaf_version"`
	Title       string    `json:"title"`
	Publisher   Publisher `json:"publisher"`
	Tracking    Tracking  `json:"tracking"`
	Notes       []Note    `json:"notes,omitempty"`

	Extra map[string]any `json:"-"`
}

// Publisher identifies who issued the advisory.
type Publisher struct {
	Category  string `json:"category"`
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
}

// Tracking is the advisory's identity and revision history.
type Tracking struct {
	ID                 string     `json:"id"`
	Status             string     `json:"status"`
	Version            string     `json:"version"`
	InitialReleaseDate string     `json:"initial_release_date"`
	CurrentReleaseDate string     `json:"current_release_date"`
	RevisionHistory    []Revision `json:"revision_history"`
}

// Revision is one entry in the tracking history.
//
// ⚠ IT MIRRORS THE VEX SUPERSESSION CHAIN. CSAF's revision history and our
// append-only statements answer the same auditor question, so publishing only
// the current version would throw away the evidence on the way out.
type Revision struct {
	Number  string `json:"number"`
	Date    string `json:"date"`
	Summary string `json:"summary"`
}

// Note is prose attached to the document or a vulnerability.
type Note struct {
	Category string `json:"category"`
	Text     string `json:"text"`
	Title    string `json:"title,omitempty"`
}

// ProductTree names the affected products.
type ProductTree struct {
	FullProductNames []FullProductName `json:"full_product_names,omitempty"`
}

// FullProductName is one product a statement applies to.
type FullProductName struct {
	ProductID string              `json:"product_id"`
	Name      string              `json:"name"`
	Helper    *ProductIdentHelper `json:"product_identification_helper,omitempty"`
}

// ProductIdentHelper carries machine-readable identifiers.
//
// ⚠ THE PURL GOES HERE, AND IT IS THE ECOSYSTEM PURL. Not the CERT-In
// identifier — `pkg:supplier/Org/Name` is not resolvable and a CSAF consumer
// would try to resolve it (CLAUDE.md invariant 4).
type ProductIdentHelper struct {
	PURL string `json:"purl,omitempty"`
}

// Vulnerability is one advisory entry.
type Vulnerability struct {
	CVE           string         `json:"cve,omitempty"`
	IDs           []VulnID       `json:"ids,omitempty"`
	Notes         []Note         `json:"notes,omitempty"`
	ProductStatus *ProductStatus `json:"product_status,omitempty"`
	Remediations  []Remediation  `json:"remediations,omitempty"`
	Threats       []Threat       `json:"threats,omitempty"`
	Scores        []Score        `json:"scores,omitempty"`

	Extra map[string]any `json:"-"`
}

// VulnID is a non-CVE identifier — GHSA, OSV, a distro id.
type VulnID struct {
	SystemName string `json:"system_name"`
	Text       string `json:"text"`
}

// ProductStatus is where the four VEX statuses land in CSAF.
//
// ⚠ CSAF SPELLS THEM DIFFERENTLY FROM CERT-In, AND THE MAPPING IS NOT
// COSMETIC. `not_affected` becomes `known_not_affected`; `affected` becomes
// `known_affected`; `fixed` becomes `fixed`; `under_investigation` becomes
// `under_investigation`. Emitting CERT-In's spelling into a CSAF document
// produces something a consumer's validator rejects.
type ProductStatus struct {
	Fixed              []string `json:"fixed,omitempty"`
	KnownAffected      []string `json:"known_affected,omitempty"`
	KnownNotAffected   []string `json:"known_not_affected,omitempty"`
	UnderInvestigation []string `json:"under_investigation,omitempty"`
}

// Remediation is what to do about it.
type Remediation struct {
	Category   string   `json:"category"`
	Details    string   `json:"details"`
	ProductIDs []string `json:"product_ids,omitempty"`
}

// Threat carries the impact statement a `known_not_affected` requires.
type Threat struct {
	Category   string   `json:"category"`
	Details    string   `json:"details"`
	ProductIDs []string `json:"product_ids,omitempty"`
}

// Score is a CVSS assessment.
type Score struct {
	ProductIDs []string       `json:"products"`
	CVSSV3     map[string]any `json:"cvss_v3,omitempty"`
	CVSSV2     map[string]any `json:"cvss_v2,omitempty"`
}

// ---------------------------------------------------------------------------
// Round trip
// ---------------------------------------------------------------------------

// Parse reads a CSAF document, keeping every field it does not model.
//
// ⚠ THE UNMODELLED FIELDS ARE THE POINT. A document that round-trips only the
// parts we understand is not stored "for fidelity" — it is stored lossily, and
// the loss shows up at whoever consumes it next.
func Parse(data []byte) (*Document, error) {
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("csaf: not valid JSON: %w", err)
	}

	var doc Document
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("csaf: unexpected shape: %w", err)
	}

	// Everything at the top level we did not map.
	doc.Extra = extraKeys(raw, "document", "product_tree", "vulnerabilities")

	if inner, ok := raw["document"].(map[string]any); ok {
		doc.DocumentMeta.Extra = extraKeys(
			inner, "category", "csaf_version", "title", "publisher", "tracking", "notes")
	}

	if vulns, ok := raw["vulnerabilities"].([]any); ok {
		for i, v := range vulns {
			inner, ok := v.(map[string]any)
			if !ok || i >= len(doc.Vulns) {
				continue
			}
			doc.Vulns[i].Extra = extraKeys(inner,
				"cve", "ids", "notes", "product_status", "remediations", "threats", "scores")
		}
	}

	return &doc, nil
}

// Marshal serializes a document, re-merging the fields Parse preserved.
func (d *Document) Marshal() ([]byte, error) {
	out, err := toMap(d)
	if err != nil {
		return nil, err
	}
	return json.Marshal(out)
}

// MarshalIndent is Marshal, formatted. Both re-merge Extra.
func (d *Document) MarshalIndent() ([]byte, error) {
	out, err := toMap(d)
	if err != nil {
		return nil, err
	}
	return json.MarshalIndent(out, "", "  ")
}

func toMap(d *Document) (map[string]any, error) {
	// Round-tripping through JSON rather than reflecting over the struct: the
	// json tags already say how every field is named, and a second mapping here
	// would be a second place for that to drift.
	data, err := json.Marshal(struct {
		DocumentMeta DocumentMeta    `json:"document"`
		ProductTree  *ProductTree    `json:"product_tree,omitempty"`
		Vulns        []Vulnerability `json:"vulnerabilities,omitempty"`
	}{d.DocumentMeta, d.ProductTree, d.Vulns})
	if err != nil {
		return nil, err
	}

	var out map[string]any
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, err
	}

	mergeExtra(out, d.Extra)

	if inner, ok := out["document"].(map[string]any); ok {
		mergeExtra(inner, d.DocumentMeta.Extra)
	}
	if vulns, ok := out["vulnerabilities"].([]any); ok {
		for i, v := range vulns {
			if inner, ok := v.(map[string]any); ok && i < len(d.Vulns) {
				mergeExtra(inner, d.Vulns[i].Extra)
			}
		}
	}

	return out, nil
}

// mergeExtra adds preserved keys back.
//
// ⚠ IT NEVER OVERWRITES A MODELLED FIELD. If a key is both modelled and in
// Extra, the modelled value is the current one — Extra is a record of what we
// did not understand, not a shadow copy that can win.
func mergeExtra(target map[string]any, extra map[string]any) {
	for k, v := range extra {
		if _, exists := target[k]; !exists {
			target[k] = v
		}
	}
}

func extraKeys(raw map[string]any, known ...string) map[string]any {
	knownSet := make(map[string]bool, len(known))
	for _, k := range known {
		knownSet[k] = true
	}

	var out map[string]any
	for k, v := range raw {
		if knownSet[k] {
			continue
		}
		if out == nil {
			out = map[string]any{}
		}
		out[k] = v
	}
	return out
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

// Validate checks the parts of CSAF 2.0 this build asserts.
//
// ⚠ NOT A FULL SCHEMA VALIDATION, AND IT SAYS SO. The official schema is large
// and lives upstream; pulling a validator in would be a dependency whose licence
// needs review (CLAUDE.md invariant 9). What this checks is every field we
// ourselves populate plus the conditional rules a consumer will reject on —
// which is the set our own generator can get wrong.
func (d *Document) Validate() []string {
	var problems []string

	if d.DocumentMeta.CSAFVersion != Version {
		problems = append(problems, fmt.Sprintf(
			"document.csaf_version is %q, want %q", d.DocumentMeta.CSAFVersion, Version))
	}
	if d.DocumentMeta.Category == "" {
		problems = append(problems, "document.category is required")
	}
	if strings.TrimSpace(d.DocumentMeta.Title) == "" {
		problems = append(problems, "document.title is required")
	}
	if d.DocumentMeta.Tracking.ID == "" {
		problems = append(problems, "document.tracking.id is required")
	}
	if len(d.DocumentMeta.Tracking.RevisionHistory) == 0 {
		problems = append(problems,
			"document.tracking.revision_history must have at least one entry")
	}
	if d.DocumentMeta.Publisher.Name == "" {
		problems = append(problems, "document.publisher.name is required")
	}

	known := map[string]bool{}
	if d.ProductTree != nil {
		for _, p := range d.ProductTree.FullProductNames {
			known[p.ProductID] = true
		}
	}

	for i, v := range d.Vulns {
		if v.CVE == "" && len(v.IDs) == 0 {
			problems = append(problems, fmt.Sprintf(
				"vulnerabilities[%d] has neither a cve nor any ids", i))
		}
		if v.ProductStatus == nil {
			continue
		}

		// ⚠ EVERY PRODUCT ID MUST EXIST IN THE PRODUCT TREE. A dangling id is
		// the most common way a hand-built CSAF document fails a consumer's
		// validator, and it is silent in ours until somebody else parses it.
		for _, id := range allProductIDs(v.ProductStatus) {
			if !known[id] {
				problems = append(problems, fmt.Sprintf(
					"vulnerabilities[%d] references product_id %q, which is not in the product tree",
					i, id))
			}
		}

		// ⚠ `known_not_affected` REQUIRES AN IMPACT STATEMENT. CSAF says so, and
		// for the same reason we refuse an unjustified `not_affected`: a
		// suppression with no stated reason is unreviewable.
		if len(v.ProductStatus.KnownNotAffected) > 0 && !hasImpactStatement(v) {
			problems = append(problems, fmt.Sprintf(
				"vulnerabilities[%d] declares known_not_affected with no impact "+
					"statement; a suppression without a reason cannot be reviewed", i))
		}
	}

	return problems
}

func allProductIDs(s *ProductStatus) []string {
	out := make([]string, 0,
		len(s.Fixed)+len(s.KnownAffected)+len(s.KnownNotAffected)+len(s.UnderInvestigation))
	out = append(out, s.Fixed...)
	out = append(out, s.KnownAffected...)
	out = append(out, s.KnownNotAffected...)
	out = append(out, s.UnderInvestigation...)
	sort.Strings(out)
	return out
}

func hasImpactStatement(v Vulnerability) bool {
	for _, t := range v.Threats {
		if t.Category == "impact" && strings.TrimSpace(t.Details) != "" {
			return true
		}
	}
	for _, n := range v.Notes {
		if n.Category == "other" || n.Category == "description" {
			if strings.TrimSpace(n.Text) != "" {
				return true
			}
		}
	}
	return false
}

// Now is the clock a document is dated by.
//
// ⚠ PASSED IN, NEVER READ FROM time.Now INSIDE THE GENERATOR. A CSAF advisory
// is dated by the decision it publishes, not by the moment somebody
// regenerated it — and a re-render must produce the same bytes (ADR-0003).
type Now = time.Time
