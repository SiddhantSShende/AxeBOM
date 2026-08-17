package csaf

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// VEXInput is one triage decision, as CSAF needs it.
//
// ⚠ THE ORCHESTRATOR'S vex.Statement IS NOT USED DIRECTLY, and that is
// deliberate. This package lives in libs/go-shared; importing a service's
// internal type would invert the dependency and make the CSAF generator
// unusable from the report service. The mapping happens at the call site.
type VEXInput struct {
	// ClusterID is what the decision attaches to. Not published — CSAF wants
	// advisory identifiers — but carried so a caller can trace back.
	ClusterID string

	// DisplayID is the advisory a remediation ticket quotes: a CVE where one
	// exists, otherwise whatever the cluster's display id resolved to.
	DisplayID string
	// Aliases are every other identifier for the same vulnerability.
	Aliases []string

	// Status is CERT-In's spelling. Mapped to CSAF's below.
	Status string
	// Justification is required for `not_affected` and becomes the impact
	// statement CSAF demands.
	Justification string
	Remediation   string
	Workarounds   string
	Downtime      string

	Products []Product

	Version   int
	CreatedAt time.Time
	// Revisions is the supersession chain, oldest first. Published as CSAF's
	// revision history — the two answer the same auditor question.
	Revisions []RevisionInput
}

// RevisionInput is one entry in the supersession chain.
type RevisionInput struct {
	Version   int
	CreatedAt time.Time
	Summary   string
}

// Product is one affected component.
type Product struct {
	// ID is the CSAF product id. Derived from the component key so it is stable
	// across regenerations.
	ID   string
	Name string
	// PURL is the ECOSYSTEM purl, never the CERT-In identifier — a consumer
	// will try to resolve it (CLAUDE.md invariant 4).
	PURL string
}

// Options configure a generated advisory.
type Options struct {
	// TrackingID is the advisory's stable identity. Supplied rather than
	// generated so a regeneration updates an advisory instead of minting a
	// second one for the same decision.
	TrackingID string
	Title      string
	// PublisherName and Namespace identify the issuing organisation — the
	// CUSTOMER's, not EncoreBOM's. We are the tool, not the asserting party.
	PublisherName string
	PublisherNS   string

	// Now dates the document. Passed in so a re-render is byte-identical.
	Now time.Time
}

// StatusMap translates CERT-In's four statuses into CSAF's product-status keys.
//
// ⚠ THE SPELLINGS DIFFER AND THE DIFFERENCE IS NOT COSMETIC. Emitting
// `not_affected` into a CSAF document produces something a consumer's validator
// rejects; CSAF's key is `known_not_affected`.
var StatusMap = map[string]string{
	"not_affected":        "known_not_affected",
	"affected":            "known_affected",
	"fixed":               "fixed",
	"under_investigation": "under_investigation",
}

// Generate builds a CSAF 2.0 VEX document from triage decisions.
//
// ⚠ IT REFUSES TO PUBLISH A DECISION THAT WAS NEVER MADE. An input with no
// status, or with `not_affected` and no justification, produces an error rather
// than a document — publishing an unjustified suppression under a customer's
// name is the one output this package must never produce.
func Generate(inputs []VEXInput, opts Options) (*Document, error) {
	if opts.TrackingID == "" {
		return nil, fmt.Errorf("csaf: a tracking id is required; an advisory with no " +
			"stable identity cannot be updated, only duplicated")
	}
	if opts.PublisherName == "" {
		return nil, fmt.Errorf("csaf: a publisher name is required; the asserting " +
			"party is the customer, not the tool that generated the document")
	}
	if len(inputs) == 0 {
		return nil, fmt.Errorf("csaf: no VEX statements to publish")
	}

	stamp := opts.Now.UTC().Format(time.RFC3339)

	tree := &ProductTree{}
	seen := map[string]bool{}
	for _, in := range inputs {
		for _, p := range in.Products {
			if p.ID == "" || seen[p.ID] {
				continue
			}
			seen[p.ID] = true
			entry := FullProductName{ProductID: p.ID, Name: p.Name}
			if p.PURL != "" {
				entry.Helper = &ProductIdentHelper{PURL: p.PURL}
			}
			tree.FullProductNames = append(tree.FullProductNames, entry)
		}
	}
	// Deterministic order: a map would shuffle the tree between generations and
	// break byte-identical regeneration.
	sort.Slice(tree.FullProductNames, func(i, j int) bool {
		return tree.FullProductNames[i].ProductID < tree.FullProductNames[j].ProductID
	})

	vulns := make([]Vulnerability, 0, len(inputs))
	for _, in := range inputs {
		v, err := vulnerability(in)
		if err != nil {
			return nil, err
		}
		vulns = append(vulns, v)
	}
	sort.SliceStable(vulns, func(i, j int) bool { return vulns[i].CVE < vulns[j].CVE })

	doc := &Document{
		DocumentMeta: DocumentMeta{
			// `csaf_vex` rather than `csaf_security_advisory`: this document
			// asserts exploitability, it does not announce a vulnerability.
			Category:    "csaf_vex",
			CSAFVersion: Version,
			Title:       opts.Title,
			Publisher: Publisher{
				Category:  "vendor",
				Name:      opts.PublisherName,
				Namespace: opts.PublisherNS,
			},
			Tracking: tracking(opts, inputs, stamp),
		},
		ProductTree: tree,
		Vulns:       vulns,
	}

	if problems := doc.Validate(); len(problems) > 0 {
		return nil, fmt.Errorf("csaf: generated an invalid document: %s",
			strings.Join(problems, "; "))
	}
	return doc, nil
}

func tracking(opts Options, inputs []VEXInput, stamp string) Tracking {
	// ⚠ THE REVISION HISTORY MIRRORS THE VEX SUPERSESSION CHAIN. Publishing
	// only the current version throws away the evidence on the way out — the
	// same evidence the append-only design exists to produce.
	var revisions []Revision
	highest := 0

	for _, in := range inputs {
		for _, r := range in.Revisions {
			revisions = append(revisions, Revision{
				Number:  fmt.Sprintf("%d", r.Version),
				Date:    r.CreatedAt.UTC().Format(time.RFC3339),
				Summary: r.Summary,
			})
			if r.Version > highest {
				highest = r.Version
			}
		}
		if in.Version > highest {
			highest = in.Version
		}
	}

	if len(revisions) == 0 {
		revisions = []Revision{{Number: "1", Date: stamp, Summary: "Initial assessment"}}
		highest = 1
	}
	sort.SliceStable(revisions, func(i, j int) bool { return revisions[i].Date < revisions[j].Date })

	initial := revisions[0].Date

	return Tracking{
		ID:                 opts.TrackingID,
		Status:             "final",
		Version:            fmt.Sprintf("%d", highest),
		InitialReleaseDate: initial,
		CurrentReleaseDate: stamp,
		RevisionHistory:    revisions,
	}
}

func vulnerability(in VEXInput) (Vulnerability, error) {
	csafStatus, ok := StatusMap[in.Status]
	if !ok {
		return Vulnerability{}, fmt.Errorf(
			"csaf: status %q is not one of CERT-In's four", in.Status)
	}

	productIDs := make([]string, 0, len(in.Products))
	for _, p := range in.Products {
		if p.ID != "" {
			productIDs = append(productIDs, p.ID)
		}
	}
	sort.Strings(productIDs)

	v := Vulnerability{ProductStatus: &ProductStatus{}}

	// ⚠ THE CVE GOES IN `cve`; EVERYTHING ELSE GOES IN `ids`. CSAF's `cve` field
	// is defined as a CVE, and putting a GHSA there produces a document that
	// validates structurally and lies about what the identifier is.
	if strings.HasPrefix(strings.ToUpper(in.DisplayID), "CVE-") {
		v.CVE = in.DisplayID
	} else if in.DisplayID != "" {
		v.IDs = append(v.IDs, VulnID{SystemName: systemFor(in.DisplayID), Text: in.DisplayID})
	}
	for _, alias := range in.Aliases {
		if strings.EqualFold(alias, v.CVE) {
			continue
		}
		if v.CVE == "" && strings.HasPrefix(strings.ToUpper(alias), "CVE-") {
			v.CVE = alias
			continue
		}
		v.IDs = append(v.IDs, VulnID{SystemName: systemFor(alias), Text: alias})
	}
	sort.SliceStable(v.IDs, func(i, j int) bool { return v.IDs[i].Text < v.IDs[j].Text })

	switch csafStatus {
	case "known_not_affected":
		v.ProductStatus.KnownNotAffected = productIDs
	case "known_affected":
		v.ProductStatus.KnownAffected = productIDs
	case "fixed":
		v.ProductStatus.Fixed = productIDs
	case "under_investigation":
		v.ProductStatus.UnderInvestigation = productIDs
	}

	// ⚠ THE JUSTIFICATION BECOMES THE IMPACT STATEMENT CSAF REQUIRES for
	// `known_not_affected`. Without it the document is invalid — and Validate
	// catches that, so a missing justification fails generation rather than
	// producing something a consumer rejects.
	if in.Justification != "" {
		v.Threats = append(v.Threats, Threat{
			Category:   "impact",
			Details:    in.Justification,
			ProductIDs: productIDs,
		})
	}

	if in.Remediation != "" {
		v.Remediations = append(v.Remediations, Remediation{
			Category:   remediationCategory(in.Status),
			Details:    in.Remediation,
			ProductIDs: productIDs,
		})
	}
	if in.Workarounds != "" {
		v.Remediations = append(v.Remediations, Remediation{
			Category:   "workaround",
			Details:    in.Workarounds,
			ProductIDs: productIDs,
		})
	}
	// ⚠ DOWNTIME IS PUBLISHED, NOT DROPPED. The guideline names it on p.35, and
	// it is the field an operator planning a remediation window actually needs.
	// CSAF has no dedicated place for it, so it becomes a note rather than
	// being lost.
	if in.Downtime != "" {
		v.Notes = append(v.Notes, Note{
			Category: "other",
			Title:    "Expected downtime",
			Text:     in.Downtime,
		})
	}

	return v, nil
}

// remediationCategory maps a status onto CSAF's remediation vocabulary.
func remediationCategory(status string) string {
	switch status {
	case "fixed":
		return "vendor_fix"
	case "not_affected":
		return "none_available"
	default:
		return "mitigation"
	}
}

// systemFor names the identifier scheme, so a consumer knows what it is reading.
func systemFor(id string) string {
	upper := strings.ToUpper(id)
	switch {
	case strings.HasPrefix(upper, "GHSA-"):
		return "GitHub Security Advisory"
	case strings.HasPrefix(upper, "OSV-"):
		return "OSV"
	case strings.HasPrefix(upper, "PYSEC-"):
		return "PyPI Advisory Database"
	case strings.HasPrefix(upper, "GO-"):
		return "Go Vulnerability Database"
	case strings.HasPrefix(upper, "RUSTSEC-"):
		return "RustSec"
	case strings.HasPrefix(upper, "CVE-"):
		return "CVE"
	default:
		return "vendor"
	}
}
