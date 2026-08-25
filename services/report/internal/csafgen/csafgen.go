// Package csafgen builds a CSAF 2.0 document from one VEX statement.
//
// ⚠ CSAF FOLLOWS VEX IN THE SEQUENCE, NEVER THE OTHER WAY AROUND. Generating
// one requires an existing vex.Statement — libs/go-shared/csaf's own module
// doc says why: "a CSAF advisory is the PUBLISHED form of a triage decision
// already made; generating one without a VEX statement behind it would be
// publishing an assertion nobody recorded."
//
// ⚠ THIS PRODUCES THE SMALLEST DOCUMENT csaf.Document.Validate() ACCEPTS,
// NOT A MAXIMAL ONE. CVSS scoring, a full product tree covering every
// affected version, threat notes beyond the required impact statement — all
// real CSAF 2.0 fields this package does not populate because AxeBOM does
// not (yet) hold the data to populate them honestly. A CSAF consumer reading
// a sparse-but-valid document learns less than one carrying more; it does
// not learn something FALSE, which is the bar every export package in this
// codebase holds itself to (see export/export.go's own "never invents a
// value" doc comment).
package csafgen

import (
	"fmt"
	"strings"
	"time"

	"github.com/axebom/axebom/libs/go-shared/csaf"
	"github.com/axebom/axebom/libs/go-shared/vex"
)

// Input is everything Generate needs beyond the VEX statement itself —
// context this package has no way to look up on its own, since it is pure
// (no database handle), matching libs/go-shared/csaf and libs/go-shared/vex's
// own "no I/O" discipline.
type Input struct {
	Statement vex.Statement

	// TenantName publishes as Publisher.Name — CSAF's publisher is whoever
	// issues the advisory, which is the CUSTOMER'S organisation, not AxeBOM
	// (AxeBOM is the tool that generated the document, not its publisher).
	TenantName string

	// ClusterDisplayID is the vulnerability's best available identifier
	// (normalize.vuln_clusters.display_id — CVE if one exists, else the
	// highest-ranked alias). Never empty for a real cluster.
	ClusterDisplayID string
	// ClusterAliases are every OTHER identifier for the same cluster (GHSA,
	// OSV, ...) — carried as CSAF `ids`, since a consumer's own tooling may
	// key on a different namespace than the one AxeBOM chose as canonical.
	ClusterAliases []string

	// ComponentName/ComponentPURL describe the product this statement is
	// scoped to. Both empty for a project-scoped statement — see
	// vex.Statement's own doc comment on why ComponentKey is empty there.
	ComponentName string
	ComponentPURL string

	// TrackingID is minted by the caller (the store layer), not here — this
	// package has no way to guarantee uniqueness against
	// normalize.csaf_advisories' own UNIQUE(tenant_id, tracking_id)
	// constraint, and inventing one that later collides is the database's
	// problem to catch, not this package's to guess around.
	TrackingID string

	// Now is the clock this document is dated by (csaf.Now = time.Time) —
	// passed in, never read from time.Now() here, so a re-generation of an
	// identical decision produces a byte-identical document (ADR-0003).
	Now time.Time
}

// vexStatusToCSAF maps CERT-In's four spellings onto CSAF 2.0's — see
// libs/go-shared/csaf.ProductStatus's own doc comment: this is not cosmetic,
// emitting CERT-In's spelling produces a document a CSAF consumer's
// validator rejects.
func vexStatusToCSAF(s vex.Status) string {
	switch s {
	case vex.StatusNotAffected:
		return "known_not_affected"
	case vex.StatusAffected:
		return "known_affected"
	case vex.StatusFixed:
		return "fixed"
	case vex.StatusUnderInvestigation:
		return "under_investigation"
	default:
		return "under_investigation"
	}
}

const productID = "CSAFPID-1"

// Generate builds a CSAF 2.0 document for one VEX statement.
//
// ⚠ ALWAYS PRODUCES SOMETHING csaf.Document.Validate() ACCEPTS. A caller
// that generates and then validates and finds problems has found a real bug
// in this function, not a caller error — Validate exists precisely so that
// class of mistake is caught mechanically rather than by a human reviewing
// generated JSON.
func Generate(in Input) *csaf.Document {
	productName := in.ComponentName
	if productName == "" {
		// A project-scoped statement has no single component — the advisory
		// still needs a product tree entry to attach product_status to
		// (Validate requires every product_status id to exist in the tree).
		productName = "the assessed project"
	}

	ids := make([]csaf.VulnID, 0, len(in.ClusterAliases))
	for _, alias := range in.ClusterAliases {
		ids = append(ids, csaf.VulnID{SystemName: aliasSystemName(alias), Text: alias})
	}

	vuln := csaf.Vulnerability{
		CVE:   cveOrEmpty(in.ClusterDisplayID),
		IDs:   ids,
		Notes: []csaf.Note{{Category: "description", Text: statementSummary(in)}},
	}
	if vuln.CVE == "" && len(vuln.IDs) == 0 {
		// Validate requires a CVE or an id on every vulnerability entry — a
		// display id that is neither a CVE nor already in aliases (an
		// OSV-native or vendor id, per vuln_clusters' own "lowest-rank
		// member" ranking) still has to be carried somehow.
		vuln.IDs = append(vuln.IDs, csaf.VulnID{
			SystemName: aliasSystemName(in.ClusterDisplayID), Text: in.ClusterDisplayID,
		})
	}

	status := &csaf.ProductStatus{}
	switch vexStatusToCSAF(in.Statement.Status) {
	case "known_not_affected":
		status.KnownNotAffected = []string{productID}
		// ⚠ REQUIRED WHENEVER known_not_affected IS DECLARED — Validate
		// checks for exactly this (a Threat with category "impact"), and a
		// `not_affected` VEX statement is REFUSED without a justification
		// in the first place (vex.Validate), so in.Statement.Justification
		// is always populated by the time Generate ever sees one.
		vuln.Threats = []csaf.Threat{{
			Category: "impact", Details: in.Statement.Justification, ProductIDs: []string{productID},
		}}
	case "known_affected":
		status.KnownAffected = []string{productID}
	case "fixed":
		status.Fixed = []string{productID}
	default:
		status.UnderInvestigation = []string{productID}
	}
	vuln.ProductStatus = status

	if in.Statement.Remediation != "" {
		vuln.Remediations = []csaf.Remediation{{
			Category: remediationCategory(in.Statement.Status), Details: in.Statement.Remediation,
			ProductIDs: []string{productID},
		}}
	}

	now := in.Now.UTC().Format(time.RFC3339)
	helper := (*csaf.ProductIdentHelper)(nil)
	if in.ComponentPURL != "" {
		helper = &csaf.ProductIdentHelper{PURL: in.ComponentPURL}
	}

	return &csaf.Document{
		DocumentMeta: csaf.DocumentMeta{
			Category:    "csaf_vex",
			CSAFVersion: csaf.Version,
			Title:       fmt.Sprintf("VEX: %s in %s", in.ClusterDisplayID, productName),
			Publisher:   csaf.Publisher{Category: "vendor", Name: in.TenantName, Namespace: "urn:axebom:tenant"},
			Tracking: csaf.Tracking{
				ID: in.TrackingID, Status: "final", Version: "1",
				InitialReleaseDate: now, CurrentReleaseDate: now,
				RevisionHistory: []csaf.Revision{{Number: "1", Date: now, Summary: "Initial publication"}},
			},
		},
		ProductTree: &csaf.ProductTree{
			FullProductNames: []csaf.FullProductName{{ProductID: productID, Name: productName, Helper: helper}},
		},
		Vulns: []csaf.Vulnerability{vuln},
	}
}

func cveOrEmpty(displayID string) string {
	if strings.HasPrefix(strings.ToUpper(displayID), "CVE-") {
		return displayID
	}
	return ""
}

func aliasSystemName(id string) string {
	switch {
	case strings.HasPrefix(strings.ToUpper(id), "CVE-"):
		return "CVE"
	case strings.HasPrefix(strings.ToUpper(id), "GHSA-"):
		return "GHSA"
	case strings.HasPrefix(strings.ToUpper(id), "OSV-"):
		return "OSV"
	default:
		return "other"
	}
}

func remediationCategory(status vex.Status) string {
	if status == vex.StatusFixed {
		return "vendor_fix"
	}
	return "workaround"
}

func statementSummary(in Input) string {
	parts := []string{fmt.Sprintf("VEX status: %s.", in.Statement.Status)}
	if in.Statement.Justification != "" {
		parts = append(parts, "Justification: "+in.Statement.Justification+".")
	}
	if in.Statement.Workarounds != "" {
		parts = append(parts, "Workarounds: "+in.Statement.Workarounds+".")
	}
	if in.Statement.Downtime != "" {
		parts = append(parts, "Downtime: "+in.Statement.Downtime+".")
	}
	return strings.Join(parts, " ")
}
