package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/encorebom/encorebom/libs/go-shared/compliance"
)

// ⚠ THIS MAP IS A CLAIM ABOUT THE PRODUCT, AND IT IS THE PART OF THE EVIDENCE
// PACK MOST LIKELY TO BECOME A LIE.
//
// Everything else in the pack is generated from the profile and cannot drift.
// This is hand-maintained: it says how EncoreBOM obtains each element, and
// nothing forces it to stay true when a worker changes. So two things guard it:
//
//   - the DEFAULT IS `not-implemented`. An element absent from this map
//     understates the product rather than overstating it, which is the correct
//     direction for a mistake in a compliance document to point.
//   - `TestEveryProfileElementIsClassified` fails when the profile gains an
//     element this map does not mention, so a CERT-In revision cannot silently
//     be reported as already covered.
//
// `user-supplied` is not a gap in the product. Intended usage, out-of-scope
// usage, warranty terms and criticality are judgements about somebody's own
// system; a tool that guessed them would invent facts and report a HIGHER
// coverage number for having done so.
var elementCoverage = map[string]compliance.Coverage{
	// ── SBOM ─────────────────────────────────────────────────────────────
	// Syft, Trivy, Grype, OSV-Scanner and Dependency-Check populate these
	// from lockfiles and manifests. No package-manager resolution is run —
	// lockfile parsing only, because resolution executes user code.
	"certin.sbom.01.component_name":         compliance.CoverageAutomated,
	"certin.sbom.02.component_version":      compliance.CoverageAutomated,
	"certin.sbom.03.component_description":  compliance.CoverageAutomated,
	"certin.sbom.04.component_supplier":     compliance.CoverageAutomated,
	"certin.sbom.05.component_license":      compliance.CoverageAutomated,
	"certin.sbom.06.component_origin":       compliance.CoverageAutomated,
	"certin.sbom.07.component_dependencies": compliance.CoverageAutomated,
	"certin.sbom.08.vulnerabilities":        compliance.CoverageAutomated,
	// Computed from the finding's fix version against the installed one.
	"certin.sbom.09.patch_status": compliance.CoverageDerived,
	"certin.sbom.10.release_date": compliance.CoverageAutomated,
	"certin.sbom.11.eol_date":     compliance.CoverageAutomated,
	// ⚠ CRITICALITY IS THE CUSTOMER'S JUDGEMENT ABOUT THEIR OWN SYSTEM. A
	// component that is critical in a payment gateway is incidental in a
	// build tool, and no scanner can know which this is.
	"certin.sbom.12.criticality":         compliance.CoverageUserSupplied,
	"certin.sbom.13.usage_restrictions":  compliance.CoverageUserSupplied,
	"certin.sbom.14.checksums":           compliance.CoverageAutomated,
	"certin.sbom.15.comments":            compliance.CoverageUserSupplied,
	"certin.sbom.16.author_of_sbom_data": compliance.CoverageDerived,
	"certin.sbom.17.timestamp":           compliance.CoverageDerived,
	"certin.sbom.18.executable_property": compliance.CoverageAutomated,
	"certin.sbom.19.archive_property":    compliance.CoverageAutomated,
	"certin.sbom.20.structured_property": compliance.CoverageAutomated,
	// ⚠ DERIVED, AND DISTINCT FROM component.purl. The CERT-In identifier is
	// rendered from supplier and name; the ecosystem PURL is the merge key.
	// Conflating them breaks dedup and produces a wrong report.
	"certin.sbom.21.unique_identifier": compliance.CoverageDerived,

	// ── CBOM — cbomkit-theia discovers crypto assets ─────────────────────
	// Type-discriminated: each asset type is scored against its own field
	// set, because a certificate has no key size.
	"certin.crypto.algo.name":             compliance.CoverageAutomated,
	"certin.crypto.algo.asset_type":       compliance.CoverageAutomated,
	"certin.crypto.algo.primitive":        compliance.CoverageDerived,
	"certin.crypto.algo.mode":             compliance.CoverageAutomated,
	"certin.crypto.algo.crypto_functions": compliance.CoverageDerived,
	// Classical security level is computed from the primitive and key size
	// by our own rules, not read from any tool's output.
	"certin.crypto.algo.security_level": compliance.CoverageDerived,
	"certin.crypto.algo.oid":            compliance.CoverageAutomated,
	"certin.crypto.algo.list":           compliance.CoverageAutomated,

	"certin.crypto.key.name":            compliance.CoverageAutomated,
	"certin.crypto.key.asset_type":      compliance.CoverageAutomated,
	"certin.crypto.key.id":              compliance.CoverageAutomated,
	"certin.crypto.key.state":           compliance.CoverageNotImplemented,
	"certin.crypto.key.size":            compliance.CoverageAutomated,
	"certin.crypto.key.creation_date":   compliance.CoverageNotImplemented,
	"certin.crypto.key.activation_date": compliance.CoverageNotImplemented,

	"certin.crypto.proto.name":          compliance.CoverageAutomated,
	"certin.crypto.proto.asset_type":    compliance.CoverageAutomated,
	"certin.crypto.proto.version":       compliance.CoverageAutomated,
	"certin.crypto.proto.cipher_suites": compliance.CoverageAutomated,
	"certin.crypto.proto.oid":           compliance.CoverageAutomated,

	"certin.crypto.cert.name":             compliance.CoverageAutomated,
	"certin.crypto.cert.asset_type":       compliance.CoverageAutomated,
	"certin.crypto.cert.subject_name":     compliance.CoverageAutomated,
	"certin.crypto.cert.issuer_name":      compliance.CoverageAutomated,
	"certin.crypto.cert.not_valid_before": compliance.CoverageAutomated,
	"certin.crypto.cert.not_valid_after":  compliance.CoverageAutomated,
	"certin.crypto.cert.sig_algo_ref":     compliance.CoverageAutomated,
	"certin.crypto.cert.subject_pk_ref":   compliance.CoverageAutomated,
	"certin.crypto.cert.format":           compliance.CoverageAutomated,
	"certin.crypto.cert.extension":        compliance.CoverageAutomated,

	// ── QBOM ─────────────────────────────────────────────────────────────
	// ⚠ QBOM IS LARGELY A DERIVATION, AND THE PACK MUST SAY SO. Crypto
	// assets come from CBOM discovery with quantum-vulnerability rules
	// applied; there is no quantum-hardware scanner. Only Table 8's DEVICE
	// metadata is separately captured, and that is a form.
	"certin.qbom.01.model_name":             compliance.CoverageUserSupplied,
	"certin.qbom.02.version":                compliance.CoverageUserSupplied,
	"certin.qbom.03.vendor_origin":          compliance.CoverageUserSupplied,
	"certin.qbom.04.license_information":    compliance.CoverageUserSupplied,
	"certin.qbom.05.cryptographic_asset":    compliance.CoverageDerived,
	"certin.qbom.06.communication_protocol": compliance.CoverageUserSupplied,
	"certin.qbom.07.hardware":               compliance.CoverageUserSupplied,
	"certin.qbom.08.software_dependencies":  compliance.CoverageDerived,
	"certin.qbom.09.environmental_impact":   compliance.CoverageUserSupplied,
	"certin.qbom.10.vulnerabilities":        compliance.CoverageDerived,
	"certin.qbom.11.attestations":           compliance.CoverageUserSupplied,

	// ── AIBOM ────────────────────────────────────────────────────────────
	// ai-bom and aibom-generator discover models and datasets from code and
	// from model cards.
	"certin.aibom.01.model_name":            compliance.CoverageAutomated,
	"certin.aibom.02.model_version":         compliance.CoverageAutomated,
	"certin.aibom.03.model_type":            compliance.CoverageAutomated,
	"certin.aibom.04.model_developer":       compliance.CoverageAutomated,
	"certin.aibom.05.licensing":             compliance.CoverageAutomated,
	"certin.aibom.06.software_dependencies": compliance.CoverageAutomated,
	"certin.aibom.07.ml_models_algorithms":  compliance.CoverageAutomated,
	"certin.aibom.08.performance_metrics":   compliance.CoverageAutomated,
	"certin.aibom.09.data_source":           compliance.CoverageAutomated,
	"certin.aibom.10.data_sets":             compliance.CoverageAutomated,
	"certin.aibom.11.hardware":              compliance.CoverageAutomated,
	// ⚠ THE FIVE NO TOOL POPULATES. They will mostly be `not-provided`, and
	// that is the correct outcome — a coverage number honestly reporting 40%
	// for an AIBOM says something true about the state of AI supply-chain
	// metadata. A plausible default would be read as a fact about the model.
	"certin.aibom.12.security_requirements": compliance.CoverageUserSupplied,
	"certin.aibom.13.input":                 compliance.CoverageAutomated,
	"certin.aibom.14.output":                compliance.CoverageAutomated,
	"certin.aibom.15.intended_usage":        compliance.CoverageUserSupplied,
	"certin.aibom.16.out_of_scope_usage":    compliance.CoverageUserSupplied,
	"certin.aibom.17.environmental_impact":  compliance.CoverageUserSupplied,
	"certin.aibom.18.vulnerabilities":       compliance.CoverageAutomated,
	"certin.aibom.19.attestations":          compliance.CoverageUserSupplied,

	// ── HBOM ─────────────────────────────────────────────────────────────
	// ⚠ EVERY ONE OF THESE IS `imported`, NOT `automated`. No open-source
	// tool inspects a device and enumerates its parts. Labelling any of them
	// automated is the claim the HBOM phase exists to avoid.
	"certin.hbom.01.product_name":                   compliance.CoverageImported,
	"certin.hbom.02.product_version":                compliance.CoverageImported,
	"certin.hbom.03.product_details":                compliance.CoverageImported,
	"certin.hbom.04.warranty_amc":                   compliance.CoverageUserSupplied,
	"certin.hbom.05.manufacturer_name":              compliance.CoverageImported,
	"certin.hbom.06.manufacturer_location":          compliance.CoverageImported,
	"certin.hbom.07.manufacturing_date":             compliance.CoverageImported,
	"certin.hbom.08.supplier_information":           compliance.CoverageImported,
	"certin.hbom.09.supplier_location":              compliance.CoverageImported,
	"certin.hbom.10.model_number":                   compliance.CoverageImported,
	"certin.hbom.11.serial_number":                  compliance.CoverageImported,
	"certin.hbom.12.technical_specification":        compliance.CoverageImported,
	"certin.hbom.13.component_supplier_information": compliance.CoverageImported,
	"certin.hbom.14.component_supplier_location":    compliance.CoverageImported,
	"certin.hbom.15.technology_node":                compliance.CoverageImported,
	"certin.hbom.16.compliance":                     compliance.CoverageImported,
	"certin.hbom.17.power_supply":                   compliance.CoverageImported,
	// The four a parts list never contains — judgements about the hardware.
	"certin.hbom.18.license_information": compliance.CoverageUserSupplied,
	"certin.hbom.19.test_result":         compliance.CoverageUserSupplied,
	"certin.hbom.20.sub_component":       compliance.CoverageImported,
	"certin.hbom.21.firmware_version":    compliance.CoverageImported,
	"certin.hbom.22.origin":              compliance.CoverageImported,
	"certin.hbom.23.criticality":         compliance.CoverageUserSupplied,
	// ⚠ MATCHED, NOT IMPORTED — and not yet wired. See STATE.md.
	"certin.hbom.24.vulnerabilities": compliance.CoverageNotImplemented,
}

// evidencePackPath is where the generated pack lands.
const evidencePackPath = "docs/COMPLIANCE-REPORT.md"

// runEvidence generates the coverage evidence pack (Phase 16 §16.1).
func runEvidence(args []string) error {
	fs := flag.NewFlagSet("profile evidence", flag.ExitOnError)
	out := fs.String("o", evidencePackPath, "where to write the pack")
	check := fs.Bool("check", false,
		"fail if the committed pack is stale rather than rewriting it")
	if err := fs.Parse(args); err != nil {
		return err
	}

	path := resolveFromRepoRoot(defaultProfilePath)
	p, err := compliance.Load(path)
	if err != nil {
		return err
	}

	pack := compliance.BuildEvidencePack(p, elementCoverage)
	rendered := pack.Markdown()

	target := resolveFromRepoRoot(*out)

	if *check {
		// ⚠ A STALE PACK IS WORSE THAN AN ABSENT ONE. It is a document with a
		// generation date on it that no longer describes the product, handed to
		// an auditor in good faith. CI regenerates and diffs.
		existing, readErr := os.ReadFile(target) //nolint:gosec // our own docs tree
		if readErr != nil {
			return fmt.Errorf("the evidence pack is missing: %w", readErr)
		}
		if normalize(string(existing)) != normalize(rendered) {
			return fmt.Errorf(
				"%s is stale. Regenerate it with `encorebom profile evidence` and "+
					"commit the result — a pack that no longer describes the product is "+
					"worse than none, because somebody hands it to an auditor believing it",
				filepath.Base(target))
		}
		fmt.Printf("evidence pack is current (%d sections)\n", len(pack.Sections))
		return nil
	}

	if err := os.WriteFile(target, []byte(rendered), 0o600); err != nil {
		return err
	}

	fmt.Printf("wrote %s\n", target)
	for _, section := range pack.Sections {
		counts := section.ByCoverage()
		fmt.Printf("  %-20s %2d elements", section.BOMType, section.ElementCount())
		if n := counts[compliance.CoverageNotImplemented]; n > 0 {
			fmt.Printf("  (%d not implemented)", n)
		}
		if n := counts[compliance.CoverageUserSupplied]; n > 0 {
			fmt.Printf("  (%d user-supplied)", n)
		}
		fmt.Println()
	}
	if len(pack.AssumedFields) > 0 {
		fmt.Printf("\n  ⚠ %d element(s) are `assumed` rather than verified against the PDF\n",
			len(pack.AssumedFields))
	}
	return nil
}

// normalize makes the comparison insensitive to line endings.
//
// Without it this check fails on Windows for everybody, every time, which is how
// a check gets removed rather than fixed.
func normalize(s string) string {
	return strings.ReplaceAll(strings.TrimSpace(s), "\r\n", "\n")
}
