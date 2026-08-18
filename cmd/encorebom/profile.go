package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/encorebom/encorebom/libs/go-shared/compliance"
)

const defaultProfilePath = "docs/reference/certin-v2.0.yaml"

func runProfile(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: encorebom profile <lint|gen|show|guardrails|evidence> [flags]")
	}
	switch args[0] {
	case "lint":
		return profileLint(args[1:])
	case "gen":
		return profileGen(args[1:])
	case "show":
		return profileShow(args[1:])
	case "guardrails":
		return profileGuardrails(args[1:])
	case "evidence":
		return runEvidence(args[1:])
	default:
		return fmt.Errorf("unknown profile subcommand %q", args[0])
	}
}

func profileLint(args []string) error {
	fs := flag.NewFlagSet("profile lint", flag.ExitOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}

	path := defaultProfilePath
	if fs.NArg() > 0 {
		path = fs.Arg(0)
	}
	path = resolveFromRepoRoot(path)

	p, err := compliance.Load(path)
	if err != nil {
		return err
	}
	res := compliance.Lint(p)

	fmt.Printf("profile %s revision %d (%s)\n", p.Meta.ID, p.Meta.Revision, filepath.Base(path))
	fmt.Printf("  fields:          %d\n", res.FieldCount)
	fmt.Printf("  count assertions:%d matched\n", res.CountsOK)
	fmt.Printf("  assumed entries: %d\n", res.AssumedCount)

	if res.AssumedCount > 0 {
		// Visible, not silent. An unverified assumption that is visible is a
		// manageable risk; one that is invisible is how a compliance product lies.
		fmt.Printf("\n  NOTE: %d entries are `assumed` rather than verified against the\n"+
			"        source document. Every generated report must say so.\n", res.AssumedCount)
	}

	if !res.OK() {
		fmt.Fprintf(os.Stderr, "\n%d problem(s):\n", len(res.Problems))
		for _, pr := range res.Problems {
			fmt.Fprintf(os.Stderr, "  %s\n", pr)
		}
		fmt.Fprintf(os.Stderr, "\nCount mismatches are transcription assertions against the source PDF.\n"+
			"A mismatch means the guideline was revised or the transcription is wrong.\n"+
			"Both need a human decision — do not 'fix' the expected value to match.\n")
		return fmt.Errorf("profile lint failed with %d problem(s)", len(res.Problems))
	}

	fmt.Println("\nprofile lint: OK")
	return nil
}

func profileGen(args []string) error {
	fs := flag.NewFlagSet("profile gen", flag.ExitOnError)
	outGo := fs.String("out-go", "libs/go-shared/model", "Go output directory")
	outPy := fs.String("out-py", "libs/py-shared/encorebom_shared/model", "Python output directory")
	profilePath := fs.String("profile", defaultProfilePath, "profile YAML")
	if err := fs.Parse(args); err != nil {
		return err
	}

	p, err := compliance.Load(resolveFromRepoRoot(*profilePath))
	if err != nil {
		return err
	}

	// Refuse to generate from a profile that does not lint. Generating from a
	// broken profile propagates the break into two languages and a runtime
	// coverage calculation.
	if res := compliance.Lint(p); !res.OK() {
		for _, pr := range res.Problems {
			fmt.Fprintf(os.Stderr, "  %s\n", pr)
		}
		return fmt.Errorf("refusing to generate from a profile with %d lint problem(s)", len(res.Problems))
	}

	goPath, err := compliance.GenerateGo(p, resolveFromRepoRoot(*outGo))
	if err != nil {
		return fmt.Errorf("generate Go: %w", err)
	}
	pyPath, err := compliance.GeneratePython(p, resolveFromRepoRoot(*outPy))
	if err != nil {
		return fmt.Errorf("generate Python: %w", err)
	}

	fmt.Printf("generated from %s (revision %d)\n", p.Meta.ID, p.Meta.Revision)
	fmt.Printf("  %s\n", goPath)
	fmt.Printf("  %s\n", pyPath)
	fmt.Printf("\n%d fields across %d BOM types and %d crypto asset types.\n",
		len(p.AllFields()), 4, len(p.CryptoAsset.Types))
	return nil
}

// profileShow prints what the profile requires, so a developer can answer
// "which fields does an AIBOM need" without opening the YAML or, worse,
// guessing.
func profileShow(args []string) error {
	fs := flag.NewFlagSet("profile show", flag.ExitOnError)
	bomType := fs.String("bom-type", "", "SBOM | QBOM | AIBOM | HBOM")
	assetType := fs.String("crypto-asset-type", "", "algorithm | key | protocol | certificate")
	if err := fs.Parse(args); err != nil {
		return err
	}

	p, err := compliance.Load(resolveFromRepoRoot(defaultProfilePath))
	if err != nil {
		return err
	}

	switch {
	case *assetType != "":
		fields := p.FieldsForCryptoAssetType(*assetType)
		if len(fields) == 0 {
			return fmt.Errorf("unknown crypto asset type %q", *assetType)
		}
		fmt.Printf("crypto asset type %q — %d scored fields\n\n", *assetType, len(fields))
		for _, f := range fields {
			fmt.Printf("  w%d  %-34s %-42s p.%d\n", f.Weight, f.Name, f.CanonicalPath, f.SourcePage)
		}
	case *bomType != "":
		fields := p.FieldsForBOMType(*bomType)
		if len(fields) == 0 {
			return fmt.Errorf("unknown BOM type %q", *bomType)
		}
		fmt.Printf("%s — %d scored fields\n\n", *bomType, len(fields))
		for _, f := range fields {
			fmt.Printf("  w%d  %-34s %-42s p.%d\n", f.Weight, f.Name, f.CanonicalPath, f.SourcePage)
		}
	default:
		counts := p.ActualCounts()
		fmt.Printf("%s revision %d — %s\n\n", p.Meta.ID, p.Meta.Revision, p.Meta.Name)
		for _, k := range compliance.SortedKeys(counts) {
			fmt.Printf("  %-46s %d\n", k, counts[k])
		}
	}
	return nil
}

// resolveFromRepoRoot makes paths work from any subdirectory.
func resolveFromRepoRoot(p string) string {
	if filepath.IsAbs(p) {
		return p
	}
	root, err := findRepoRoot()
	if err != nil {
		return p
	}
	return filepath.Join(root, p)
}

// ─── guardrails ─────────────────────────────────────────────────────────────

// auditRoots are the trees whose output a customer reads.
//
// ⚠ NOT THE WHOLE REPOSITORY, AND THAT IS A DELIBERATE NARROWING. Every
// explanatory comment in this codebase discusses the numbers and the word these
// rules forbid — including the rules themselves. A check that flags its own
// documentation is a check somebody disables, and a disabled check is worse
// than none because its absence is invisible.
var auditRoots = []string{
	"services",
	"workers",
	"libs/go-shared/model",
	"libs/py-shared/encorebom_shared",
	"frontend/src",
}

// profileGuardrails runs the Phase 16 §16.1 audit.
//
// The phase file asks for these to be grepped by hand. A hand-grep happens once,
// performed by the person who already knows the rule — which is the person least
// likely to have broken it. This runs in CI instead.
func profileGuardrails(args []string) error {
	fs := flag.NewFlagSet("profile guardrails", flag.ExitOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}

	path := resolveFromRepoRoot(defaultProfilePath)
	p, err := compliance.Load(path)
	if err != nil {
		return err
	}

	root := filepath.Dir(filepath.Dir(filepath.Dir(path)))
	report, err := compliance.AuditGeneratedOutput(p, root, auditRoots)
	if err != nil {
		return err
	}

	fmt.Printf("guardrail audit — %d files across %d trees\n", report.Scanned, len(auditRoots))
	for _, bomType := range compliance.SortedKeys(report.CountsChecked) {
		fmt.Printf("  %-6s element count %d must never be written as a literal\n",
			bomType, report.CountsChecked[bomType])
	}
	fmt.Println()

	if report.OK() {
		fmt.Println("  no hardcoded field count")
		fmt.Println("  no assertion of compliance in customer-facing output")
		fmt.Println("\nguardrails: OK")
		return nil
	}

	for _, f := range report.Findings {
		fmt.Printf("  %s\n\n", f)
	}
	return fmt.Errorf("guardrails: %d violation(s)", len(report.Findings))
}
