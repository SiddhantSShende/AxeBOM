package model

import "fmt"

// BOMType is one of the five bill-of-materials types AxeBOM produces.
//
// This lives in libs/go-shared because it crosses every boundary in the
// system: project classifies into them, scan fans out by them, report renders
// them, and the NATS subject `scan.job.<family>` is derived from them. A copy
// in each service would drift, and the drift would show up as a scan that
// silently produces nothing.
//
// The values match the CHECK constraint on project.project_classifications
// (docs/01-DATA-MODEL.md §2). Uppercase because CERT-In writes them that way
// and the reports quote them.
type BOMType string

const (
	// BOMTypeSBOM is the software bill of materials.
	BOMTypeSBOM BOMType = "SBOM"
	// BOMTypeCBOM is the cryptographic bill of materials (CERT-In Table 9).
	BOMTypeCBOM BOMType = "CBOM"
	// BOMTypeQBOM is the quantum bill of materials (CERT-In Table 8).
	//
	// HONEST LABEL: largely a DERIVATION. Crypto assets come from CBOM
	// discovery with quantum-vulnerability rules applied; only Table 8's
	// device metadata is separately captured. There is no quantum-hardware
	// scanner, and the UI must not imply one.
	BOMTypeQBOM BOMType = "QBOM"
	// BOMTypeAIBOM is the AI/ML bill of materials (CERT-In Table 10).
	BOMTypeAIBOM BOMType = "AIBOM"
	// BOMTypeHBOM is the hardware bill of materials (CERT-In Table 11).
	//
	// HONEST LABEL: there is no open-source HBOM scanner. This is a structured
	// CSV/form import plus a data model. Never imply discovery.
	BOMTypeHBOM BOMType = "HBOM"
)

// AllBOMTypes returns every type, in the order CERT-In presents them.
//
// Returns a fresh slice each call: a package-level slice would let one caller's
// sort or append corrupt every other caller's view.
func AllBOMTypes() []BOMType {
	return []BOMType{BOMTypeSBOM, BOMTypeCBOM, BOMTypeQBOM, BOMTypeAIBOM, BOMTypeHBOM}
}

// ParseBOMType validates a string.
//
// Exact match, no case folding: the database CHECK constraint is exact, so
// accepting "sbom" here would produce a clean-looking API that fails at INSERT
// with a constraint violation nobody can act on.
func ParseBOMType(s string) (BOMType, error) {
	for _, t := range AllBOMTypes() {
		if BOMType(s) == t {
			return t, nil
		}
	}
	return "", fmt.Errorf("unknown BOM type %q (want one of %v)", s, AllBOMTypes())
}

// Valid reports whether t is a known BOM type.
func (t BOMType) Valid() bool {
	_, err := ParseBOMType(string(t))
	return err == nil
}

func (t BOMType) String() string { return string(t) }

// RequiresImport reports whether this BOM type can ONLY be populated by user
// import, because no engine in its family reads a source.
//
// ⚠ THIS RETURNED TRUE FOR HBOM LONG AFTER HBOM BECAME SCANNABLE, AND THE
// FRONTEND RENDERED THAT AS AN "import only" CHIP ON THE REGISTRATION SCREEN.
//
// `hbom-ecad` parses committed KiCad, Altium and OrCAD design files from a
// repository or an upload — a real scan producing real jobs on scan.job.hbom.
// A user choosing classifications was being told, at the point of the decision,
// that a working path did not exist.
//
// It is now empty, and that is the honest answer: no BOM type is import-only.
// The method stays because `GET /v1/projects/options` publishes it and because
// a future type could genuinely be import-only — deleting it would move the
// question into the UI, where invariant 2 says facts like this must not live.
//
// ⚠ THE REAL FIX IS THE AGREEMENT TEST, NOT THIS LINE. Whether a family can be
// scanned is decided by the engine registry
// (services/scan-orchestrator/internal/policy), and depguard rightly forbids
// this package from importing a service. So the registry's own test asserts
// that these two answers match — see TestBOMTypeFactsAgreeWithTheEngineRegistry.
// Without it this is just a second place to forget.
func (t BOMType) RequiresImport() bool { return importOnlyTypes[t] }

// importOnlyTypes is empty on purpose. See RequiresImport.
var importOnlyTypes = map[BOMType]bool{}

// IsDerived reports whether this BOM type is derived from another's findings
// rather than discovered independently.
//
// Only QBOM, which derives from CBOM crypto assets. A project classified QBOM
// without CBOM will produce device metadata and no crypto assets — worth
// warning about at registration rather than at report time.
func (t BOMType) IsDerived() bool { return t == BOMTypeQBOM }

// SDLCStageValid reports whether s is one of the CERT-In §3.2 stages.
//
// Reads SDLCClassifications, which is GENERATED from the compliance profile.
// Do not inline the six values: if CERT-In revises them, the profile changes
// and this follows, whereas a hardcoded list silently disagrees.
func SDLCStageValid(s string) bool {
	for _, v := range SDLCClassifications {
		if v == s {
			return true
		}
	}
	return false
}

// BOMDepthValid reports whether s is one of the CERT-In §3.1 depth levels.
// Generated from the profile, same reasoning as SDLCStageValid.
func BOMDepthValid(s string) bool {
	for _, v := range BOMLevels {
		if v == s {
			return true
		}
	}
	return false
}
