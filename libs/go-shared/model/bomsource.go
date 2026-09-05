package model

import "sort"

// RegistrationSources reports the project source types a BOM type can actually
// be registered from.
//
// ⚠ REGISTRATION WAS ONE FLAT SET FOR ALL FIVE TYPES, AND THE DATABASE SHOWS
// WHAT THAT COSTS. `sourceTypes` in the project service accepted github,
// gitlab, bitbucket, upload, image, manual and url for every classification, so
// an AIBOM project could be — and in the dev database WAS — registered against
// a `url` source that no AIBOM engine can read. Nothing refused it, nothing
// warned, and the project produces an empty AIBOM forever. That is precisely
// the "silent no-op the user only discovers when a report comes back empty"
// that parseClassifications' own comment warns about; it guarded the empty
// classification set and not the incompatible source.
//
// ⚠ THIS IS A TRANSCRIPTION, AND IT IS ONLY SAFE BECAUSE OF THE AGREEMENT TEST.
// Which sources a family can read is decided by the engine registry in
// services/scan-orchestrator/internal/policy, and depguard rightly forbids this
// package from importing a service (ADR-0001). So the fact is stated here, and
// the registry's own test — which is allowed to see both sides — asserts the
// two still agree. Exactly the arrangement RequiresImport describes, and for
// the same reason: without the test this is just a second place to forget.
//
// Returns a sorted copy: callers render it and must not be able to mutate the
// table underneath another caller.
func RegistrationSources(t BOMType) []string {
	kinds := registrationSources[t]
	if len(kinds) == 0 {
		return nil
	}
	out := make([]string, len(kinds))
	copy(out, kinds)
	sort.Strings(out)
	return out
}

// SupportsRegistrationSource reports whether one source type is valid for a
// BOM type. An unknown BOM type supports nothing, rather than everything — a
// type this table has not been taught about must fail closed.
func SupportsRegistrationSource(t BOMType, sourceType string) bool {
	for _, s := range registrationSources[t] {
		if s == sourceType {
			return true
		}
	}
	return false
}

// ⚠ `manual` IS NOT AN ENGINE SOURCE KIND, AND THE AGREEMENT TEST KNOWS THAT.
// The registry describes what an engine can READ. `manual` is the path where
// the customer supplies the BOM themselves and no engine runs at all, so it can
// never appear in the registry and is held to a different rule: it is offered
// only where a manual registration actually produces a document.
//
//   - HBOM — a device, its parts tree, and a CSV/XLSX import all produce a real
//     hardware document with no repository. CLAUDE.md's honest labels describe
//     this as a first-class path, not a fallback.
//   - QBOM — Table 8's device metadata form produces the document; the
//     readiness half is derived from the project's CBOM.
//
// SBOM, CBOM and AIBOM have no hand-entry path: there is no form that produces
// a component inventory, so a `manual` project of those types would register
// cleanly and produce nothing. That is the same silent no-op this table exists
// to prevent, so it is refused rather than offered.
//
// `git` is not listed either — it is an engine source KIND, and a project's
// source_type names the provider (github, gitlab, bitbucket). The agreement
// test performs that mapping rather than either side guessing it.
var registrationSources = map[BOMType][]string{
	BOMTypeSBOM:  {"github", "gitlab", "bitbucket", "upload", "image", "url"},
	BOMTypeCBOM:  {"github", "gitlab", "bitbucket", "upload", "image"},
	BOMTypeQBOM:  {"github", "gitlab", "bitbucket", "upload", "image", "manual"},
	BOMTypeAIBOM: {"github", "gitlab", "bitbucket", "upload"},
	BOMTypeHBOM:  {"github", "gitlab", "bitbucket", "upload", "manual"},
}

// GitProviders are the source types that mean "a git repository", and so map
// onto the registry's single `git` source kind.
//
// Exported because the agreement test needs the same mapping the project
// service uses; two copies of it would be the drift this file exists to stop.
func GitProviders() []string { return []string{"github", "gitlab", "bitbucket"} }

// ManualSource is the registration path where no engine runs.
const ManualSource = "manual"
