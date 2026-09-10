package compliance

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// Lint implements the seven checks in docs/06-COMPLIANCE-PROFILES.md §8.
//
// The counts in `expected_counts` are TRANSCRIPTION ASSERTIONS against the
// source PDF, not application logic. A mismatch means either the guideline was
// revised or the transcription is wrong — both need a human decision, never a
// silent fix. So this reports and fails; it never repairs.

// Problem is one lint failure.
type Problem struct {
	Check   string
	Detail  string
	FieldID string
}

func (p Problem) String() string {
	if p.FieldID != "" {
		return fmt.Sprintf("[%s] %s (%s)", p.Check, p.Detail, p.FieldID)
	}
	return fmt.Sprintf("[%s] %s", p.Check, p.Detail)
}

// LintResult summarizes a run.
type LintResult struct {
	Problems     []Problem
	FieldCount   int
	AssumedCount int
	CountsOK     int
}

func (r LintResult) OK() bool { return len(r.Problems) == 0 }

var (
	fieldIDPattern = regexp.MustCompile(`^(certin|axebom)\.[a-z0-9_.]+$`)
	// Segments may nest and any segment may be a collection, e.g.
	// component.provenance[].author — the author of a component's SBOM data
	// lives on each provenance record, not on the component.
	canonicalPathPattern = regexp.MustCompile(`^[a-z_]+(\[\])?(\.[a-z0-9_]+(\[\])?)+$`)
)

// knownEntities are the canonical-model roots a canonical_path may address.
// Kept in sync with docs/01-DATA-MODEL.md; an unknown prefix usually means a
// typo or a field that was never modelled.
var knownEntities = map[string]bool{
	"component":         true,
	"bom_document":      true,
	"crypto_asset":      true,
	"quantum_component": true,
	"ai_model":          true,
	// `normalize.ai_assets` — prompts, vector stores, RAG pipelines, agents,
	// tools, MCP servers, inference endpoints and datasets. Added with the
	// second discovery engine, which is the first thing that could report any
	// of them; no CERT-In table has an element for one.
	"ai_assets":          true,
	"hardware_component": true,
	"vex_statement":      true,
	"csaf_advisory":      true,
	"project":            true,
	"scan":               true,
	"report":             true,
}

// Lint runs every check and returns all problems, not just the first.
func Lint(p *Profile) LintResult {
	var res LintResult
	add := func(check, detail, fieldID string) {
		res.Problems = append(res.Problems, Problem{Check: check, Detail: detail, FieldID: fieldID})
	}

	// --- 2. expected_counts match reality -----------------------------------
	actual := p.ActualCounts()
	expectedKeys := make([]string, 0, len(p.ExpectedCounts))
	for k := range p.ExpectedCounts {
		expectedKeys = append(expectedKeys, k)
	}
	sort.Strings(expectedKeys)

	for _, k := range expectedKeys {
		want := p.ExpectedCounts[k]
		got, ok := actual[k]
		switch {
		case !ok:
			add("counts", fmt.Sprintf("%s is declared but cannot be computed", k), "")
		case got != want:
			add("counts", fmt.Sprintf("%s: declared %d, profile contains %d", k, want, got), "")
		default:
			res.CountsOK++
		}
	}

	fields := p.AllFields()
	res.FieldCount = len(fields)

	// --- 3. field ids are globally unique -----------------------------------
	seen := map[string]int{}
	for _, f := range fields {
		seen[f.ID]++
	}
	dupes := make([]string, 0)
	for id, n := range seen {
		if n > 1 {
			dupes = append(dupes, fmt.Sprintf("%s (%d times)", id, n))
		}
	}
	sort.Strings(dupes)
	for _, d := range dupes {
		add("unique-ids", "duplicate field id: "+d, "")
	}

	for _, f := range fields {
		// --- 6. status present; `assumed` requires a note --------------------
		switch f.Status {
		case "verified":
			// Transcribed from the named page of the source document.
		case "assumed":
			res.AssumedCount++
			if strings.TrimSpace(f.Note) == "" {
				add("status", "status is `assumed` but no note explains the inference", f.ID)
			}
		case "extension":
			// An AxeBOM field, not a requirement of the standard. It has no
			// source page to verify against.
			if !strings.HasPrefix(f.ID, "axebom.") {
				add("status", "status `extension` is only valid for axebom.* ids", f.ID)
			}
			// ⚠ THE `scored: false` RULE INVERTS FOR AN OPERATIONAL PROFILE,
			// AND ONLY THERE.
			//
			// In a COMPLIANCE profile an extension is our own analysis riding
			// alongside the standard's fields, and scoring it would move a
			// number a regulator reads — so `scored: false` is mandatory.
			//
			// An operational profile is nothing BUT our own fields, with its
			// own separately-labelled number that is never published as
			// compliance. There, scoring them is the entire point rather than
			// the danger.
			if p.Meta.IsCompliance() && f.IsScored() {
				add("status", "an extension must set `scored: false`; scoring our own "+
					"analysis would inflate or deflate a compliance percentage", f.ID)
			}
		case "":
			add("status", "missing `status` (verified | assumed | extension)", f.ID)
		default:
			add("status", "unknown status "+f.Status, f.ID)
		}

		// --- 6b. an operational profile cites no document ---------------------
		//
		// A source_page is a promise that an auditor can open that page and
		// check. An AxeBOM-defined field set has no such document, so a page
		// number here would imply an authority behind it that does not exist.
		if !p.Meta.IsCompliance() && f.SourcePage != 0 {
			add("source-page", "an operational profile has no source document; a "+
				"source_page here implies a citation nobody can check", f.ID)
		}

		// --- 7. source_page within the document ------------------------------
		if f.SourcePage < 0 || (p.Meta.SourcePages > 0 && f.SourcePage > p.Meta.SourcePages) {
			add("source-page",
				fmt.Sprintf("source_page %d is outside the %d-page source document",
					f.SourcePage, p.Meta.SourcePages), f.ID)
		}

		// --- id shape --------------------------------------------------------
		if !fieldIDPattern.MatchString(f.ID) {
			add("id-shape", "id must match (certin|axebom).<dotted-lowercase>", f.ID)
		}

		// --- 5. canonical_path is well-formed and addresses a known entity ---
		//
		// Full resolution against the generated Go structs would be circular:
		// the structs are generated FROM this file. Validating the shape and
		// the entity prefix catches the realistic failure — a typo or a field
		// that was never modelled.
		if f.CanonicalPath != "" {
			if !canonicalPathPattern.MatchString(f.CanonicalPath) {
				add("canonical-path",
					"malformed canonical_path "+f.CanonicalPath+" (want entity.field or entity.field[])", f.ID)
			} else {
				entity := strings.SplitN(f.CanonicalPath, ".", 2)[0]
				if !knownEntities[entity] {
					add("canonical-path",
						fmt.Sprintf("canonical_path %q addresses unknown entity %q", f.CanonicalPath, entity), f.ID)
				}
			}
		}

		// --- weight sanity ---------------------------------------------------
		if f.IsScored() && f.Weight <= 0 && f.CanonicalPath != "" {
			add("weight", "scored field has no positive weight", f.ID)
		}
	}

	// --- 4. SBOM ordinals contiguous 1..N -----------------------------------
	ordinals := make([]int, 0, len(p.SBOM.DataFields))
	for _, f := range p.SBOM.DataFields {
		ordinals = append(ordinals, f.Ordinal)
	}
	sort.Ints(ordinals)
	for i, o := range ordinals {
		if o != i+1 {
			add("ordinals",
				fmt.Sprintf("SBOM data-field ordinals are not contiguous 1..%d (found %d at position %d)",
					len(ordinals), o, i+1), "")
			break
		}
	}

	// --- all_entries_verified must match reality ----------------------------
	//
	// ⚠ A COMPLIANCE CLAIM ABOUT TRANSCRIPTION FROM A PDF, so it is checked
	// only where there is a PDF. An operational profile is held to the
	// opposite rule: claiming verification it cannot have is the error.
	if p.Meta.IsCompliance() {
		if p.Meta.AllEntriesVerified && res.AssumedCount > 0 {
			add("meta",
				fmt.Sprintf("profile.all_entries_verified is true but %d entries are `assumed`; "+
					"every report would then overstate its provenance", res.AssumedCount), "")
		}
		if !p.Meta.AllEntriesVerified && res.AssumedCount == 0 {
			add("meta", "profile.all_entries_verified is false but no entry is `assumed`", "")
		}
	} else {
		if p.Meta.AllEntriesVerified {
			add("meta", "all_entries_verified without a source document reads as a "+
				"provenance claim there is nothing behind", "")
		}
		// ⚠ THE CHECK THAT MAKES THE SEPARATION ENFORCED RATHER THAN INTENDED.
		//
		// Every CERT-In accessor in this package reads the named sections. If
		// an operational profile ever defined one, its fields would be read as
		// a standard's — scored into completeness_pct, generated into
		// HBOM_FIELDS, printed in the evidence pack. Refuse the shape outright
		// rather than trusting that nobody does it.
		if len(p.SBOM.DataFields)+len(p.QBOM.Elements)+len(p.AIBOM.Elements)+
			len(p.HBOM.Elements)+len(p.CryptoAsset.Types) > 0 {
			add("kind", "an operational profile must not define CERT-In sections; a "+
				"`sbom:`/`hbom:`/`crypto_asset:` block here would be read as a "+
				"standard by every accessor in this package", "")
		}
	}

	// --- crypto discriminator ------------------------------------------------
	//
	// Without a discriminator the coverage checker cannot branch on asset_type,
	// and every certificate gets scored against the Keys field set.
	if len(p.CryptoAsset.Types) > 0 && p.CryptoAsset.Discriminator == "" {
		add("crypto", "crypto_asset has types but no discriminator; type-aware "+
			"coverage scoring would be impossible", "")
	}

	return res
}
