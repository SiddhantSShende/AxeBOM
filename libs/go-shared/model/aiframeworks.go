package model

import (
	"slices"
	"strings"

	"github.com/axebom/axebom/libs/go-shared/platform/errs"
)

// ---------------------------------------------------------------------------
// AI governance framework vocabularies
//
// ⚠ THESE ARE VOCABULARIES A PERSON CHOOSES FROM, NOT THINGS AxeBOM INFERS.
//
// Whether an AI system is "high-risk" under the EU AI Act depends on what it is
// USED FOR — the sector, the deployment context, whether a human is in the loop
// — and none of that is visible in a repository. A product that derived a risk
// tier from an import statement would be manufacturing a legal conclusion out of
// a dependency graph, and a customer would carry it into an audit.
//
// So AxeBOM offers the closed sets below, records which values a named person
// chose, and renders the result as their declaration. `aibom.compliance_tags
// .declared_by` is on every row for exactly that reason.
//
// ⚠ CLOSED SETS, AND THE DATABASE AGREES. `migrations/aibom/0001_init.sql`
// carries a CHECK constraint over the tier values; `TestEUAIActTiersMatchTheDatabaseCheck`
// asserts these two lists are the same, because a transcription between Go and
// SQL is exactly the kind of thing that drifts silently.
// ---------------------------------------------------------------------------

// EUAIActTiers are the risk categories of Regulation (EU) 2024/1689.
//
//	unacceptable  Article 5 — prohibited practices.
//	high          Article 6 and Annex III.
//	limited       Article 50 — transparency obligations.
//	minimal       everything else; no obligations under the Act.
//	undetermined  ⚠ A FIRST-CLASS ANSWER, NOT AN ABSENCE. "Nobody has looked at
//	              this yet" and "somebody looked and could not decide" are
//	              different states, and only one of them is a task for a person.
var EUAIActTiers = []string{"unacceptable", "high", "limited", "minimal", "undetermined"}

// NISTAIRMFFunctions are the four core functions of the NIST AI Risk
// Management Framework 1.0 (NIST AI 100-1).
//
// A tag names the functions a project has ADDRESSED. It says nothing about how
// well: the framework has no conformance level and AxeBOM measures none.
var NISTAIRMFFunctions = []string{"GOVERN", "MAP", "MEASURE", "MANAGE"}

// ISO42001Controls are the Annex A control CATEGORIES of ISO/IEC 42001:2023.
//
// ⚠ CATEGORIES, NOT INDIVIDUAL CONTROLS, AND THAT IS A DELIBERATE LIMIT.
// Annex A subdivides each of these into numbered controls. AxeBOM does not
// enumerate them, because a control reference that is one digit wrong is a false
// citation in a compliance document — and unlike a missing value, a plausible
// wrong one is not visible to the reader. A customer who works at control
// granularity records it in the rationale, in their own words.
var ISO42001Controls = []string{
	"A.2 Policies related to AI",
	"A.3 Internal organization",
	"A.4 Resources for AI systems",
	"A.5 Assessing impacts of AI systems",
	"A.6 AI system life cycle",
	"A.7 Data for AI systems",
	"A.8 Information for interested parties",
	"A.9 Use of AI systems",
	"A.10 Third-party and customer relationships",
}

// UserSuppliedAIBOMFields are the CERT-In Table 10 elements no tool can report.
//
// ⚠ DERIVED FROM THE PROFILE, AND DERIVED IN ONE PLACE. `user_supplied: true`
// in `docs/reference/certin-v2.0.yaml` is what says which elements these are;
// both languages generate their field sets from it. This lives in the shared
// model package rather than in a service because TWO services now read it —
// services/aibom renders the form and services/project renders the "what is
// still owed" requirement — and two hand-maintained copies of a field set is
// how the last one drifted, silently omitting `environmental_impact` so that
// element sat in the coverage denominator with no way for anyone to fill it.
//
// ⚠ NO COUNT IS WRITTEN ANYWHERE (invariant 2). Callers that need one take
// `len()` of this.
func UserSuppliedAIBOMFields() []ProfileField {
	out := make([]ProfileField, 0, len(AIBOMFields))
	for _, f := range AIBOMFields {
		if f.UserSupplied {
			out = append(out, f)
		}
	}
	return out
}

// ValidateComplianceTag refuses a value outside the published vocabularies.
//
// ⚠ REFUSED AT THE EDGE, NOT SILENTLY DROPPED. A typo'd tier stored as-is would
// render in a report as a category the framework does not have, and would be
// invisible to any aggregate that groups by tier. An empty tier is legal — it
// means nobody has classified this — and is distinct from `undetermined`, which
// means somebody looked.
func ValidateComplianceTag(tier string, nist, iso []string) error {
	if tier != "" && !slices.Contains(EUAIActTiers, tier) {
		return errs.Newf(errs.ValidationFieldInvalid,
			"eu_ai_act_tier %q is not a risk category of Regulation (EU) 2024/1689; want one of %s",
			tier, strings.Join(EUAIActTiers, ", "))
	}
	for _, f := range nist {
		if !slices.Contains(NISTAIRMFFunctions, f) {
			return errs.Newf(errs.ValidationFieldInvalid,
				"nist_ai_rmf %q is not a core function of NIST AI 100-1; want one of %s",
				f, strings.Join(NISTAIRMFFunctions, ", "))
		}
	}
	for _, c := range iso {
		if !slices.Contains(ISO42001Controls, c) {
			return errs.Newf(errs.ValidationFieldInvalid,
				"iso_42001 %q is not an Annex A control category of ISO/IEC 42001:2023", c)
		}
	}
	return nil
}
