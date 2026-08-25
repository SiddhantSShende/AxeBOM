// Package aibom implements the small, Go-owned slice of CERT-In Table 10
// (AIBOM) that no scanner can ever populate — the four user-supplied
// elements — for services/project.
//
// ⚠ THIS IS NOT THE WHOLE OF AIBOM, UNLIKE hbom/qbom'S PACKAGES FOR THEIR
// BOM TYPES. Sixteen of Table 10's nineteen elements, and every dataset and
// dependency row, are discovered and normalized by
// workers/aibom/normalize/pipeline.py and read straight off
// normalize.ai_models by services/project/internal/store/ai_models.go — this
// package exists only for the remainder no tool reports: what the model is
// FOR, what it must not be used for, what security requirements apply, and
// its attestation. Mirrors workers/aibom/normalize/ai.py's
// USER_SUPPLIED_FIELDS and its `_is_substantive` rule field-for-field, the
// same "Go port, no bridge exists" precedent services/project/internal/qbom
// and .../hbom document for their own domains.
package aibom

import (
	"strings"

	"github.com/axebom/axebom/libs/go-shared/model"
)

// NotProvided is the explicit sentinel stored for an element nobody
// recorded. CLAUDE.md invariant 3: unknown fields are stored explicitly,
// never silently omitted, and score present = 0 either way.
const NotProvided = "not-provided"

// userSuppliedFieldIDs mirrors workers/aibom/normalize/ai.py's
// USER_SUPPLIED_FIELDS exactly — the four Table 10 elements that describe
// intent or policy rather than anything discoverable from code or a model
// card.
var userSuppliedFieldIDs = map[string]bool{
	model.FieldCertinAibom12SecurityRequirements: true,
	model.FieldCertinAibom15IntendedUsage:        true,
	model.FieldCertinAibom16OutOfScopeUsage:      true,
	model.FieldCertinAibom19Attestations:         true,
}

// IsUserSupplied reports whether fieldID is one of the four elements no
// tool reports.
func IsUserSupplied(fieldID string) bool { return userSuppliedFieldIDs[fieldID] }

// FormField describes one user-suppliable element, for the frontend to
// render a form from.
//
// ⚠ GENERATED FROM THE PROFILE. No count is written anywhere — a CERT-In
// revision that changes which elements are user-supplied changes this
// list without a Go code change (CLAUDE.md invariant 2).
type FormField struct {
	FieldID       string
	Name          string
	CanonicalPath string
	SourcePage    int
}

// UserSuppliedFormFields returns the four elements a user is asked to
// supply, generated from model.AIBOMFields — never hand-typed.
func UserSuppliedFormFields() []FormField {
	out := make([]FormField, 0, len(userSuppliedFieldIDs))
	for _, f := range model.AIBOMFields {
		if !IsUserSupplied(f.ID) {
			continue
		}
		out = append(out, FormField{
			FieldID:       f.ID,
			Name:          f.Name,
			CanonicalPath: f.CanonicalPath,
			SourcePage:    f.SourcePage,
		})
	}
	return out
}

// UserFields is what a caller supplies for the four Table 10 elements no
// tool ever reports.
type UserFields struct {
	SecurityRequirements string
	IntendedUsage        string
	OutOfScopeUsage      string
	AttestationSignature string
}

// ApplyUserFields updates fieldStatus in place for exactly the four
// user-supplied field ids, leaving every other entry (the fifteen
// tool-discovered elements' status, already correct as of the last
// normalization pass) untouched.
//
// Mirrors workers/aibom/normalize/ai.py's `_is_substantive` for the string
// case — a user who types "not-provided" has DECLARED the gap, which is a
// real act, and it still counts as zero.
func ApplyUserFields(fieldStatus map[string]string, fields UserFields) {
	set := func(fieldID, value string) {
		if isSubstantive(value) {
			fieldStatus[fieldID] = "provided"
		} else {
			fieldStatus[fieldID] = NotProvided
		}
	}
	set(model.FieldCertinAibom12SecurityRequirements, fields.SecurityRequirements)
	set(model.FieldCertinAibom15IntendedUsage, fields.IntendedUsage)
	set(model.FieldCertinAibom16OutOfScopeUsage, fields.OutOfScopeUsage)
	set(model.FieldCertinAibom19Attestations, fields.AttestationSignature)
}

// OrNotProvided returns value unchanged if it is substantive, or the
// explicit NotProvided sentinel otherwise.
//
// ⚠ STORED EXPLICITLY, NEVER NULL. Mirrors workers/aibom/normalize/ai.py's
// _empty_for(): every one of Table 10's nineteen elements always carries
// either a substantive value or the literal string "not-provided" once
// normalize_model() has run — never a genuinely empty value — so a Go write
// onto an already-normalized row must preserve that same guarantee rather
// than storing NULL for an empty submission. A NULL and an explicit
// "not-provided" would otherwise mean two different things to a reader with
// no way to tell them apart (CLAUDE.md invariant 3: omission hides the gap).
func OrNotProvided(value string) string {
	if isSubstantive(value) {
		return value
	}
	return NotProvided
}

func isSubstantive(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", NotProvided, "noassertion", "unknown", "n/a":
		return false
	default:
		return true
	}
}
