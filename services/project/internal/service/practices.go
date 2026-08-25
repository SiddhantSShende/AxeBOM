package service

import (
	"context"
	"strings"

	"github.com/axebom/axebom/libs/go-shared/model"
	"github.com/axebom/axebom/libs/go-shared/platform/errs"
	"github.com/axebom/axebom/services/project/internal/store"
)

// CERT-In "Practices and Processes" — Table 5, category 3 (PDF p.22).
//
// WHY THIS IS A PRODUCT FEATURE AND NOT A SETTINGS PAGE:
//
// "Minimum Elements" is THREE categories, not just the 21 data fields — Data
// Fields, Automation Support, and Practices and Processes. A tool that
// implements only the data fields and calls itself CERT-In compliant is
// overstating, and that overstatement is the exact failure mode this product
// exists to avoid.
//
// So the six sub-elements are captured at project registration, they are
// surfaced as a GAP when absent, and the gap is reported HERE — at the point of
// entry — rather than discovered as a coverage surprise when a report is
// generated weeks later.
//
// The list is read from the compliance profile (model.PracticeFields, which is
// generated from docs/reference/certin-v2.0.yaml). Never write the count.

// PracticeGap is one unrecorded sub-element.
type PracticeGap struct {
	// FieldID is the profile id, e.g. certin.sbom.pp.frequency.
	FieldID string `json:"field_id"`
	// Name is the CERT-In name, for display.
	Name string `json:"name"`
	// Reason states why it does not count as recorded.
	Reason string `json:"reason"`
}

// PracticesReport is the practices of a project plus its compliance gaps.
type PracticesReport struct {
	Practices store.Practices `json:"-"`

	// Gaps lists the sub-elements that are not substantively recorded.
	Gaps []PracticeGap `json:"gaps"`

	// Recorded and Total are rendered, never hardcoded. Total comes from the
	// profile, so a CERT-In revision changes it without a code change.
	Recorded int `json:"recorded"`
	Total    int `json:"total"`

	// Complete is true only when every sub-element is substantively recorded.
	// This is what the UI uses to say a project cannot yet produce a complete
	// compliance report.
	Complete bool `json:"complete"`
}

// practiceValue maps a profile field id to the stored value.
//
// The binding is declared in the profile as `axebom_binding`; this is the Go
// side of that binding. Keeping it in one function means a field added to the
// profile fails here loudly rather than being silently skipped in scoring.
func practiceValue(p store.Practices, fieldID string) (*string, bool) {
	switch fieldID {
	case model.FieldCertinSbomPpFrequency:
		return p.Frequency, true
	case model.FieldCertinSbomPpDepth:
		return p.Depth, true
	case model.FieldCertinSbomPpKnownUnknowns:
		return p.KnownUnknowns, true
	case model.FieldCertinSbomPpDistributionAndDelivery:
		return p.Distribution, true
	case model.FieldCertinSbomPpAccessControl:
		return p.AccessControl, true
	case model.FieldCertinSbomPpAccommodationOfMistakes:
		return p.ErrataPolicy, true
	default:
		return nil, false
	}
}

// substantive reports whether a value counts as PRESENT for coverage.
//
// CLAUDE.md invariant 3: `not-provided`, `NOASSERTION`, `unknown`, "" and "[]"
// are all recorded but score zero. Treating "not-provided" as covered is
// exactly how a tool ships a misleading 100%.
func substantive(v *string) bool {
	if v == nil {
		return false
	}
	s := strings.ToLower(strings.TrimSpace(*v))
	switch s {
	case "", model.NotProvided, "noassertion", "none", "unknown", "n/a", "na", "[]", "null":
		return false
	}
	return true
}

// EvaluatePractices scores a project's practices against the profile.
func EvaluatePractices(p store.Practices) PracticesReport {
	report := PracticesReport{
		Practices: p,
		Total:     len(model.PracticeFields), // FROM THE PROFILE. Never a literal.
	}

	for _, field := range model.PracticeFields {
		value, known := practiceValue(p, field.ID)
		if !known {
			// A profile field with no Go binding. Report it as a gap rather
			// than ignoring it: silently skipping an unmapped field would
			// inflate the score after a profile revision.
			report.Gaps = append(report.Gaps, PracticeGap{
				FieldID: field.ID, Name: field.Name,
				Reason: "this sub-element has no binding in the product yet",
			})
			continue
		}

		switch {
		case value == nil:
			report.Gaps = append(report.Gaps, PracticeGap{
				FieldID: field.ID, Name: field.Name,
				Reason: "not recorded",
			})
		case !substantive(value):
			report.Gaps = append(report.Gaps, PracticeGap{
				FieldID: field.ID, Name: field.Name,
				// Naming the value makes the rule visible: the user declared
				// something, and the declaration does not count as coverage.
				Reason: "recorded as " + strings.TrimSpace(*value) +
					", which is a declaration rather than a substantive value",
			})
		default:
			report.Recorded++
		}
	}

	report.Complete = report.Recorded == report.Total
	return report
}

// GetPractices reads and scores a project's practices.
func (s *Service) GetPractices(ctx context.Context, tenantID, projectID string) (PracticesReport, error) {
	p, err := s.store.GetPractices(ctx, tenantID, projectID)
	if err != nil {
		return PracticesReport{}, mapStoreError(err)
	}
	return EvaluatePractices(p), nil
}

// PracticesInput is the request body for setting practices.
//
// Pointers throughout, so the handler can distinguish "field omitted" from
// "field set to empty" — see the note on store.Practices.
type PracticesInput struct {
	Frequency     *string
	Depth         *string
	KnownUnknowns *string
	Distribution  *string
	AccessControl *string
	ErrataPolicy  *string
}

// SetPractices writes a project's practices.
//
// Enum values are validated against the PROFILE, not a hardcoded list:
// `depth` against CERT-In §3.1 levels, `access_control` against the two values
// Table 5 names.
func (s *Service) SetPractices(ctx context.Context, tenantID, projectID string,
	in PracticesInput,
) (PracticesReport, error) {
	if in.Depth != nil && *in.Depth != "" && !model.BOMDepthValid(*in.Depth) {
		return PracticesReport{}, errs.Newf(errs.ValidationFieldInvalid,
			"depth must be one of %v", model.BOMLevels)
	}
	if in.AccessControl != nil && *in.AccessControl != "" {
		// CERT-In §5.3.2 requires BOTH a public and a private version be
		// maintainable, so this records which one THIS project's BOM is.
		if *in.AccessControl != "public" && *in.AccessControl != "private" {
			return PracticesReport{}, errs.New(errs.ValidationFieldInvalid,
				"access_control must be 'public' or 'private'")
		}
	}

	saved, err := s.store.UpsertPractices(ctx, tenantID, store.Practices{
		ProjectID:     projectID,
		Frequency:     trimPtr(in.Frequency),
		Depth:         trimPtr(in.Depth),
		KnownUnknowns: trimPtr(in.KnownUnknowns),
		Distribution:  trimPtr(in.Distribution),
		AccessControl: trimPtr(in.AccessControl),
		ErrataPolicy:  trimPtr(in.ErrataPolicy),
	})
	if err != nil {
		return PracticesReport{}, mapStoreError(err)
	}
	return EvaluatePractices(saved), nil
}

// trimPtr trims a pointed-to string, preserving nil.
func trimPtr(s *string) *string {
	if s == nil {
		return nil
	}
	t := strings.TrimSpace(*s)
	return &t
}
