// Package vex implements CERT-In §6 vulnerability exploitability exchange.
//
// ⚠ LIVES IN libs/go-shared, NOT services/scan-orchestrator, BECAUSE TWO
// SERVICES NEED IT — the same reason libs/go-shared/csaf gives for its own
// placement. scan-orchestrator owns the CRUD (validates and writes
// normalize.vex_statements); report needs the identical Resolve() logic at
// render time, to compute the effective status behind render.Finding
// .VEXStatus. Report cannot import a scan-orchestrator internal package
// (CLAUDE.md invariant 11 — depguard fails that build), and reimplementing
// Resolve()'s specificity-then-recency rule a second time in report would be
// exactly the kind of restated spec that drifts the first time either copy
// changed (invariant 1). One resolver, two readers.
//
// ⚠ VEX NEVER MUTATES A FINDING. IT JOINS TO ONE.
//
// A suppressed finding is still a finding. "We assessed this and it does not
// apply to us" is a defensible position a reviewer can evaluate; "this CVE does
// not appear in our scan" is a different claim entirely, and a product that
// makes the first look like the second is producing a misleading artifact.
//
// ⚠ APPEND-ONLY. A NEW STATEMENT SUPERSEDES; NOTHING IS EDITED.
//
// The guideline (p.35) is explicit that VEX updates with each change. The chain
// is the evidence: an auditor asking "when did you decide this was not
// exploitable, and on what basis" needs every version, not the current one.
//
// ⚠ IT ATTACHES TO A CLUSTER, NOT A RAW VULNERABILITY ID.
//
// Grype says GHSA, OSV-Scanner says OSV, Dependency-Check says CVE. Attaching a
// triage decision to whichever id happened to be displayed means the decision is
// silently orphaned the moment the alias graph absorbs a new edge and the
// display id changes. The cluster is the durable surrogate (ADR-0005), so a
// decision survives that.
package vex

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// Status is one of CERT-In's four, verbatim.
//
// ⚠ EXACTLY FOUR, AND THE SPELLING IS THE GUIDELINE'S. They are restated
// identically for CBOM/QBOM (p.48), AIBOM (p.56) and HBOM (p.62), so a fifth
// status invented for convenience here would be wrong in five places and would
// fail the database CHECK constraint besides.
type Status string

const (
	// StatusNotAffected asserts the vulnerability is not exploitable here.
	// Requires a justification — see Validate.
	StatusNotAffected Status = "not_affected"
	// StatusAffected asserts it is exploitable and not yet remediated.
	StatusAffected Status = "affected"
	// StatusFixed asserts remediation has shipped.
	StatusFixed Status = "fixed"
	// StatusUnderInvestigation asserts triage is in progress. A real answer,
	// not an absence: it tells a reader somebody is looking.
	StatusUnderInvestigation Status = "under_investigation"
)

// Statuses returns the four, in the guideline's order.
func Statuses() []Status {
	return []Status{
		StatusNotAffected,
		StatusAffected,
		StatusFixed,
		StatusUnderInvestigation,
	}
}

// Valid reports whether s is one of the four.
func (s Status) Valid() bool {
	switch s {
	case StatusNotAffected, StatusAffected, StatusFixed, StatusUnderInvestigation:
		return true
	default:
		return false
	}
}

// Scope is how narrowly a statement applies.
//
// ⚠ SPECIFICITY IS THE FIRST TIE-BREAK, WHICH IS WHY THE ORDER MATTERS. A
// project-wide "not affected" must not override a component-specific
// "affected": the narrower assertion was made by someone looking at that
// component, and the broader one by someone looking at the estate.
type Scope string

const (
	// ScopeProject applies to every occurrence in the project.
	ScopeProject Scope = "project"
	// ScopeComponent applies to one component, whatever its version.
	ScopeComponent Scope = "component"
	// ScopeVersion applies to one component at one version.
	ScopeVersion Scope = "version"
)

// specificity ranks scopes, lowest number = most specific.
func (s Scope) specificity() int {
	switch s {
	case ScopeVersion:
		return 0
	case ScopeComponent:
		return 1
	case ScopeProject:
		return 2
	default:
		// An unknown scope is treated as the LEAST specific, so it can never
		// silently outrank a scope we understand.
		return 3
	}
}

// Valid reports whether the scope is one this build knows.
func (s Scope) Valid() bool {
	return s == ScopeProject || s == ScopeComponent || s == ScopeVersion
}

// Statement is one VEX assertion.
type Statement struct {
	ID        string
	TenantID  string
	ProjectID string

	// ComponentKey is empty for a project-scoped statement.
	ComponentKey string
	// ClusterID is the durable surrogate the decision attaches to.
	ClusterID string

	Status Status
	Scope  Scope

	Justification string
	Remediation   string
	// Workarounds and Downtime are named in the guideline text on p.35, not
	// merely implied — a product that stores only the status loses the two
	// fields an operator most wants when the answer is `affected`.
	Workarounds string
	Downtime    string

	Version int
	// SupersededBy is empty for the statement currently in force.
	SupersededBy string

	AuthorUserID string
	CreatedAt    time.Time
}

// Effective is the status in force for one finding, plus how it was reached.
type Effective struct {
	Status        Status
	StatementID   string
	Justification string
	Scope         Scope

	// History is every applicable statement, newest first — including the
	// superseded ones. The chain IS the evidence.
	History []Statement

	// Reason explains which rule selected the winner. Rendered in the UI so a
	// user who disagrees can see whether to write a narrower statement or a
	// newer one.
	Reason string
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

// Justifications are the CSAF 2.0 `impact_statement` categories.
//
// Constrained to the standard's set rather than free text, because a CSAF
// document carrying a justification outside it fails a consumer's validator —
// and free text there is also unmachine-readable, which defeats the point of
// publishing VEX at all.
var Justifications = []string{
	"component_not_present",
	"vulnerable_code_not_present",
	"vulnerable_code_not_in_execute_path",
	"vulnerable_code_cannot_be_controlled_by_adversary",
	"inline_mitigations_already_exist",
}

// Validate checks a statement before it is written.
func Validate(s Statement) error {
	if !s.Status.Valid() {
		return fmt.Errorf(
			"status %q is not one of CERT-In's four (%v)", s.Status, Statuses())
	}
	if !s.Scope.Valid() {
		return fmt.Errorf("scope %q is not project, component or version", s.Scope)
	}
	if s.ClusterID == "" {
		return fmt.Errorf(
			"a VEX statement must name a vulnerability cluster; attaching one to a " +
				"raw advisory id would orphan it the next time the alias graph changes")
	}
	if s.Scope != ScopeProject && s.ComponentKey == "" {
		return fmt.Errorf("a %s-scoped statement must name a component", s.Scope)
	}

	// ⚠ `not_affected` WITHOUT A JUSTIFICATION IS REFUSED.
	//
	// An unjustified suppression is an assertion a reviewer cannot evaluate —
	// and it is the one status that removes a vulnerability from a customer's
	// attention. CSAF requires it for the same reason.
	if s.Status == StatusNotAffected && strings.TrimSpace(s.Justification) == "" {
		return fmt.Errorf(
			"a `not_affected` statement requires a justification: suppressing a "+
				"vulnerability without a stated reason is an assertion nobody can "+
				"review. Use one of: %s", strings.Join(Justifications, ", "))
	}

	return nil
}

// ---------------------------------------------------------------------------
// Resolution
// ---------------------------------------------------------------------------

// Applies reports whether a statement governs a given finding.
func (s Statement) Applies(clusterID, componentKey string) bool {
	if s.ClusterID != clusterID {
		return false
	}
	switch s.Scope {
	case ScopeProject:
		return true
	case ScopeComponent, ScopeVersion:
		return s.ComponentKey == componentKey
	default:
		return false
	}
}

// Resolve finds the status in force for one finding.
//
// ⚠ TWO RULES, IN THIS ORDER, AND THE ORDER IS A DECISION RATHER THAN AN
// ACCIDENT:
//
//  1. Most specific scope wins. A component-scoped statement beats a
//     project-scoped one even if the project one is newer — the narrower
//     assertion was made by someone looking at that component.
//  2. Latest timestamp wins within a scope, then highest version. Somebody
//     revisiting the same question later had more information.
//
// Reversing them would let a sweeping "not affected" applied across a project
// silently suppress a specific, deliberate "affected" recorded yesterday.
func Resolve(statements []Statement, clusterID, componentKey string) *Effective {
	var applicable []Statement
	for _, s := range statements {
		if s.Applies(clusterID, componentKey) {
			applicable = append(applicable, s)
		}
	}
	if len(applicable) == 0 {
		return nil
	}

	history := append([]Statement(nil), applicable...)
	sort.SliceStable(history, func(i, j int) bool {
		if !history[i].CreatedAt.Equal(history[j].CreatedAt) {
			return history[i].CreatedAt.After(history[j].CreatedAt)
		}
		return history[i].Version > history[j].Version
	})

	// ⚠ SUPERSEDED STATEMENTS ARE EXCLUDED FROM THE DECISION AND KEPT IN THE
	// HISTORY. Dropping them from the history would destroy the audit chain the
	// append-only design exists to produce.
	live := make([]Statement, 0, len(applicable))
	for _, s := range applicable {
		if s.SupersededBy == "" {
			live = append(live, s)
		}
	}
	reason := ""
	if len(live) == 0 {
		// Every applicable statement was superseded by something outside this
		// set — a successor at a different scope, say. Reporting nothing would
		// silently drop an assertion that exists, so the most recent one stands
		// and the reason says why.
		live = applicable
		reason = "every applicable statement is superseded; the most recent one stands"
	}

	sort.SliceStable(live, func(i, j int) bool {
		a, b := live[i], live[j]
		if a.Scope.specificity() != b.Scope.specificity() {
			return a.Scope.specificity() < b.Scope.specificity()
		}
		if !a.CreatedAt.Equal(b.CreatedAt) {
			return a.CreatedAt.After(b.CreatedAt)
		}
		return a.Version > b.Version
	})

	winner := live[0]
	if reason == "" {
		reason = explain(winner, live)
	}

	return &Effective{
		Status:        winner.Status,
		StatementID:   winner.ID,
		Justification: winner.Justification,
		Scope:         winner.Scope,
		History:       history,
		Reason:        reason,
	}
}

// explain says which rule picked the winner.
//
// ⚠ THE UI RENDERS THIS. A user who disagrees with an effective status needs to
// know whether to write a NARROWER statement or a NEWER one, and "VEX says not
// affected" answers neither question.
func explain(winner Statement, live []Statement) string {
	sameScope := 0
	for _, s := range live {
		if s.Scope == winner.Scope {
			sameScope++
		}
	}

	switch {
	case len(live) == 1:
		return fmt.Sprintf("the only statement in force, scoped to the %s", winner.Scope)
	case sameScope == 1:
		return fmt.Sprintf(
			"the most specific statement in force: %s scope beats the %d broader one(s)",
			winner.Scope, len(live)-1)
	default:
		return fmt.Sprintf(
			"the most recent of %d statements at %s scope", sameScope, winner.Scope)
	}
}

// ---------------------------------------------------------------------------
// Supersession
// ---------------------------------------------------------------------------

// Supersede builds the successor to an existing statement.
//
// ⚠ IT RETURNS A NEW STATEMENT AND LEAVES THE OLD ONE ALONE. The caller writes
// both — the successor, and a `superseded_by` pointer on the predecessor. An
// UPDATE that changed the status in place would destroy exactly the record an
// auditor asks for.
func Supersede(previous Statement, next Statement) (Statement, error) {
	if previous.ClusterID != next.ClusterID {
		return Statement{}, fmt.Errorf(
			"a statement can only supersede one about the same vulnerability cluster")
	}
	if previous.Scope != next.Scope || previous.ComponentKey != next.ComponentKey {
		// ⚠ REFUSED RATHER THAN ALLOWED. A "successor" at a different scope is a
		// separate assertion, and chaining it would make the history read as one
		// evolving decision when it is two decisions about different things.
		return Statement{}, fmt.Errorf(
			"a successor must have the same scope and component as the statement it "+
				"supersedes (%s/%s -> %s/%s); a statement at a different scope is a "+
				"separate assertion, not a revision",
			previous.Scope, previous.ComponentKey, next.Scope, next.ComponentKey)
	}

	next.Version = previous.Version + 1
	next.SupersededBy = ""
	if err := Validate(next); err != nil {
		return Statement{}, err
	}
	return next, nil
}

// Chain orders a supersession chain oldest-first for display.
func Chain(statements []Statement) []Statement {
	out := append([]Statement(nil), statements...)
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Version != out[j].Version {
			return out[i].Version < out[j].Version
		}
		return out[i].CreatedAt.Before(out[j].CreatedAt)
	})
	return out
}

// ---------------------------------------------------------------------------
// Presentation
// ---------------------------------------------------------------------------

// DeEmphasized reports whether a finding should be shown quietly.
//
// ⚠ QUIETLY, NOT ABSENT. A `not_affected` finding is de-emphasized in a report
// and never deleted from it: the assessment is the valuable part, and a reader
// comparing two reports must be able to see that a vulnerability was considered
// rather than that it vanished.
func DeEmphasized(e *Effective) bool {
	return e != nil && (e.Status == StatusNotAffected || e.Status == StatusFixed)
}

// Summary counts findings by effective status, for the landscape view the
// guideline asks for (p.49 §8.4.1.11).
type Summary struct {
	NotAffected        int
	Affected           int
	Fixed              int
	UnderInvestigation int
	// Untriaged is findings with no statement at all.
	//
	// ⚠ COUNTED SEPARATELY FROM `under_investigation`. "Nobody has looked" and
	// "somebody is looking" are different facts, and folding the first into the
	// second overstates how much triage has happened.
	Untriaged int
}

// Total is every finding the summary covers.
func (s Summary) Total() int {
	return s.NotAffected + s.Affected + s.Fixed + s.UnderInvestigation + s.Untriaged
}

// Summarize counts a set of resolved findings.
func Summarize(effective []*Effective) Summary {
	var out Summary
	for _, e := range effective {
		if e == nil {
			out.Untriaged++
			continue
		}
		switch e.Status {
		case StatusNotAffected:
			out.NotAffected++
		case StatusAffected:
			out.Affected++
		case StatusFixed:
			out.Fixed++
		case StatusUnderInvestigation:
			out.UnderInvestigation++
		}
	}
	return out
}
