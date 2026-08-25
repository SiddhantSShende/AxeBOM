package compliance

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// ─── Guardrails ─────────────────────────────────────────────────────────────
//
// ⚠ THESE CHECKS GUARD FAILURES THAT ARE INVISIBLE IN NORMAL OPERATION.
//
// Nothing crashes, no test goes red, and the wrong thing appears on a document
// somebody hands to a regulator. Phase 16 asks for them to be grepped by hand;
// a hand-grep happens once, performed by the person who already knows the rule,
// who is the person least likely to have broken it. These run in CI instead.
//
// ⚠ AND THEY ARE DELIBERATELY NARROW, BECAUSE THE FIRST VERSION WAS NOT.
//
// A naive "does this line contain 21?" flagged `pageWidth = 210.0`, a cache TTL
// of `24 * 3600`, and two comments explaining the rule itself. Five findings,
// five false positives. A check that cries wolf is a check somebody disables,
// and a disabled check is worse than no check because its absence is invisible.
//
// So a count must appear with a WORD BOUNDARY and in a context that means a
// count of fields; and the compliance-word rule ignores comments, which
// necessarily discuss the word they forbid.

// GuardrailFinding is one violation, located.
type GuardrailFinding struct {
	Rule string
	File string
	Line int
	Text string
	Why  string
}

func (f GuardrailFinding) String() string {
	return fmt.Sprintf("%s:%d: [%s] %s\n      %s", f.File, f.Line, f.Rule, f.Text, f.Why)
}

// GuardrailReport is the result of an audit.
type GuardrailReport struct {
	Findings []GuardrailFinding
	// Scanned is how many files were read. Reported because a check that
	// silently scanned nothing passes, and a passing check that proves nothing
	// is worse than no check.
	Scanned int
	// CountsChecked are the field counts the audit searched for.
	CountsChecked map[string]int
}

func (r GuardrailReport) OK() bool { return len(r.Findings) == 0 }

// ⚠ THE WORD "compliant" MUST NOT APPEAR IN GENERATED OUTPUT.
//
// AxeBOM reports violations against a CONFIGURED POLICY. It cannot assert
// compliance: that is a determination an auditor makes about an organisation,
// not one a tool makes about a repository. A report that says "compliant"
// converts our coverage arithmetic into a legal claim we are not positioned to
// make — and the customer quotes it, in good faith, to somebody who will hold
// them to it.
var compliantWord = regexp.MustCompile(`(?i)\bcompliant\b|\bcompliance status\b`)

// Uses of the word that are not claims: negations, and third-party markings.
var compliantAllowed = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\b(not|never|cannot|no|isn't|is not|avoid)\b[^.]{0,80}\bcompliant\b`),
	regexp.MustCompile(`(?i)\bcompliant\b[^.]{0,80}\b(is not|never|must not|does not|would be)\b`),
	// RoHS/CE are a manufacturer's assertion about a part, carried verbatim
	// from a datasheet. Ours to report, not ours to make.
	regexp.MustCompile(`(?i)\bRoHS[- ]?compliant\b`),
	regexp.MustCompile(`(?i)\bCE[- ]?compliant\b`),
}

// ⚠ A COUNT ANSWERS "HOW MANY". AN ORDINAL ANSWERS "WHICH ONE" — AND CERT-In
// USES ORDINALS CONSTANTLY.
//
// "§4.2 field 21" names the Unique Identifier. It is the guideline's own
// numbering, it is correct, and rewriting it would be wrong. "Table 11" is a
// table number. An earlier version of this check flagged eight of those plus
// every `Ordinal:` in the generated profile — nine findings, nine false
// positives, which is precisely how a check gets switched off.
//
// The number has to come BEFORE the noun to be a count.
const countPhrasePattern = `(?i)\b%d\s+(data\s+)?(field|element|minimum\s+element)s?\b`

// countAssignmentPattern matches a count stored where a count belongs.
const countAssignmentPattern = `(?i)\b(count|total|num|numfields|fieldcount|expected)\w*\s*[:=]{1,2}\s*%d\b`

// AuditGeneratedOutput checks the packages that produce customer-facing text.
func AuditGeneratedOutput(p *Profile, repoRoot string, roots []string) (GuardrailReport, error) {
	report := GuardrailReport{CountsChecked: fieldCounts(p)}

	for _, root := range roots {
		dir := filepath.Join(repoRoot, filepath.FromSlash(root))
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			continue
		}

		err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return err
			}
			if !auditable(path) {
				return nil
			}

			body, err := os.ReadFile(path) //nolint:gosec // walking our own source
			if err != nil {
				return err
			}
			report.Scanned++

			rel, relErr := filepath.Rel(repoRoot, path)
			if relErr != nil {
				rel = path
			}

			report.Findings = append(report.Findings,
				auditFile(filepath.ToSlash(rel), string(body), report.CountsChecked)...)
			return nil
		})
		if err != nil {
			return report, fmt.Errorf("walking %s: %w", dir, err)
		}
	}

	if report.Scanned == 0 {
		return report, fmt.Errorf(
			"no files were audited, so this check proves nothing; the roots given "+
				"(%s) matched nothing under %s", strings.Join(roots, ", "), repoRoot)
	}
	return report, nil
}

// auditable reports whether a file's content reaches a customer.
//
// Test files are excluded: they necessarily contain the literals and phrases
// these rules forbid, in order to assert that production code does not.
func auditable(path string) bool {
	base := filepath.Base(path)
	switch strings.ToLower(filepath.Ext(path)) {
	case ".go", ".py", ".ts", ".tsx":
		return !strings.HasSuffix(base, "_test.go") &&
			!strings.Contains(base, ".test.") &&
			!strings.HasPrefix(base, "test_") &&
			base != "guardrail.go" &&
			// Generated FROM the profile, so its numbers ARE the profile rather
			// than a copy of it. Auditing it flags the authoritative source as a
			// violation of itself.
			!strings.HasPrefix(base, "generated_")
	default:
		return false
	}
}

func auditFile(path, body string, counts map[string]int) []GuardrailFinding {
	var findings []GuardrailFinding

	// ⚠ COMMENT STATE IS TRACKED ACROSS LINES, because a prefix check misses
	// every continuation line — which is where prose actually lives. The first
	// version flagged two comments explaining these very rules.
	inBlock := false

	for i, line := range strings.Split(body, "\n") {
		number := i + 1
		trimmed := strings.TrimSpace(line)

		wasComment := inBlock
		inBlock = trackComment(trimmed, inBlock)
		if wasComment || inBlock || isLineComment(trimmed) {
			continue
		}

		// --- Rule 1: no hardcoded field count -----------------------------
		//
		// ⚠ WRITING THE COUNT IS EXACTLY HOW A PRODUCT SHIPS A FALSE CLAIM WHEN
		// A GUIDELINE IS REVISED. The literal stops matching the profile,
		// nothing fails, and a report states a number that is wrong.
		for _, bomType := range SortedKeys(counts) {
			if hardcodedCount(trimmed, counts[bomType]) {
				findings = append(findings, GuardrailFinding{
					Rule: "hardcoded-field-count", File: path, Line: number,
					Text: truncate(trimmed),
					Why: fmt.Sprintf(
						"%d is the current %s element count. Render it from the profile "+
							"(len(...Fields)); a literal stops matching when CERT-In revises "+
							"the guideline, and nothing fails when it does.",
						counts[bomType], bomType),
				})
				break
			}
		}

		// --- Rule 2: no assertion of compliance ---------------------------
		if inUserFacingString(trimmed) &&
			compliantWord.MatchString(trimmed) &&
			!allowedCompliant(trimmed) {
			findings = append(findings, GuardrailFinding{
				Rule: "asserts-compliance", File: path, Line: number,
				Text: truncate(trimmed),
				Why: "AxeBOM reports violations against a configured policy and never " +
					"asserts compliance — that is a determination an auditor makes about an " +
					"organisation, not one a tool makes about a repository, and the customer " +
					"will quote it in good faith to somebody who holds them to it.",
			})
		}
	}

	return findings
}

// trackComment returns whether the NEXT line is inside a block comment.
func trackComment(trimmed string, inBlock bool) bool {
	if inBlock {
		// A docstring and a /* */ block both end on the delimiter.
		return !strings.Contains(trimmed, `"""`) &&
			!strings.Contains(trimmed, "'''") &&
			!strings.Contains(trimmed, "*/")
	}

	for _, open := range []string{`"""`, "'''"} {
		if strings.HasPrefix(trimmed, open) {
			// A one-line docstring opens and closes on the same line.
			return strings.Count(trimmed, open) == 1
		}
	}
	if strings.HasPrefix(trimmed, "/*") && !strings.Contains(trimmed, "*/") {
		return true
	}
	return false
}

func isLineComment(trimmed string) bool {
	return strings.HasPrefix(trimmed, "//") ||
		strings.HasPrefix(trimmed, "#") ||
		strings.HasPrefix(trimmed, "*") ||
		strings.HasPrefix(trimmed, "{/*")
}

// inUserFacingString reports whether a line contains a string literal.
//
// A Go identifier called `complianceProfile` is not a claim; a string saying
// "your SBOM is compliant" is.
func inUserFacingString(trimmed string) bool {
	return strings.ContainsAny(trimmed, "\"'`")
}

func allowedCompliant(line string) bool {
	for _, allowed := range compliantAllowed {
		if allowed.MatchString(line) {
			return true
		}
	}
	return false
}

// hardcodedCount reports whether a line states a field count as a literal.
//
// ⚠ THREE CONDITIONS, ALL REQUIRED, AND EACH ONE REMOVES A CLASS OF FALSE
// POSITIVE THE FIRST VERSION PRODUCED:
//
//	word boundary   `= 21` must not match `pageWidth = 210.0`
//	field context   the line must mention a field, element or the profile —
//	                without this, a 24-hour cache TTL is a finding
//	no len()        a line already deriving the count from the profile is the
//	                CORRECT form, not a violation of the rule
func hardcodedCount(trimmed string, count int) bool {
	// A line already deriving the count from the profile is the CORRECT form,
	// not a violation of the rule.
	if strings.Contains(trimmed, "len(") {
		return false
	}

	phrase := regexp.MustCompile(fmt.Sprintf(countPhrasePattern, count))
	assignment := regexp.MustCompile(fmt.Sprintf(countAssignmentPattern, count))

	return phrase.MatchString(trimmed) || assignment.MatchString(trimmed)
}

func fieldCounts(p *Profile) map[string]int {
	out := map[string]int{}
	if n := len(p.SBOM.DataFields); n > 0 {
		out["SBOM"] = n
	}
	if n := len(p.AIBOM.Elements); n > 0 {
		out["AIBOM"] = n
	}
	if n := len(p.QBOM.Elements); n > 0 {
		out["QBOM"] = n
	}
	if n := len(p.HBOM.Elements) + len(p.HBOM.AdditionalRequiredElements.Elements); n > 0 {
		out["HBOM"] = n
	}
	return out
}

func truncate(s string) string {
	const max = 100
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}
