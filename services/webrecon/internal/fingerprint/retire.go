// Package fingerprint matches fetched page/script content against the
// retire.js vulnerable-JS-library signature database.
//
// ⚠ A GO-NATIVE MATCHER, NOT retire.js's OWN NODE CLI. Embedding a Node
// runtime inside a network-enabled sandboxed container would roughly double
// that container's attack surface for no benefit — see
// docs/04-OSINT-INTEGRATION.md's webrecon roster entry.
//
// ⚠ GO'S regexp (RE2) CANNOT EXECUTE EVERY retire.js SIGNATURE VERBATIM.
// Spiked against the real signature database before this package was
// written — not assumed. Full findings, counts and reasoning:
// services/webrecon/internal/fingerprint/signatures/PROVENANCE.md. Three RE2 gaps, handled
// three different ways:
//
//   - Backreferences (\1, \2, \3 inside a pattern) and lookbehind
//     ((?<=...)) are FUNDAMENTALLY unsupported by RE2 (linear-time matching
//     is the whole point of RE2, and both constructs are what make regex
//     matching exponential in the worst case). 2 of 284 uri+filecontent
//     patterns use one — jQuery's backreference filecontent variant and
//     lodash's lookbehind variant. SKIPPED at load, counted in LoadStats —
//     never silently dropped.
//   - Repeat counts above RE2's hardcoded 1000 cap (regexp/syntax's
//     maxRepeat, not configurable via any public API) are FIXABLE: CAPPED at
//     1000 rather than dropped. 7 patterns (tinyMCE, underscore.js, Vue x2,
//     Next.js x2, select2). A real, honest precision loss — a genuine gap
//     between two anchors in a minified bundle can exceed 1000 characters —
//     not a silent one.
package fingerprint

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// versionPlaceholder is retire.js's own marker for "the version capture
// group goes here" in an extractor pattern.
const versionPlaceholder = "§§version§§"

// versionCapture is what replaces it. Loose by design — a version string in
// the wild is "3.5.1", "3.5.1-beta.2", "v3.5.1", and rejecting anything this
// regex does not expect would be a matcher that works less often than
// retire.js's own does, for shapes it already knows about.
const versionCapture = `([0-9][0-9A-Za-z._-]*)`

// maxRE2Repeat is regexp/syntax's own hardcoded ceiling for a {n,m} bound —
// see this package's doc comment. A local constant, not derived from the
// stdlib, because there is no public API to read it from.
const maxRE2Repeat = 1000

// repeatBound matches a {n,m} or {n,} quantifier so an oversized upper bound
// can be capped before compilation.
var repeatBound = regexp.MustCompile(`\{(\d+),(\d*)\}`)

// Vulnerability is one retire.js-known CVE/advisory for a version range.
type Vulnerability struct {
	Below     string
	AtOrAbove string
	Severity  string
	Summary   string
	CVE       []string
	GHSA      string
}

// Match is one library detected in fetched content, with any vulnerability
// whose range contains the extracted version.
type Match struct {
	Library         string
	Version         string
	Vulnerabilities []Vulnerability
}

type library struct {
	name            string
	uriPatterns     []*regexp.Regexp
	contentPatterns []*regexp.Regexp
	vulnerabilities []Vulnerability
}

// Matcher holds the loaded, RE2-compatible subset of the signature database.
type Matcher struct {
	libraries []library
}

// LoadStats reports what LoadSignatures actually compiled, so a caller can
// log the gap honestly rather than assume every signature is in force.
type LoadStats struct {
	Libraries           int
	PatternsTotal       int
	PatternsCompiled    int
	SkippedIncompatible int // backreference or lookbehind — see package doc
	CappedRepeat        int // {n,m} with m > 1000, capped rather than dropped
}

// rawEntry mirrors one library's shape in repository/jsrepository.json.
// Fields this matcher does not use (bowername, npmname, hashes,
// filecontentreplace, func) are intentionally absent — see the package doc
// for filecontentreplace/hashes; func requires a live JS runtime (window.*
// property access) this static fetcher never has.
type rawEntry struct {
	Vulnerabilities []rawVulnerability `json:"vulnerabilities"`
	Extractors      rawExtractors      `json:"extractors"`
}

type rawExtractors struct {
	URI         []string `json:"uri"`
	FileContent []string `json:"filecontent"`
}

type rawVulnerability struct {
	Below       string         `json:"below"`
	AtOrAbove   string         `json:"atOrAbove"`
	Severity    string         `json:"severity"`
	Identifiers rawIdentifiers `json:"identifiers"`
}

type rawIdentifiers struct {
	Summary string   `json:"summary"`
	CVE     []string `json:"CVE"`
	GitHub  string   `json:"githubID"`
}

// LoadSignatures parses the vendored retire.js signature database
// (services/webrecon/internal/fingerprint/signatures/retire-js-jsrepository.json) into a Matcher.
//
// Never fails on a single bad pattern — an incompatible or malformed
// signature is skipped and counted, not a load-time error. The database is
// third-party data that changes on someone else's schedule; a shape this
// package has never seen must degrade the AFFECTED library's detection, not
// the whole matcher.
func LoadSignatures(data []byte) (*Matcher, LoadStats, error) {
	var raw map[string]rawEntry
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, LoadStats{}, fmt.Errorf("fingerprint: parse signature database: %w", err)
	}

	m := &Matcher{}
	var stats LoadStats
	stats.Libraries = len(raw)

	for name, entry := range raw {
		lib := library{name: name}

		for _, p := range entry.Extractors.URI {
			stats.PatternsTotal++
			if re, capped := compilePattern(p); re != nil {
				lib.uriPatterns = append(lib.uriPatterns, re)
				stats.PatternsCompiled++
				if capped {
					stats.CappedRepeat++
				}
			} else {
				stats.SkippedIncompatible++
			}
		}
		for _, p := range entry.Extractors.FileContent {
			stats.PatternsTotal++
			if re, capped := compilePattern(p); re != nil {
				lib.contentPatterns = append(lib.contentPatterns, re)
				stats.PatternsCompiled++
				if capped {
					stats.CappedRepeat++
				}
			} else {
				stats.SkippedIncompatible++
			}
		}

		for _, v := range entry.Vulnerabilities {
			lib.vulnerabilities = append(lib.vulnerabilities, Vulnerability{
				Below: v.Below, AtOrAbove: v.AtOrAbove, Severity: v.Severity,
				Summary: v.Identifiers.Summary, CVE: v.Identifiers.CVE, GHSA: v.Identifiers.GitHub,
			})
		}

		if len(lib.uriPatterns) > 0 || len(lib.contentPatterns) > 0 {
			m.libraries = append(m.libraries, lib)
		}
	}

	return m, stats, nil
}

// compilePattern substitutes the version placeholder, caps an oversized
// repeat bound, and compiles. Returns (nil, false) for a pattern RE2
// genuinely cannot express (backreference, lookbehind, or any other future
// incompatibility) rather than panicking or erroring the whole load.
func compilePattern(raw string) (*regexp.Regexp, bool) {
	pattern := strings.ReplaceAll(raw, versionPlaceholder, versionCapture)
	pattern, capped := capOversizedRepeats(pattern)

	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, false
	}
	return re, capped
}

// capOversizedRepeats rewrites every {n,m} with m > maxRE2Repeat to
// {n,1000} — RE2's own ceiling, hardcoded in regexp/syntax with no public
// API to raise it. {n,} (unbounded) is left alone: RE2 handles unbounded
// repeats natively, the cap is specific to an EXPLICIT upper bound.
func capOversizedRepeats(pattern string) (string, bool) {
	capped := false
	out := repeatBound.ReplaceAllStringFunc(pattern, func(m string) string {
		sub := repeatBound.FindStringSubmatch(m)
		if sub[2] == "" {
			return m // {n,} — unbounded, not this function's concern
		}
		upper, err := strconv.Atoi(sub[2])
		if err != nil || upper <= maxRE2Repeat {
			return m
		}
		capped = true
		return "{" + sub[1] + "," + strconv.Itoa(maxRE2Repeat) + "}"
	})
	return out, capped
}

// MatchURI checks a script's source URL (e.g. "/3.5.1/jquery.min.js")
// against every library's uri patterns.
func (m *Matcher) MatchURI(uri string) (Match, bool) {
	return m.match(uri, func(l library) []*regexp.Regexp { return l.uriPatterns })
}

// MatchContent checks a fetched script's body against every library's
// filecontent patterns.
func (m *Matcher) MatchContent(content string) (Match, bool) {
	return m.match(content, func(l library) []*regexp.Regexp { return l.contentPatterns })
}

func (m *Matcher) match(text string, patternsOf func(library) []*regexp.Regexp) (Match, bool) {
	for _, lib := range m.libraries {
		for _, re := range patternsOf(lib) {
			sub := re.FindStringSubmatch(text)
			if len(sub) < 2 {
				continue
			}
			version := sub[1]
			return Match{
				Library:         lib.name,
				Version:         version,
				Vulnerabilities: vulnerableAt(lib.vulnerabilities, version),
			}, true
		}
	}
	return Match{}, false
}

// vulnerableAt returns every vulnerability whose range contains version.
//
// A comparison error (an unparseable version, on either side) EXCLUDES the
// vulnerability rather than including it — asserting a version is vulnerable
// when the comparison could not actually be performed is a fabricated
// finding, and CLAUDE.md's normalizer doctrine is explicit that this
// codebase never invents data it cannot support.
func vulnerableAt(vulns []Vulnerability, version string) []Vulnerability {
	var out []Vulnerability
	for _, v := range vulns {
		if v.Below == "" && v.AtOrAbove == "" {
			continue
		}
		if v.Below != "" {
			cmp, ok := compareVersions(version, v.Below)
			if !ok || cmp >= 0 {
				continue
			}
		}
		if v.AtOrAbove != "" {
			cmp, ok := compareVersions(version, v.AtOrAbove)
			if !ok || cmp < 0 {
				continue
			}
		}
		out = append(out, v)
	}
	return out
}

// compareVersions does a best-effort, dot-separated numeric comparison —
// NOT full semver (no pre-release precedence, no build-metadata handling).
// Returns ok=false when either side has a non-numeric component, so the
// caller can refuse to assert a range it cannot actually evaluate.
func compareVersions(a, b string) (int, bool) {
	as, aok := numericParts(a)
	bs, bok := numericParts(b)
	if !aok || !bok {
		return 0, false
	}
	for i := 0; i < len(as) || i < len(bs); i++ {
		var av, bv int
		if i < len(as) {
			av = as[i]
		}
		if i < len(bs) {
			bv = bs[i]
		}
		if av != bv {
			if av < bv {
				return -1, true
			}
			return 1, true
		}
	}
	return 0, true
}

func numericParts(v string) ([]int, bool) {
	// A leading "v" (v3.5.1) is common enough in the wild to strip rather
	// than refuse.
	v = strings.TrimPrefix(v, "v")
	// Cut at the first non-version character (a pre-release/build suffix like
	// "-beta.2" or "+build5") rather than fail the whole comparison on it —
	// the numeric prefix is still a meaningful ordering signal.
	for i, r := range v {
		if r != '.' && (r < '0' || r > '9') {
			v = v[:i]
			break
		}
	}
	v = strings.Trim(v, ".")
	if v == "" {
		return nil, false
	}
	parts := strings.Split(v, ".")
	out := make([]int, 0, len(parts))
	for _, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil {
			return nil, false
		}
		out = append(out, n)
	}
	return out, true
}
