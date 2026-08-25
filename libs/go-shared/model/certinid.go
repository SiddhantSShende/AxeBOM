package model

// CERT-In unique identifier derivation — data field 21 (PDF p.24).
//
// ⚠ THIS IS NOT A PACKAGE URL, AND IT IS NOT A MERGE KEY.
//
// CERT-In §4.2 field 21 specifies:
//
//	pkg:supplier/OrganizationName/ComponentName@Version?qualifiers&subpath
//
// with the literal type token `supplier` and an ORGANISATION NAME where
// purl-spec uses an ecosystem type and namespace. Standard PURL for the same
// component is pkg:maven/org.apache.tomcat/tomcat@9.0.71.
//
// These are two different identifiers and AxeBOM stores both:
//
//	component.purl               canonical ecosystem PURL. THE MERGE KEY.
//	                             Every scanner emits it; all dedup runs on it.
//	component.certin_identifier  derived here. RENDER-ONLY. Never a merge key.
//
// Conflating them breaks dedup (organisation names are not stable or unique)
// AND breaks compliance output. See docs/03-NORMALIZER-SPEC.md §6.

import (
	"sort"
	"strings"
	"unicode"
)

// CERTInIdentifierInput is what the derivation needs.
type CERTInIdentifierInput struct {
	// Supplier is the organisation. When empty the caller must mark field 21
	// `not-provided` rather than accept a fabricated value.
	Supplier string
	Name     string
	// VersionRaw is used verbatim. Never the normalized version: the
	// identifier must round-trip to what the component actually declares.
	VersionRaw string
	// Qualifiers are identity-bearing only (arch, os, distro, epoch...).
	Qualifiers map[string]string
	Subpath    string
}

// NotProvided is the explicit marker for an absent value.
//
// Unknown fields are STORED as this, never silently omitted — omission hides
// the gap. It scores 0 for completeness_pct and 1 for declaration_pct
// (docs/03-NORMALIZER-SPEC.md §5.2).
const NotProvided = "not-provided"

// DeriveCERTInIdentifier builds the CERT-In form.
//
// Returns ("", false) when the supplier is unknown. The caller then records
// field 21 as `not-provided`: fabricating an organisation name would put a
// made-up value into a compliance artifact, which is worse than an honest gap.
func DeriveCERTInIdentifier(in CERTInIdentifierInput) (string, bool) {
	supplier := PascalCompact(in.Supplier)
	name := PascalCompact(in.Name)
	if supplier == "" || name == "" {
		return "", false
	}

	var b strings.Builder
	b.WriteString("pkg:supplier/")
	b.WriteString(supplier)
	b.WriteByte('/')
	b.WriteString(name)

	if v := strings.TrimSpace(in.VersionRaw); v != "" {
		b.WriteByte('@')
		b.WriteString(v)
	}

	if len(in.Qualifiers) > 0 {
		keys := make([]string, 0, len(in.Qualifiers))
		for k := range in.Qualifiers {
			if in.Qualifiers[k] != "" {
				keys = append(keys, k)
			}
		}
		// Sorted so the identifier is byte-stable. Map iteration order would
		// make the same component produce different identifiers across runs,
		// which breaks golden tests and, worse, makes two reports of the same
		// scan disagree.
		sort.Strings(keys)
		for i, k := range keys {
			if i == 0 {
				b.WriteByte('?')
			} else {
				b.WriteByte('&')
			}
			b.WriteString(k)
			b.WriteByte('=')
			b.WriteString(in.Qualifiers[k])
		}
	}

	// The guideline's prose says "&subpath" while its own Table 6 example uses
	// "#server/webapps". We follow the EXAMPLE and purl-spec, both of which use
	// '#'. The discrepancy is recorded in every report's methodology footnote
	// rather than silently resolved.
	if sp := strings.Trim(strings.TrimSpace(in.Subpath), "/"); sp != "" {
		b.WriteByte('#')
		b.WriteString(sp)
	}

	return b.String(), true
}

// PascalCompact converts a display name to the compact PascalCase the CERT-In
// examples use: "Apache Software Foundation" -> "ApacheSoftwareFoundation".
//
// Rules derived from the Table 6 worked examples (PDF p.26):
//
//	Apache Software Foundation        -> ApacheSoftwareFoundation
//	PostgreSQL Global Development Group -> PostgreSQLGlobalDevelopmentGroup
//	Twilio Inc.                       -> TwilioInc
//	Apache Tomcat                     -> ApacheTomcat
//
// Note PostgreSQL: INTERNAL CAPITALISATION IS PRESERVED. Naive Title-casing
// would produce "Postgresql" and no longer match the guideline's own example,
// so only the first letter of a word is forced upper.
func PascalCompact(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}

	words := strings.FieldsFunc(s, func(r rune) bool {
		return unicode.IsSpace(r) || r == '-' || r == '_' || r == ','
	})

	var b strings.Builder
	for _, w := range words {
		// Drop punctuation ("Inc." -> "Inc"), keep letters and digits.
		cleaned := strings.Map(func(r rune) rune {
			if unicode.IsLetter(r) || unicode.IsDigit(r) {
				return r
			}
			return -1
		}, w)
		if cleaned == "" {
			continue
		}
		runes := []rune(cleaned)
		runes[0] = unicode.ToUpper(runes[0])
		b.WriteString(string(runes)) // remaining runes keep their original case
	}
	return b.String()
}

// IdentityQualifiers are the PURL qualifiers that are part of a component's
// IDENTITY and therefore belong in the CERT-In identifier.
//
// Everything else (repository_url, download_url, checksum, file_name, vcs_url)
// is metadata about where a component came from, not which component it is,
// and is stripped to typed fields during normalization.
var IdentityQualifiers = map[string]bool{
	"arch":       true,
	"os":         true,
	"distro":     true,
	"epoch":      true,
	"classifier": true, // Maven
	"type":       true, // Maven
	"channel":    true, // conda
}

// FilterIdentityQualifiers keeps only identity-bearing qualifiers.
func FilterIdentityQualifiers(q map[string]string) map[string]string {
	out := make(map[string]string, len(q))
	for k, v := range q {
		if IdentityQualifiers[strings.ToLower(k)] && v != "" {
			out[strings.ToLower(k)] = v
		}
	}
	return out
}
