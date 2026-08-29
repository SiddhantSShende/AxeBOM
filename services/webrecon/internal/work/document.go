package work

import "github.com/axebom/axebom/services/webrecon/internal/fingerprint"

// webreconDoc is the native_output artifact this service produces — AxeBOM's
// own JSON shape, not a CycloneDX or SPDX document (there is no "native"
// format for a retire.js-style fingerprint result). Parsed exclusively by
// workers/sbom/adapters/webrecon_fingerprint.py; see docs/04-OSINT-
// INTEGRATION.md §4's webrecon subsection for the field-by-field mapping
// into canonical components.
type webreconDoc struct {
	SchemaVersion    string    `json:"schema_version"`
	RootURL          string    `json:"root_url"`
	DiscoveryEnabled bool      `json:"discovery_enabled"`
	Hosts            []hostDoc `json:"hosts"`
}

type hostDoc struct {
	Host       string       `json:"host"`
	FetchedURL string       `json:"fetched_url"`
	Status     string       `json:"status"`
	Error      string       `json:"error,omitempty"`
	Libraries  []libraryDoc `json:"libraries"`
}

type libraryDoc struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	// NPMPurl is a BEST-EFFORT inference, not an assertion the tool proved:
	// virtually every JS library retire.js's database covers is npm-
	// published, but this is inference, never a certainty retire.js itself
	// states — see docs/04-OSINT-INTEGRATION.md's webrecon subsection.
	NPMPurl         string    `json:"npm_purl"`
	Vulnerabilities []vulnDoc `json:"vulnerabilities,omitempty"`
}

type vulnDoc struct {
	Severity string   `json:"severity,omitempty"`
	Summary  string   `json:"summary,omitempty"`
	CVE      []string `json:"cve,omitempty"`
	GHSA     string   `json:"ghsa,omitempty"`
}

func toHostDoc(r fingerprint.HostResult) hostDoc {
	h := hostDoc{
		Host: r.Host, FetchedURL: r.FetchedURL,
		Status: r.Status, Error: r.Error,
	}
	for _, m := range r.Libraries {
		h.Libraries = append(h.Libraries, toLibraryDoc(m))
	}
	return h
}

func toLibraryDoc(m fingerprint.Match) libraryDoc {
	lib := libraryDoc{
		Name: m.Library, Version: m.Version,
		NPMPurl: "pkg:npm/" + m.Library + "@" + m.Version,
	}
	for _, v := range m.Vulnerabilities {
		lib.Vulnerabilities = append(lib.Vulnerabilities, vulnDoc{
			Severity: v.Severity, Summary: v.Summary, CVE: v.CVE, GHSA: v.GHSA,
		})
	}
	return lib
}
