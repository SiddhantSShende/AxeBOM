// Package toolctl acquires and verifies the third-party scanners AxeBOM
// invokes.
//
// ADR-0002: pinned release artifacts, never source builds. For a compliance
// product, provenance IS the product — a report must be able to assert "this
// SBOM was produced by syft v1.51.0 against grype-db vintage X", and a binary
// built locally off a branch cannot make that claim.
//
// Three properties this package must preserve:
//
//   - Verification failures are LOUD. A checksum mismatch refuses to install.
//     Where upstream publishes nothing to verify against, the gap is declared
//     in the manifest and warned about on every sync — never silently accepted.
//
//   - A missing engine is NOT fatal. Resolution degrades container -> binary ->
//     `unavailable`, and an unavailable engine is recorded in the report's
//     Engine Coverage section. Losing one engine should cost that engine's
//     coverage, visibly, not the whole scan.
//
//   - Java tools are container-only, so the host JDK never matters.
package toolctl

import (
	"fmt"
	"os"
	"runtime"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Manifest is the parsed tools.manifest.yaml.
type Manifest struct {
	Meta      ManifestMeta   `yaml:"manifest"`
	Defaults  Defaults       `yaml:"defaults"`
	Tools     []Tool         `yaml:"tools"`
	Libraries []Library      `yaml:"libraries"`
	Services  []Service      `yaml:"services"`
	Providers []Provider     `yaml:"part_data_providers"`
	Rejected  []RejectedTool `yaml:"rejected"`
}

type ManifestMeta struct {
	Version                int    `yaml:"version"`
	Updated                string `yaml:"updated"`
	ResolvedAgainstNetwork bool   `yaml:"resolved_against_network"`
	ToolsDir               string `yaml:"tools_dir"`
}

type Defaults struct {
	ModePreference []string `yaml:"mode_preference"`
	Verify         Verify   `yaml:"verify"`
}

// Verify records what verification is possible for an artifact.
//
// `unavailable` is a first-class value, not an absence: it means upstream
// publishes nothing to check against, which is a fact about the world that
// must be visible rather than a config someone forgot to fill in.
type Verify struct {
	Checksum  string `yaml:"checksum"`  // required | preferred | unavailable
	Signature string `yaml:"signature"` // required | preferred | unavailable
}

// Tool is one engine.
// ReadTool is a third-party tool whose output we parse but never run.
type ReadTool struct {
	Tool       string `yaml:"tool"`
	License    string `yaml:"license"`
	Invocation string `yaml:"invocation"`
}

type Tool struct {
	ID       string   `yaml:"id"`
	Role     string   `yaml:"role"`
	Families []string `yaml:"families"`
	Upstream string   `yaml:"upstream"`
	License  string   `yaml:"license"`
	Version  string   `yaml:"version"`

	Container *Container `yaml:"container"`
	Binary    *Binary    `yaml:"binary"`
	Pip       *Pip       `yaml:"pip"`

	ContainerOnly       bool   `yaml:"container_only"`
	ContainerOnlyReason string `yaml:"container_only_reason"`

	Mode        string   `yaml:"mode"`
	SourceKinds []string `yaml:"source_kinds"`
	Produces    []string `yaml:"produces"`

	// ReadsOutputOf names third-party tools whose OUTPUT an internal engine
	// parses, without ever invoking, linking against or shipping them.
	//
	// ⚠ THE DISTINCTION IS THE WHOLE OF INVARIANT 9, SO IT IS DATA RATHER THAN
	// A COMMENT. `hbom-host-report` reads text produced by lshw, dmidecode and
	// fwupd — all copyleft — because the CUSTOMER ran them on their own
	// machine. Reading a tool's output carries no licence obligation, the same
	// reason a CSV exported from Altium is not an Altium derivative work.
	//
	// Recording it here means `toolctl licenses` can SHOW a legal reviewer the
	// boundary instead of leaving them to infer it from silence — and means the
	// next person cannot quietly promote one of these into a real dependency
	// without the audit noticing the licence.
	ReadsOutputOf []ReadTool `yaml:"reads_output_of"`

	NativeFormat      string   `yaml:"native_format"`
	AlsoEmits         []string `yaml:"also_emits"`
	EmitsIDNamespaces []string `yaml:"emits_id_namespaces"`
	IdentityKind      string   `yaml:"identity_kind"`

	DefaultWeight int      `yaml:"default_weight"`
	DBBacked      bool     `yaml:"db_backed"`
	DBRefresh     string   `yaml:"db_refresh"`
	RequiresEnv   []string `yaml:"requires_env"`
	RequiresVol   string   `yaml:"requires_volume"`

	Enabled  *bool `yaml:"enabled"`
	Optional bool  `yaml:"optional"`

	Verify          *Verify `yaml:"verify"`
	SupplyChainGap  string  `yaml:"supply_chain_gap"`
	UnpinnedReason  string  `yaml:"unpinned_reason"`
	DeferredReason  string  `yaml:"deferred_reason"`
	SecurityNote    string  `yaml:"security_note"`
	Notes           string  `yaml:"notes"`
	FirstRunMinutes []int   `yaml:"first_run_minutes"`
}

// IsEnabled defaults to true. A tool must be explicitly disabled.
func (t Tool) IsEnabled() bool { return t.Enabled == nil || *t.Enabled }

// EffectiveVerify returns the tool's verification policy, falling back to the
// manifest defaults.
func (t Tool) EffectiveVerify(d Defaults) Verify {
	if t.Verify != nil {
		return *t.Verify
	}
	return d.Verify
}

// HasSupplyChainGap reports whether upstream publishes nothing to verify.
func (t Tool) HasSupplyChainGap() bool { return strings.TrimSpace(t.SupplyChainGap) != "" }

type Container struct {
	Image       string `yaml:"image"`
	ImageTag    string `yaml:"image_tag"`
	ImageDigest string `yaml:"image_digest"`
}

// Ref returns the pull reference, preferring the digest.
//
// A tag is mutable: `image:0.74.0` can be repointed at different bytes after we
// pinned it. A digest cannot. Trivy's distribution channel was compromised
// twice in March 2026, which is the concrete reason this preference exists.
func (c Container) Ref() string {
	if c.ImageDigest != "" {
		return c.Image + "@" + c.ImageDigest
	}
	if c.ImageTag != "" {
		return c.Image + ":" + c.ImageTag
	}
	return c.Image
}

// PinnedByDigest reports whether the reference is immutable.
func (c Container) PinnedByDigest() bool { return c.ImageDigest != "" }

type Binary struct {
	URLTemplate  string            `yaml:"url_template"`
	Ext          map[string]string `yaml:"ext"`
	Exe          map[string]string `yaml:"exe"`
	OSTrivy      map[string]string `yaml:"os_trivy"`
	ChecksumFile string            `yaml:"checksum_file"`
	Signature    *Signature        `yaml:"signature"`
}

type Signature struct {
	Kind   string `yaml:"kind"` // cosign-keyless | sigstore-bundle
	Sig    string `yaml:"sig"`
	Cert   string `yaml:"cert"`
	Bundle string `yaml:"bundle"`
}

type Pip struct {
	Package       string `yaml:"package"`
	Version       string `yaml:"version"`
	Git           string `yaml:"git"`
	Ref           string `yaml:"ref"`
	RequireHashes bool   `yaml:"require_hashes"`
}

type Library struct {
	ID       string `yaml:"id"`
	Upstream string `yaml:"upstream"`
	License  string `yaml:"license"`
	Kind     string `yaml:"kind"`
	Version  string `yaml:"version"`
	UsedBy   string `yaml:"used_by"`
	Enabled  *bool  `yaml:"enabled"`
	Optional bool   `yaml:"optional"`
	Notes    string `yaml:"notes"`
}

type Service struct {
	ID             string      `yaml:"id"`
	Upstream       string      `yaml:"upstream"`
	License        string      `yaml:"license"`
	Kind           string      `yaml:"kind"`
	Version        string      `yaml:"version"`
	Enabled        *bool       `yaml:"enabled"`
	ComposeProfile string      `yaml:"compose_profile"`
	Containers     []Container `yaml:"containers"`
	MemoryMinGB    int         `yaml:"memory_min_gb"`
	MemoryRecGB    int         `yaml:"memory_recommended_gb"`
	Notes          string      `yaml:"notes"`
}

type Provider struct {
	ID          string   `yaml:"id"`
	Kind        string   `yaml:"kind"`
	BaseURL     string   `yaml:"base_url"`
	RequiresEnv []string `yaml:"requires_env"`
	Commercial  bool     `yaml:"commercial"`
	Default     bool     `yaml:"default"`
	Notes       string   `yaml:"notes"`
}

// RejectedTool is recorded so nobody re-adds it.
type RejectedTool struct {
	ID       string `yaml:"id"`
	Upstream string `yaml:"upstream"`
	License  string `yaml:"license"`
	Reason   string `yaml:"reason"`
}

// Load reads and parses the manifest.
func Load(path string) (*Manifest, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- repo-relative operator path
	if err != nil {
		return nil, fmt.Errorf("read manifest: %w", err)
	}
	var m Manifest
	if err := yaml.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("parse manifest: %w", err)
	}
	return &m, nil
}

// Tool looks up an engine by id.
func (m *Manifest) Tool(id string) (Tool, bool) {
	for _, t := range m.Tools {
		if t.ID == id {
			return t, true
		}
	}
	return Tool{}, false
}

// EnabledTools returns engines that are switched on, in manifest order.
func (m *Manifest) EnabledTools() []Tool {
	out := make([]Tool, 0, len(m.Tools))
	for _, t := range m.Tools {
		if t.IsEnabled() {
			out = append(out, t)
		}
	}
	return out
}

// ToolsForFamily returns enabled engines that can produce a BOM family.
func (m *Manifest) ToolsForFamily(family string) []Tool {
	var out []Tool
	for _, t := range m.EnabledTools() {
		for _, f := range t.Families {
			if f == family {
				out = append(out, t)
				break
			}
		}
	}
	return out
}

// CopyleftLicenses are licenses that must never be linked into an AxeBOM
// binary. CLAUDE.md invariant 9.
var CopyleftLicenses = map[string]bool{
	"GPL-2.0": true, "GPL-3.0": true, "GPL-2.0-only": true, "GPL-3.0-only": true,
	"GPL-2.0-or-later": true, "GPL-3.0-or-later": true,
	"AGPL-3.0": true, "AGPL-3.0-only": true, "AGPL-3.0-or-later": true,
}

// LicenseProblems returns tools or libraries whose license would contaminate
// an AxeBOM binary.
//
// Anything genuinely copyleft belongs in `rejected:` (invoked as a subprocess
// or not at all). Finding one in `tools:` or `libraries:` means somebody added
// a dependency without checking, which is how `django-bom` would have made
// hbom-worker a GPL derivative work.
func (m *Manifest) LicenseProblems() []string {
	var problems []string
	for _, t := range m.Tools {
		if CopyleftLicenses[t.License] {
			problems = append(problems, fmt.Sprintf(
				"tool %q is %s — copyleft must be in `rejected:` and invoked out-of-process, "+
					"never linked (CLAUDE.md invariant 9)", t.ID, t.License))
		}
	}
	for _, l := range m.Libraries {
		if CopyleftLicenses[l.License] {
			problems = append(problems, fmt.Sprintf(
				"library %q is %s — a library IS linked; this would relicense our binary",
				l.ID, l.License))
		}
	}
	sort.Strings(problems)
	return problems
}

// hostOS maps Go's GOOS to the token upstream release assets use.
func hostOS() string {
	switch runtime.GOOS {
	case "windows":
		return "windows"
	case "darwin":
		return "darwin"
	default:
		return "linux"
	}
}

// hostArch maps GOARCH to the token upstream release assets use.
func hostArch() string {
	switch runtime.GOARCH {
	case "arm64":
		return "arm64"
	default:
		return "amd64"
	}
}
