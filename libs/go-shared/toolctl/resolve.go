package toolctl

import (
	"fmt"
	"strings"
)

// URL-template resolution and engine mode selection.
//
// The templates are deliberately data rather than code: every upstream project
// names its release assets differently, and encoding those differences as
// per-tool Go functions would mean a code change every time a tool is added.
// Trivy alone needs `Linux-64bit` / `macOS-64bit` / `windows-64bit`, which is
// inconsistent even within one project.

// Mode is how an engine will be executed.
type Mode string

const (
	ModeContainer   Mode = "container"
	ModeBinary      Mode = "binary"
	ModePip         Mode = "pip"
	ModeInternal    Mode = "internal"
	ModeUnavailable Mode = "unavailable"
)

// Resolution is the decision for one engine on this host.
type Resolution struct {
	ToolID  string
	Mode    Mode
	Version string

	// Container
	ImageRef       string
	PinnedByDigest bool

	// Binary
	URL          string
	ChecksumURL  string
	SignatureURL string
	CertURL      string
	BundleURL    string

	// Pip
	PipSpec string

	Verify Verify

	// Reason is set when Mode is ModeUnavailable, and is what the report's
	// Engine Coverage section shows the customer.
	Reason string

	// Warnings are non-fatal but must be surfaced on every sync. An
	// unverifiable artifact that nobody mentions is the failure this whole
	// package exists to prevent.
	Warnings []string
}

// Resolve decides how to obtain a tool on this host.
//
// Order is container -> binary -> pip -> unavailable, honouring the manifest's
// mode_preference. `unavailable` is a legitimate outcome, not an error: a
// missing engine costs that engine's coverage, visibly, never the whole scan.
func Resolve(t Tool, d Defaults) Resolution {
	return ResolveWithPreference(t, d, nil)
}

// ResolveWithPreference resolves with an overridden mode preference.
//
// Exists so `toolctl dryrun --force-mode binary` can exercise the URL
// TEMPLATES. Without it the dry run silently proves nothing about them:
// container is preferred for almost every tool, so the binary paths — the part
// most likely to be wrong, since every project names its assets differently —
// would never be probed.
func ResolveWithPreference(t Tool, d Defaults, override []string) Resolution {
	if len(override) > 0 {
		d.ModePreference = override
	}
	return resolve(t, d, len(override) > 0)
}

func resolve(t Tool, d Defaults, forced bool) Resolution {
	r := Resolution{
		ToolID:  t.ID,
		Version: t.Version,
		Verify:  t.EffectiveVerify(d),
	}

	if !t.IsEnabled() {
		r.Mode = ModeUnavailable
		r.Reason = firstNonEmpty(t.DeferredReason, "disabled in the manifest")
		return r
	}

	// Internal engines (HBOM import/form) have no artifact to fetch.
	if t.Upstream == "internal" {
		r.Mode = ModeInternal
		return r
	}

	if t.HasSupplyChainGap() {
		r.Warnings = append(r.Warnings, strings.TrimSpace(t.SupplyChainGap))
	}
	if t.UnpinnedReason != "" {
		r.Warnings = append(r.Warnings, strings.TrimSpace(t.UnpinnedReason))
	}

	prefs := d.ModePreference
	if len(prefs) == 0 {
		prefs = []string{"container", "binary"}
	}
	// A container-only tool must never fall through to a binary path that does
	// not exist — Java tools in particular, where the host JDK is 1.8. This
	// holds even under --force-mode: there is genuinely no binary to fetch.
	if t.ContainerOnly {
		prefs = []string{"container"}
	}

	// Under a forced mode, a tool that cannot satisfy it is reported as
	// unavailable rather than silently falling back — the point of forcing is
	// to test one specific path.
	if forced {
		r2, ok := tryModes(t, prefs, &r)
		if ok {
			return r2
		}
		r.Mode = ModeUnavailable
		r.Reason = fmt.Sprintf("no %s artifact declared for this engine", strings.Join(prefs, "/"))
		return r
	}

	if r2, ok := tryModes(t, prefs, &r); ok {
		return r2
	}

	// pip is not part of mode_preference; it is a distinct distribution channel.
	if t.Pip != nil {
		r.Mode = ModePip
		r.PipSpec = pipSpec(*t.Pip)
		return r
	}

	r.Mode = ModeUnavailable
	if t.ContainerOnly {
		r.Reason = firstNonEmpty(t.ContainerOnlyReason,
			"container-only, but no container image is declared")
	} else {
		r.Reason = "no container image, binary URL or pip package declared"
	}
	return r
}

// tryModes attempts each preferred mode in order.
func tryModes(t Tool, prefs []string, r *Resolution) (Resolution, bool) {
	for _, pref := range prefs {
		switch pref {
		case "container":
			if t.Container != nil && t.Container.Image != "" {
				r.Mode = ModeContainer
				r.ImageRef = t.Container.Ref()
				r.PinnedByDigest = t.Container.PinnedByDigest()
				if !r.PinnedByDigest {
					r.Warnings = append(r.Warnings,
						"image is pinned by TAG, not digest — a tag is mutable and can be "+
							"repointed at different bytes after pinning. Run `toolctl pin`.")
				}
				return *r, true
			}
		case "binary":
			if t.Binary != nil && t.Binary.URLTemplate != "" {
				r.Mode = ModeBinary
				r.URL = expand(t.Binary.URLTemplate, t)
				if t.Binary.ChecksumFile != "" {
					r.ChecksumURL = expand(t.Binary.ChecksumFile, t)
				}
				if s := t.Binary.Signature; s != nil {
					r.SignatureURL = expandRef(s.Sig, r.ChecksumURL, t)
					r.CertURL = expandRef(s.Cert, r.ChecksumURL, t)
					r.BundleURL = expandRef(s.Bundle, r.ChecksumURL, t)
				}
				return *r, true
			}
		}
	}
	return Resolution{}, false
}

// expand fills a URL template from the tool's version and this host's platform.
func expand(tmpl string, t Tool) string {
	osTok, archTok := hostOS(), hostArch()

	repl := []string{
		"{version}", t.Version,
		"{os}", osTok,
		"{arch}", archTok,
	}

	if t.Binary != nil {
		// Trivy uses its own OS tokens (Linux-64bit / macOS-64bit /
		// windows-64bit) rather than GOOS values.
		if v, ok := t.Binary.OSTrivy[osTok]; ok {
			repl = append(repl, "{os_trivy}", v)
		}
		if v, ok := t.Binary.Ext[osTok]; ok {
			repl = append(repl, "{ext}", v)
		}
		// Bare-binary tools (osv-scanner) need ".exe" on Windows and "" elsewhere.
		if v, ok := t.Binary.Exe[osTok]; ok {
			repl = append(repl, "{exe}", v)
		} else if strings.Contains(tmpl, "{exe}") {
			repl = append(repl, "{exe}", "")
		}
	}

	return strings.NewReplacer(repl...).Replace(tmpl)
}

// expandRef resolves a signature template, which may reference the checksum
// file as "{checksum_file}.sig".
func expandRef(tmpl, checksumURL string, t Tool) string {
	if tmpl == "" {
		return ""
	}
	tmpl = strings.ReplaceAll(tmpl, "{checksum_file}", checksumURL)
	return expand(tmpl, t)
}

func pipSpec(p Pip) string {
	switch {
	case p.Git != "" && p.Ref != "":
		return fmt.Sprintf("git+%s@%s", p.Git, p.Ref)
	case p.Git != "":
		// No tag and no resolved commit: not reproducible. The manifest's
		// unpinned_reason explains it and the warning surfaces on every sync.
		return fmt.Sprintf("git+%s", p.Git)
	case p.Version != "":
		return fmt.Sprintf("%s==%s", p.Package, p.Version)
	default:
		return p.Package
	}
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// ResolveAll resolves every tool, optionally forcing a mode.
func (m *Manifest) ResolveAll(override []string) []Resolution {
	out := make([]Resolution, 0, len(m.Tools))
	for _, t := range m.Tools {
		out = append(out, ResolveWithPreference(t, m.Defaults, override))
	}
	return out
}
