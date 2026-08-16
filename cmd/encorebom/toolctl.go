package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"

	"github.com/encorebom/encorebom/libs/go-shared/toolctl"
)

const defaultManifestPath = "OSINT/tools.manifest.yaml"

func runToolctl(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: encorebom toolctl <list|dryrun|sync|verify|licenses> [flags]")
	}
	switch args[0] {
	case "list":
		return toolctlList(args[1:])
	case "dryrun":
		return toolctlDryRun(ctx, args[1:])
	case "sync":
		return toolctlSync(ctx, args[1:])
	case "verify":
		return toolctlVerify(args[1:])
	case "licenses":
		return toolctlLicenses(args[1:])
	default:
		return fmt.Errorf("unknown toolctl subcommand %q", args[0])
	}
}

func loadManifest(path string) (*toolctl.Manifest, error) {
	return toolctl.Load(resolveFromRepoRoot(path))
}

func manifestFlag(fs *flag.FlagSet) *string {
	return fs.String("manifest", defaultManifestPath, "path to tools.manifest.yaml")
}

// ---------------------------------------------------------------------------
// list
// ---------------------------------------------------------------------------

func toolctlList(args []string) error {
	fs := flag.NewFlagSet("toolctl list", flag.ExitOnError)
	path := manifestFlag(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	m, err := loadManifest(*path)
	if err != nil {
		return err
	}

	fmt.Printf("manifest v%d, updated %s, resolved against network: %v\n\n",
		m.Meta.Version, m.Meta.Updated, m.Meta.ResolvedAgainstNetwork)

	fmt.Printf("  %-20s %-10s %-12s %-9s %s\n", "ENGINE", "VERSION", "FAMILIES", "MODE", "NOTE")
	for _, t := range m.Tools {
		r := toolctl.Resolve(t, m.Defaults)
		note := ""
		switch {
		case !t.IsEnabled():
			note = "disabled"
		case t.HasSupplyChainGap():
			note = "⚠ unverifiable artifact"
		case r.Mode == toolctl.ModeContainer && !r.PinnedByDigest:
			note = "tag-pinned (run `toolctl pin`)"
		}
		fmt.Printf("  %-20s %-10s %-12s %-9s %s\n",
			t.ID, t.Version, strings.Join(t.Families, ","), r.Mode, note)
	}

	if len(m.Rejected) > 0 {
		fmt.Printf("\nDeliberately NOT used (%d):\n", len(m.Rejected))
		for _, r := range m.Rejected {
			lic := r.License
			if lic == "" {
				lic = "—"
			}
			fmt.Printf("  %-16s %-10s %s\n", r.ID, lic, firstLine(r.Reason))
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// dryrun — the Phase 2 acceptance criterion
// ---------------------------------------------------------------------------

// toolctlDryRun resolves every pinned URL and probes it, WITHOUT downloading.
//
// This is what proves the manifest describes reality rather than a plausible
// guess. Every version in the Phase 0 manifest was stale by many releases, and
// nothing but a network probe would have revealed that.
func toolctlDryRun(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("toolctl dryrun", flag.ExitOnError)
	path := manifestFlag(fs)
	// Container is preferred for almost every engine, so without this the dry
	// run never probes a binary URL and proves nothing about the templates.
	forceMode := fs.String("force-mode", "", "force a mode (binary|container) to exercise that path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	var override []string
	if *forceMode != "" {
		override = []string{*forceMode}
	}
	m, err := loadManifest(*path)
	if err != nil {
		return err
	}

	type result struct {
		tool     toolctl.Tool
		res      toolctl.Resolution
		statuses []toolctl.URLStatus
	}

	resolutions := m.ResolveAll(override)

	// Probe concurrently but bounded — a burst of parallel requests to one
	// host invites rate limiting, which would look like a broken manifest.
	results := make([]result, len(m.Tools))
	sem := make(chan struct{}, 4)
	var wg sync.WaitGroup
	for i := range m.Tools {
		results[i] = result{tool: m.Tools[i], res: resolutions[i]}
		if resolutions[i].Mode != toolctl.ModeBinary {
			continue
		}
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			results[i].statuses = toolctl.ProbeResolution(ctx, resolutions[i])
		}(i)
	}
	wg.Wait()

	var failures, warnings int

	fmt.Printf("Dry run — resolving %d engines without downloading\n\n", len(m.Tools))

	for _, r := range results {
		fmt.Printf("── %s %s  (%s)\n", r.tool.ID, r.tool.Version, r.res.Mode)

		switch r.res.Mode {
		case toolctl.ModeInternal:
			fmt.Printf("     internal engine — nothing to fetch\n")
		case toolctl.ModeUnavailable:
			fmt.Printf("     unavailable: %s\n", firstLine(r.res.Reason))
		case toolctl.ModeContainer:
			fmt.Printf("     image  %s\n", r.res.ImageRef)
			if !r.res.PinnedByDigest {
				warnings++
			}
		case toolctl.ModePip:
			fmt.Printf("     pip    %s\n", r.res.PipSpec)
		case toolctl.ModeBinary:
			for _, s := range r.statuses {
				mark := "ok  "
				if !s.OK() {
					mark = "FAIL"
					failures++
				}
				detail := fmt.Sprintf("HTTP %d", s.Status)
				if s.Err != nil {
					detail = s.Err.Error()
				} else if s.Size > 0 {
					detail = fmt.Sprintf("HTTP %d, %s", s.Status, humanBytes(s.Size))
				}
				fmt.Printf("     %s %-12s %s\n", mark, s.Label, detail)
				if !s.OK() {
					fmt.Printf("          %s\n", s.URL)
				}
			}
		}

		for _, w := range r.res.Warnings {
			warnings++
			fmt.Printf("     ⚠ %s\n", wrapIndent(w, 8))
		}
		fmt.Println()
	}

	fmt.Printf("%d engine(s): %d URL failure(s), %d warning(s)\n",
		len(m.Tools), failures, warnings)

	if failures > 0 {
		return fmt.Errorf("%d pinned URL(s) did not resolve — the manifest does not "+
			"describe reality. Check the version and the asset naming upstream", failures)
	}
	fmt.Println("\nEvery pinned URL resolves.")
	return nil
}

// ---------------------------------------------------------------------------
// sync
// ---------------------------------------------------------------------------

func toolctlSync(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("toolctl sync", flag.ExitOnError)
	path := manifestFlag(fs)
	only := fs.String("only", "", "sync a single engine by id")
	if err := fs.Parse(args); err != nil {
		return err
	}
	m, err := loadManifest(*path)
	if err != nil {
		return err
	}

	root, err := findRepoRoot()
	if err != nil {
		return err
	}
	toolsDir := m.Meta.ToolsDir
	if toolsDir == "" {
		toolsDir = ".encorebom/tools"
	}

	cosignAvailable := haveCosign(ctx)
	if !cosignAvailable {
		// ADR-0002: degrade to checksum-only, but LOUDLY. A silent degradation
		// is how a supply-chain control stops being one.
		fmt.Fprintln(os.Stderr,
			"\n⚠ cosign is not installed. Signature verification is SKIPPED; artifacts\n"+
				"  are verified by checksum only. That is a real reduction in supply-chain\n"+
				"  assurance — Trivy's channel was compromised twice in March 2026.\n"+
				"  Install: go install github.com/sigstore/cosign/v2/cmd/cosign@latest")
	}

	var installed, skipped, failed int

	for _, t := range m.Tools {
		if *only != "" && t.ID != *only {
			continue
		}
		r := toolctl.Resolve(t, m.Defaults)

		switch r.Mode {
		case toolctl.ModeInternal, toolctl.ModeUnavailable, toolctl.ModeContainer, toolctl.ModePip:
			// Containers are pulled by the sandbox at run time; pip packages are
			// installed into the worker image. Neither is fetched here.
			skipped++
			continue
		}

		for _, w := range r.Warnings {
			fmt.Fprintf(os.Stderr, "⚠ %s: %s\n", t.ID, firstLine(w))
		}

		dest := filepath.Join(root, toolsDir, t.ID, t.Version, baseName(r.URL))
		fmt.Printf("→ %s %s\n", t.ID, t.Version)

		sum, err := toolctl.Download(ctx, r.URL, dest)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  FAILED: %v\n", err)
			failed++
			continue
		}

		if r.ChecksumURL == "" {
			if r.Verify.Checksum == "required" {
				fmt.Fprintf(os.Stderr,
					"  FAILED: checksum is REQUIRED but no checksum file is published\n")
				_ = os.Remove(dest)
				failed++
				continue
			}
			fmt.Printf("  installed (UNVERIFIED — no checksum published) sha256=%s\n", sum[:16])
			installed++
			continue
		}

		published, err := toolctl.FetchChecksums(ctx, r.ChecksumURL)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  FAILED: %v\n", err)
			_ = os.Remove(dest)
			failed++
			continue
		}
		if err := toolctl.VerifyChecksum(r.URL, sum, published); err != nil {
			// Remove the artifact: leaving a failed download on disk means the
			// next run might treat it as cached and good.
			_ = os.Remove(dest)
			fmt.Fprintf(os.Stderr, "  %v\n", err)
			failed++
			continue
		}

		fmt.Printf("  installed, checksum verified\n")
		installed++
	}

	fmt.Printf("\n%d installed, %d skipped (container/pip/internal), %d failed\n",
		installed, skipped, failed)
	if failed > 0 {
		return fmt.Errorf("%d engine(s) failed to install", failed)
	}
	return nil
}

// ---------------------------------------------------------------------------
// verify — availability probe
// ---------------------------------------------------------------------------

func toolctlVerify(args []string) error {
	fs := flag.NewFlagSet("toolctl verify", flag.ExitOnError)
	path := manifestFlag(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	m, err := loadManifest(*path)
	if err != nil {
		return err
	}

	fmt.Printf("Engine availability on this host (%s)\n\n", hostLabel())

	var available, unavailable int
	for _, t := range m.Tools {
		r := toolctl.Resolve(t, m.Defaults)
		status := "available"
		detail := string(r.Mode)

		switch r.Mode {
		case toolctl.ModeUnavailable:
			status = "UNAVAILABLE"
			detail = firstLine(r.Reason)
			unavailable++
		case toolctl.ModeContainer:
			detail = "container " + r.ImageRef
			available++
		case toolctl.ModeBinary:
			detail = "binary " + baseName(r.URL)
			available++
		case toolctl.ModePip:
			detail = "pip " + r.PipSpec
			available++
		case toolctl.ModeInternal:
			detail = "internal"
			available++
		}
		fmt.Printf("  %-12s %-20s %s\n", status, t.ID, detail)
	}

	fmt.Printf("\n%d available, %d unavailable\n", available, unavailable)
	fmt.Println("\nAn unavailable engine is NOT an error: it is recorded in every report's")
	fmt.Println("Engine Coverage section, so lost coverage is visible rather than silent.")
	return nil
}

// ---------------------------------------------------------------------------
// licenses
// ---------------------------------------------------------------------------

// toolctlLicenses fails if a copyleft dependency would be linked into an
// EncoreBOM binary. CLAUDE.md invariant 9.
func toolctlLicenses(args []string) error {
	fs := flag.NewFlagSet("toolctl licenses", flag.ExitOnError)
	path := manifestFlag(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	m, err := loadManifest(*path)
	if err != nil {
		return err
	}

	seen := map[string][]string{}
	for _, t := range m.Tools {
		seen[t.License] = append(seen[t.License], t.ID)
	}
	for _, l := range m.Libraries {
		seen[l.License] = append(seen[l.License], l.ID+" (library)")
	}

	fmt.Println("Licenses across pinned tools and libraries:")
	fmt.Println()
	for _, lic := range sortedKeys(seen) {
		fmt.Printf("  %-14s %s\n", lic, strings.Join(seen[lic], ", "))
	}

	problems := m.LicenseProblems()
	if len(problems) > 0 {
		fmt.Fprintln(os.Stderr)
		for _, p := range problems {
			fmt.Fprintf(os.Stderr, "  ✗ %s\n", p)
		}
		return fmt.Errorf("%d copyleft dependency problem(s)", len(problems))
	}

	fmt.Printf("\nNo copyleft dependency is linked into an EncoreBOM binary.\n")
	if len(m.Rejected) > 0 {
		fmt.Printf("%d tool(s) are deliberately rejected — see `toolctl list`.\n", len(m.Rejected))
	}
	return nil
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func sortedKeys(m map[string][]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return strings.TrimSpace(s[:i])
	}
	return s
}

func wrapIndent(s string, indent int) string {
	s = strings.Join(strings.Fields(s), " ")
	const width = 68
	if len(s) <= width {
		return s
	}
	var b strings.Builder
	pad := strings.Repeat(" ", indent)
	for len(s) > width {
		cut := strings.LastIndex(s[:width], " ")
		if cut <= 0 {
			cut = width
		}
		b.WriteString(s[:cut])
		b.WriteString("\n" + pad)
		s = strings.TrimSpace(s[cut:])
	}
	b.WriteString(s)
	return b.String()
}

func humanBytes(n int64) string {
	switch {
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.0f KB", float64(n)/(1<<10))
	default:
		return fmt.Sprintf("%d B", n)
	}
}

// baseName returns the filename portion of a URL. Deliberately path.Base, not
// filepath.Base: a URL always uses forward slashes, and filepath.Base on
// Windows would treat a backslash as a separator.
func baseName(rawURL string) string {
	if i := strings.IndexAny(rawURL, "?#"); i >= 0 {
		rawURL = rawURL[:i]
	}
	return path.Base(rawURL)
}

// haveCosign reports whether signature verification is possible.
//
// Its absence degrades sync to checksum-only, which is a real reduction in
// assurance and is therefore warned about rather than silently accepted.
func haveCosign(ctx context.Context) bool {
	cmd := exec.CommandContext(ctx, "cosign", "version")
	return cmd.Run() == nil
}

func hostLabel() string { return runtime.GOOS + "/" + runtime.GOARCH }
