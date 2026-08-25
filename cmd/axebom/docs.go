package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// `axebom docs lint` fails on broken relative links between specification
// documents.
//
// This matters more than ordinary doc hygiene: every phase file opens with a
// "Read first" list, and a session that cannot resolve one of those paths
// starts without a contract it was told to honour. A dangling link is therefore
// a build-correctness problem, not a typo.

var (
	// Markdown links: [text](path)
	mdLink = regexp.MustCompile(`\[[^\]]*\]\(([^)#\s]+)(?:#[^)]*)?\)`)
	// Backticked repo paths: `docs/01-DATA-MODEL.md`, `OSINT/tools.manifest.yaml`
	backtickPath = regexp.MustCompile("`((?:docs|OSINT|deploy|libs|services|workers|proto|fixtures|cmd|tools)/[A-Za-z0-9._/-]+\\.[A-Za-z0-9]+)`")
)

func runDocs(ctx context.Context, args []string) error {
	if len(args) == 0 || args[0] != "lint" {
		return fmt.Errorf("usage: axebom docs lint [dir]")
	}
	fs := flag.NewFlagSet("docs lint", flag.ExitOnError)
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}

	root := "docs"
	if fs.NArg() > 0 {
		root = fs.Arg(0)
	}

	repoRoot, err := findRepoRoot()
	if err != nil {
		return err
	}

	forward, err := loadForwardRefs(filepath.Join(repoRoot, "docs", ".forward-refs"))
	if err != nil {
		return err
	}

	type problem struct{ file, link, why string }
	var problems []problem
	var checked, deferred int

	walk := func(path string, isDir bool) error {
		if isDir || !strings.HasSuffix(path, ".md") {
			return nil
		}
		// #nosec G304 -- path comes from filepath.Walk over the repo's docs/
		// tree, not from user input.
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		text := string(data)
		rel, _ := filepath.Rel(repoRoot, path)

		targets := map[string]bool{}
		for _, m := range mdLink.FindAllStringSubmatch(text, -1) {
			t := m[1]
			// Skip external links and mailto.
			if strings.HasPrefix(t, "http://") || strings.HasPrefix(t, "https://") ||
				strings.HasPrefix(t, "mailto:") {
				continue
			}
			targets[t] = true
		}
		for _, m := range backtickPath.FindAllStringSubmatch(text, -1) {
			targets[m[1]] = true
		}

		for t := range targets {
			checked++
			if forward[filepath.ToSlash(t)] {
				// A later phase creates this. Declared in docs/.forward-refs.
				deferred++
				continue
			}
			// Try: relative to the file, then relative to the repo root.
			candidates := []string{
				filepath.Join(filepath.Dir(path), t),
				filepath.Join(repoRoot, t),
				filepath.Join(repoRoot, "docs", t),
			}
			found := false
			for _, c := range candidates {
				if _, err := os.Stat(c); err == nil {
					found = true
					break
				}
			}
			if !found {
				problems = append(problems, problem{file: rel, link: t,
					why: "no such file relative to the document, the repo root, or docs/; " +
						"if a later phase creates it, declare it in docs/.forward-refs"})
			}
		}
		return nil
	}

	if err := filepath.Walk(filepath.Join(repoRoot, root),
		func(p string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			return walk(p, info.IsDir())
		}); err != nil {
		return err
	}

	sort.Slice(problems, func(i, j int) bool {
		if problems[i].file != problems[j].file {
			return problems[i].file < problems[j].file
		}
		return problems[i].link < problems[j].link
	})

	if len(problems) > 0 {
		for _, p := range problems {
			fmt.Fprintf(os.Stderr, "  %s -> %s\n      %s\n", p.file, p.link, p.why)
		}
		return fmt.Errorf("%d broken reference(s) across %d checked", len(problems), checked)
	}

	fmt.Printf("docs lint: %d references checked, all resolve", checked)
	if deferred > 0 {
		fmt.Printf(" (%d forward refs deferred per docs/.forward-refs)", deferred)
	}
	fmt.Println()
	return nil
}

// loadForwardRefs reads paths that a later phase creates.
//
// Without this, a specification that correctly names a file its phase will
// produce reads as a broken link — and the obvious "fix" is to delete the
// reference, which loses information. Declaring them explicitly keeps the
// reference AND keeps the linter honest about everything else.
func loadForwardRefs(path string) (map[string]bool, error) {
	out := map[string]bool{}
	// #nosec G304 -- fixed path under the repo root.
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return out, nil // optional file
		}
		return nil, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		if i := strings.Index(line, "#"); i >= 0 {
			line = line[:i]
		}
		if p := strings.TrimSpace(line); p != "" {
			out[filepath.ToSlash(p)] = true
		}
	}
	return out, nil
}

// findRepoRoot walks up looking for go.mod so the command works from any
// subdirectory.
func findRepoRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("not inside a Go module (no go.mod found walking up from cwd)")
		}
		dir = parent
	}
}
