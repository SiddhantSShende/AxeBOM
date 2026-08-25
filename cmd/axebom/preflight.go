package main

import (
	"context"
	"flag"
	"fmt"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
)

// Preflight reports what is installed and — more usefully — what is missing and
// why it matters. It is deliberately non-fatal on optional tooling: it tells you
// what you lose, rather than refusing to run.
//
// Three checks here exist because of specific traps on the primary dev machine,
// documented in docs/08-OPERATIONS.md §1:
//
//   - Java 1.8. Dependency-Check needs 11+, cbomkit needs 17+. Not a blocker,
//     because those tools are container-only by design (ADR-0002).
//   - Docker daemon stopped. Both WSL2 distros idle to Stopped.
//   - core.autocrlf=true, set by the Git for Windows installer at SYSTEM level.
//     This silently rewrites line endings and corrupts golden files, producing
//     normalizer test failures that look like code bugs.

type checkResult struct {
	name     string
	found    bool
	version  string
	detail   string
	severity severity
	fix      string
}

type severity int

const (
	sevOK severity = iota
	sevInfo
	sevWarn
	sevBlock
)

func (s severity) label() string {
	switch s {
	case sevOK:
		return "ok"
	case sevInfo:
		return "info"
	case sevWarn:
		return "warn"
	default:
		return "BLOCK"
	}
}

func runPreflight(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("preflight", flag.ExitOnError)
	quiet := fs.Bool("quiet", false, "only print problems")
	if err := fs.Parse(args); err != nil {
		return err
	}

	results := []checkResult{
		checkGo(ctx),
		checkNode(ctx),
		checkPython(ctx),
		checkGit(ctx),
		checkAutoCRLF(ctx),
		checkDocker(ctx),
		checkJava(ctx),
		checkTask(ctx),
		checkGolangciLint(ctx),
		checkCosign(ctx),
	}
	if runtime.GOOS == "windows" {
		results = append(results, checkWSL(ctx))
	}

	fmt.Printf("AxeBOM preflight  (%s/%s)\n\n", runtime.GOOS, runtime.GOARCH)

	var blockers, warnings int
	for _, r := range results {
		if r.severity == sevBlock {
			blockers++
		}
		if r.severity == sevWarn {
			warnings++
		}
		if *quiet && r.severity == sevOK {
			continue
		}

		status := r.version
		if !r.found {
			status = "not found"
		}
		fmt.Printf("  %-5s %-16s %s\n", r.severity.label(), r.name, status)
		if r.detail != "" {
			fmt.Printf("        %s\n", r.detail)
		}
		if r.fix != "" {
			fmt.Printf("        fix: %s\n", r.fix)
		}
	}

	fmt.Println()
	switch {
	case blockers > 0:
		fmt.Printf("%d blocker(s), %d warning(s). Resolve blockers before `task dev`.\n", blockers, warnings)
		return fmt.Errorf("preflight found %d blocker(s)", blockers)
	case warnings > 0:
		fmt.Printf("%d warning(s). The stack will run; some capability is reduced.\n", warnings)
	default:
		fmt.Println("All checks passed.")
	}
	return nil
}

// --- individual checks -----------------------------------------------------

func checkGo(ctx context.Context) checkResult {
	out, err := run(ctx, "go", "version")
	if err != nil {
		return checkResult{name: "go", severity: sevBlock,
			detail: "required to build services",
			fix:    "install Go 1.24+ from https://go.dev/dl/"}
	}
	v := extract(out, `go(\d+\.\d+(?:\.\d+)?)`)
	r := checkResult{name: "go", found: true, version: v}
	if !atLeast(v, 1, 24) {
		r.severity = sevBlock
		r.detail = "Go 1.24+ required"
		r.fix = "upgrade from https://go.dev/dl/"
	}
	return r
}

func checkNode(ctx context.Context) checkResult {
	out, err := run(ctx, "node", "--version")
	if err != nil {
		return checkResult{name: "node", severity: sevWarn,
			detail: "frontend cannot be built",
			fix:    "install Node 20+ from https://nodejs.org/"}
	}
	v := strings.TrimPrefix(strings.TrimSpace(out), "v")
	r := checkResult{name: "node", found: true, version: v}
	if !atLeast(v, 20, 0) {
		r.severity = sevWarn
		r.detail = "Node 20+ required for the frontend"
	}
	return r
}

func checkPython(ctx context.Context) checkResult {
	for _, bin := range []string{"python", "python3", "py"} {
		out, err := run(ctx, bin, "--version")
		if err != nil {
			continue
		}
		v := extract(out, `Python (\d+\.\d+(?:\.\d+)?)`)
		if v == "" {
			continue
		}
		r := checkResult{name: "python", found: true, version: v}
		if !atLeast(v, 3, 11) {
			r.severity = sevWarn
			r.detail = "Python 3.11+ required for scan workers"
		}
		return r
	}
	return checkResult{name: "python", severity: sevWarn,
		detail: "scan workers cannot run",
		fix:    "install Python 3.11+ from https://python.org/"}
}

func checkGit(ctx context.Context) checkResult {
	out, err := run(ctx, "git", "--version")
	if err != nil {
		return checkResult{name: "git", severity: sevBlock,
			detail: "required to fetch scan sources",
			fix:    "install git"}
	}
	return checkResult{name: "git", found: true, version: extract(out, `git version (\S+)`)}
}

// checkAutoCRLF guards the golden-file corruption trap.
//
// Git for Windows sets core.autocrlf=true at SYSTEM level during installation.
// With it on, checking out a .golden file rewrites LF to CRLF, every normalizer
// golden test fails, and the failure looks like a code bug rather than a
// configuration one. .gitattributes mitigates it, but a repo-local `false` is
// the belt to that braces.
func checkAutoCRLF(ctx context.Context) checkResult {
	out, err := run(ctx, "git", "config", "--get", "core.autocrlf")
	value := strings.TrimSpace(out)
	if err != nil || value == "" {
		return checkResult{name: "core.autocrlf", found: true, version: "unset",
			severity: sevOK, detail: ".gitattributes governs line endings"}
	}
	if strings.EqualFold(value, "true") {
		return checkResult{name: "core.autocrlf", found: true, version: value,
			severity: sevBlock,
			detail:   "will rewrite line endings and CORRUPT GOLDEN FILES; normalizer tests will fail for reasons unrelated to the code",
			fix:      "git config core.autocrlf false   (run inside this repo)"}
	}
	return checkResult{name: "core.autocrlf", found: true, version: value, severity: sevOK}
}

func checkDocker(ctx context.Context) checkResult {
	if _, err := run(ctx, "docker", "--version"); err != nil {
		return checkResult{name: "docker", severity: sevBlock,
			detail: "required for the local stack and for every container-only scanner",
			fix:    "install Docker Desktop and enable the WSL2 backend"}
	}
	// `docker info` fails when the CLI is present but the daemon is not running,
	// which is the common state on this machine.
	if _, err := run(ctx, "docker", "info", "--format", "{{.ServerVersion}}"); err != nil {
		return checkResult{name: "docker", found: true, version: "daemon unreachable",
			severity: sevBlock,
			detail:   "CLI present but the daemon is not running",
			fix:      "start Docker Desktop, or: wsl -d docker-desktop"}
	}
	out, _ := run(ctx, "docker", "info", "--format", "{{.ServerVersion}}")
	return checkResult{name: "docker", found: true, version: strings.TrimSpace(out)}
}

// checkJava is informational by design.
//
// Java 1.8 on this machine is too old for Dependency-Check (11+) and cbomkit
// (17+), but that is not a blocker: ADR-0002 runs every Java tool
// container-only, precisely so the host JDK never matters.
func checkJava(ctx context.Context) checkResult {
	out, err := run(ctx, "java", "-version")
	if err != nil {
		return checkResult{name: "java", found: false, severity: sevInfo,
			detail: "not required — all Java-based scanners run container-only (ADR-0002)"}
	}
	v := extract(out, `version "([^"]+)"`)
	r := checkResult{name: "java", found: true, version: v, severity: sevInfo,
		detail: "not used directly — Java scanners run container-only (ADR-0002)"}
	if strings.HasPrefix(v, "1.8") || strings.HasPrefix(v, "8.") {
		r.detail = "1.8 is too old for Dependency-Check (11+) and cbomkit (17+), " +
			"but neither is installed locally — both run container-only (ADR-0002)"
	}
	return r
}

func checkTask(ctx context.Context) checkResult {
	out, err := run(ctx, "task", "--version")
	if err != nil {
		return checkResult{name: "task", severity: sevWarn,
			detail: "Taskfile.yml targets cannot be run; invoke go/npm directly meanwhile",
			fix:    "winget install Task.Task   |   go install github.com/go-task/task/v3/cmd/task@latest"}
	}
	return checkResult{name: "task", found: true, version: strings.TrimSpace(out)}
}

func checkGolangciLint(ctx context.Context) checkResult {
	out, err := run(ctx, "golangci-lint", "--version")
	if err != nil {
		return checkResult{name: "golangci-lint", severity: sevWarn,
			detail: "lint and the import-boundary guard cannot run locally (CI still enforces them)",
			fix:    "go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest"}
	}
	return checkResult{name: "golangci-lint", found: true,
		version: extract(out, `version v?(\S+)`)}
}

// checkCosign is a warning, never a silent degradation.
//
// ADR-0002: without cosign, scanner-artifact verification falls back to
// checksum-only. That is a real reduction in supply-chain assurance — Trivy's
// distribution channel was compromised twice in March 2026 — so it must be
// visible rather than quietly accepted.
func checkCosign(ctx context.Context) checkResult {
	out, err := run(ctx, "cosign", "version")
	if err != nil {
		return checkResult{name: "cosign", severity: sevWarn,
			detail: "scanner-artifact signature verification degrades to checksum-only",
			fix:    "go install github.com/sigstore/cosign/v2/cmd/cosign@latest"}
	}
	return checkResult{name: "cosign", found: true, version: extract(out, `GitVersion:\s*(\S+)`)}
}

func checkWSL(ctx context.Context) checkResult {
	out, err := run(ctx, "wsl", "-l", "-v")
	if err != nil {
		return checkResult{name: "wsl2", severity: sevWarn,
			detail: "Docker Desktop's WSL2 backend is the supported path on Windows",
			fix:    "wsl --install"}
	}
	// `wsl -l -v` emits UTF-16; run() already normalises it.
	clean := strings.ReplaceAll(out, "\x00", "")
	running := strings.Contains(clean, "Running")
	r := checkResult{name: "wsl2", found: true, version: "installed"}
	if !running {
		r.severity = sevInfo
		r.version = "installed (all distros stopped)"
		r.detail = "distros idle to Stopped; Docker Desktop starts docker-desktop on demand"
	}
	return r
}

// --- helpers ---------------------------------------------------------------

// run executes a command and returns combined output. Several tools print their
// version to stderr (java, notably), so stdout alone is not enough.
func run(ctx context.Context, name string, args ...string) (string, error) {
	// #nosec G204 -- every call site passes a literal tool name from the
	// checks above; nothing here is caller-supplied.
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.CombinedOutput()
	s := string(out)
	// `wsl` emits UTF-16LE; strip the NULs so regexes match.
	if strings.Contains(s, "\x00") {
		s = strings.ReplaceAll(s, "\x00", "")
	}
	return s, err
}

func extract(s, pattern string) string {
	m := regexp.MustCompile(pattern).FindStringSubmatch(s)
	if len(m) > 1 {
		return strings.TrimSpace(m[1])
	}
	return strings.TrimSpace(strings.SplitN(s, "\n", 2)[0])
}

// atLeast compares a dotted version against a minimum major.minor.
func atLeast(v string, major, minor int) bool {
	parts := strings.SplitN(v, ".", 3)
	if len(parts) < 2 {
		return false
	}
	ma, err1 := strconv.Atoi(parts[0])
	mi, err2 := strconv.Atoi(parts[1])
	if err1 != nil || err2 != nil {
		return false
	}
	if ma != major {
		return ma > major
	}
	return mi >= minor
}
