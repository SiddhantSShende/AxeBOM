package sandbox_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/encorebom/encorebom/libs/go-shared/sandbox"
)

// ⚠ THE ESCAPE SUITE.
//
// Every case here is a real attack against the sandbox, run against a real
// container runtime. These are not unit tests of a config struct — a config
// that looks right and is not applied is exactly the failure this suite exists
// to catch, so each case makes the container actually TRY the thing.
//
// They SKIP when Docker is unavailable, and CI has it. A skipped security test
// is visible in the output; a security test that silently passes because it
// never ran is not.

// testImage is a minimal image with a shell. Pinned by tag here because the
// test only needs `sh`; production pins by DIGEST, since a mutable reference
// means the provenance recorded in a report may not describe what ran.
const testImage = "busybox:1.37"

func newRunner(t *testing.T) *sandbox.DockerRunner {
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
	if err := r.Ping(ctx); err != nil {
		t.Skipf("docker daemon unreachable (%v) — start Docker Desktop", err)
	}

	pullCtx, pullCancel := context.WithTimeout(t.Context(), 3*time.Minute)
	defer pullCancel()
	if err := r.EnsureImage(pullCtx, testImage); err != nil {
		t.Skipf("could not pull %s: %v", testImage, err)
	}
	return r
}

// spec builds a default-policy spec running one shell command.
func spec(argv ...string) sandbox.Spec {
	return sandbox.Spec{
		Image:  testImage,
		Argv:   argv,
		Policy: sandbox.DefaultPolicy(),
		Limits: fastLimits(),
	}
}

// fastLimits keeps the suite quick. The POLICY is unchanged — only the wall
// clock is shortened, because a security test that takes 15 minutes to fail is
// a security test nobody runs.
func fastLimits() sandbox.Limits {
	l := sandbox.DefaultLimits()
	l.WallClock = 45 * time.Second
	l.MemoryMB = 256
	return l
}

func run(t *testing.T, r *sandbox.DockerRunner, s sandbox.Spec) sandbox.Result {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()

	res, err := r.Run(ctx, s)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	return res
}

// ---------------------------------------------------------------------------
// The sandbox works at all
// ---------------------------------------------------------------------------

func TestEscapeBaselineCommandRuns(t *testing.T) {
	r := newRunner(t)
	res := run(t, r, spec("sh", "-c", "echo hello-from-sandbox"))

	if res.ExitCode != 0 {
		t.Fatalf("exit = %d, stderr = %s", res.ExitCode, res.Stderr)
	}
	if !strings.Contains(string(res.Stdout), "hello-from-sandbox") {
		t.Errorf("stdout = %q", res.Stdout)
	}
	// A guard that breaks the product is not a guard.
	t.Logf("baseline ran in %v (disk quota enforced: %v)", res.Duration, res.DiskQuotaEnforced)
}

// ---------------------------------------------------------------------------
// Network
// ---------------------------------------------------------------------------

// ⚠ EXFILTRATION AND SSRF FROM INSIDE A SCAN.
//
// --network=none is what makes this impossible rather than merely filtered. A
// scanner that can reach the network can post the customer's source anywhere.
func TestEscapeNetworkIsUnreachable(t *testing.T) {
	r := newRunner(t)

	// Three different ways out: DNS, a public address, and cloud metadata.
	res := run(t, r, spec("sh", "-c",
		"nslookup example.com 2>&1; "+
			"wget -T 3 -O- http://93.184.216.34/ 2>&1; "+
			"wget -T 3 -O- http://169.254.169.254/latest/meta-data/ 2>&1; "+
			"echo DONE"))

	out := string(res.Stdout) + string(res.Stderr)
	if !strings.Contains(out, "DONE") {
		t.Fatalf("the probe did not complete: %q", out)
	}

	// Any sign of a successful fetch is a failure. The container should have
	// no route at all — "bad address", "network unreachable", or similar.
	for _, sign := range []string{"HTTP/1.1 200", "ami-id", "instance-id", "Example Domain"} {
		if strings.Contains(out, sign) {
			t.Errorf("THE CONTAINER REACHED THE NETWORK: found %q in output", sign)
		}
	}
	t.Logf("network probe output (expected to be all failures): %s", truncate(out, 400))
}

// ---------------------------------------------------------------------------
// Filesystem
// ---------------------------------------------------------------------------

// A writable rootfs means persistence and tampering — a scanner that modifies
// its own image layer, or drops a binary for the next run to pick up.
func TestEscapeRootFilesystemIsReadOnly(t *testing.T) {
	r := newRunner(t)
	res := run(t, r, spec("sh", "-c",
		"echo attempting >/etc/evil.txt && echo WROTE_ETC || echo etc-denied; "+
			"echo attempting >/usr/bin/evil && echo WROTE_USR || echo usr-denied; "+
			"echo attempting >/evil.txt && echo WROTE_ROOT || echo root-denied"))

	out := string(res.Stdout) + string(res.Stderr)
	for _, marker := range []string{"WROTE_ETC", "WROTE_USR", "WROTE_ROOT"} {
		if strings.Contains(out, marker) {
			t.Errorf("THE ROOTFS IS WRITABLE: %s", marker)
		}
	}
	if !strings.Contains(out, "denied") {
		t.Errorf("expected denials, got: %q", truncate(out, 300))
	}
}

// The workspace tmpfs is the ONLY writable path, and it must be usable — a
// scanner needs somewhere to put its own temporary files.
func TestEscapeWorkspaceIsWritableButNoexec(t *testing.T) {
	r := newRunner(t)
	res := run(t, r, spec("sh", "-c",
		"echo ok >/workspace/file.txt && echo WROTE_WORKSPACE; "+
			"cp /bin/echo /workspace/payload 2>/dev/null; "+
			"chmod +x /workspace/payload 2>/dev/null; "+
			"/workspace/payload ran 2>&1 && echo EXECUTED || echo exec-denied"))

	out := string(res.Stdout) + string(res.Stderr)
	if !strings.Contains(out, "WROTE_WORKSPACE") {
		t.Errorf("the workspace is not writable; scanners need scratch space: %q", truncate(out, 300))
	}
	// noexec: a scanner must not run something it just wrote, which is how a
	// downloaded payload becomes a running process.
	if strings.Contains(out, "EXECUTED") {
		t.Error("THE WORKSPACE IS EXECUTABLE: a written payload could be run")
	}
}

// ---------------------------------------------------------------------------
// Privileges
// ---------------------------------------------------------------------------

// uid 0 in a container without user namespaces is uid 0 on the host if anything
// escapes.
func TestEscapeRunsAsNonRoot(t *testing.T) {
	r := newRunner(t)
	res := run(t, r, spec("sh", "-c", "id -u; id"))

	out := strings.TrimSpace(string(res.Stdout))
	if strings.HasPrefix(out, "0\n") || out == "0" {
		t.Fatalf("THE CONTAINER IS RUNNING AS ROOT: %q", out)
	}
	if !strings.Contains(out, "65534") {
		t.Errorf("uid = %q, want the configured 65534", truncate(out, 120))
	}
}

// Without dropped capabilities a scanner can bind low ports, change file
// ownership, and reach kernel interfaces it has no business touching.
func TestEscapeCapabilitiesAreDropped(t *testing.T) {
	r := newRunner(t)
	res := run(t, r, spec("sh", "-c",
		"chown 0:0 /workspace 2>&1 && echo CHOWN_OK || echo chown-denied; "+
			"mknod /workspace/dev c 1 3 2>&1 && echo MKNOD_OK || echo mknod-denied; "+
			"mount -t tmpfs none /workspace 2>&1 && echo MOUNT_OK || echo mount-denied"))

	out := string(res.Stdout) + string(res.Stderr)
	for _, marker := range []string{"CHOWN_OK", "MKNOD_OK", "MOUNT_OK"} {
		if strings.Contains(out, marker) {
			t.Errorf("A CAPABILITY SURVIVED: %s", marker)
		}
	}
}

// ---------------------------------------------------------------------------
// Resource limits
// ---------------------------------------------------------------------------

// ⚠ THE FORK BOMB.
//
// `:(){ :|:& };:` in a build file exhausts the host's PID table without the
// limit. The container must die; the HOST must stay up — and the fact that the
// rest of this suite still runs afterwards is part of the assertion.
func TestEscapeForkBombHitsThePIDLimit(t *testing.T) {
	r := newRunner(t)

	s := spec("sh", "-c", "while true; do sleep 30 & done")
	s.Limits.PIDsMax = 24
	s.Limits.WallClock = 20 * time.Second

	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()

	start := time.Now()
	res, err := r.Run(ctx, s)
	if err != nil {
		t.Fatalf("run: %v", err)
	}

	// It must have been stopped — by the PID limit making progress impossible,
	// or by the wall clock. Either way it ended, and it ended bounded.
	t.Logf("fork bomb ended after %v: exit=%d timed_out=%v", time.Since(start), res.ExitCode, res.TimedOut)
	if time.Since(start) > 60*time.Second {
		t.Error("the fork bomb was not bounded")
	}
}

// A scanner that allocates without bound must take down its own container, not
// the host.
func TestEscapeMemoryLimitOOMKills(t *testing.T) {
	r := newRunner(t)

	// Allocate far past the limit, in a way busybox can express.
	s := spec("sh", "-c", "dd if=/dev/zero of=/dev/shm/fill bs=1M count=2048 2>&1; echo DONE")
	s.Limits.MemoryMB = 64
	s.Limits.WallClock = 30 * time.Second

	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	res, err := r.Run(ctx, s)
	if err != nil {
		t.Fatalf("run: %v", err)
	}

	// Either the OOM killer fired or the write failed — both are the limit
	// holding. What must NOT happen is 2 GB being allocated successfully.
	t.Logf("memory probe: exit=%d oom=%v out=%s",
		res.ExitCode, res.OOMKilled, truncate(string(res.Stdout)+string(res.Stderr), 200))
	if res.ExitCode == 0 && !res.OOMKilled && strings.Contains(string(res.Stdout), "2048+0 records out") {
		t.Error("2 GB was allocated under a 64 MB limit")
	}
}

// ⚠ WALL CLOCK.
//
// An infinite loop must be killed by US. Relying on the scanner to respect a
// timeout flag is relying on the untrusted thing to bound itself.
func TestEscapeWallClockKillsAndRemoves(t *testing.T) {
	r := newRunner(t)

	s := spec("sh", "-c", "while true; do :; done")
	s.Limits.WallClock = 5 * time.Second

	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()

	start := time.Now()
	res, err := r.Run(ctx, s)
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if !res.TimedOut {
		t.Error("TimedOut is false for a job that ran past its wall clock")
	}
	if elapsed > 45*time.Second {
		t.Errorf("took %v to kill a 5s job", elapsed)
	}
	t.Logf("killed after %v", elapsed)
}

// ---------------------------------------------------------------------------
// Credentials
// ---------------------------------------------------------------------------

// ⚠ ADR-0008 ENFORCED IN CODE.
//
// Engine containers receive an archive and nothing else. Compromising a scanner
// must yield the code it was already scanning — not a token, not another
// tenant's data, not lateral movement.
func TestEscapeNoCredentialReachesTheContainer(t *testing.T) {
	r := newRunner(t)

	// A spec carrying a credential must be REFUSED, not sanitized.
	byName := []string{
		"GITHUB_TOKEN", "AWS_SECRET_ACCESS_KEY", "VAULT_TOKEN",
		"DB_PASSWORD", "API_KEY", "SESSION_COOKIE", "PRIVATE_KEY",
	}
	for _, key := range byName {
		t.Run("name/"+key, func(t *testing.T) {
			s := spec("sh", "-c", "env")
			s.Env = map[string]string{key: "some-value-here"}

			if _, err := r.Run(t.Context(), s); err == nil {
				t.Fatalf("a spec carrying %s was accepted", key)
			} else if !errors.Is(err, sandbox.ErrSecretInEnvironment) {
				t.Errorf("wrong error: %v", err)
			}
		})
	}

	// And by VALUE SHAPE, because the mistake is somebody adding
	// EXTRA_CONFIG=ghp_... where a name check sees nothing wrong.
	byValue := map[string]string{
		"github pat":  "ghp_0123456789abcdefghijklmnopqrstuvwx",
		"gitlab pat":  "glpat-0123456789abcdefghij",
		"aws key id":  "AKIAIOSFODNN7EXAMPLE1234",
		"vault token": "hvs.CAESIJ0123456789abcdefghijklmn",
		"pem key":     "-----BEGIN RSA PRIVATE KEY-----\nMIIE...",
	}
	for name, value := range byValue {
		t.Run("shape/"+name, func(t *testing.T) {
			s := spec("sh", "-c", "env")
			s.Env = map[string]string{"HARMLESS_NAME": value}

			if _, err := r.Run(t.Context(), s); err == nil {
				t.Fatalf("a %s was accepted under a harmless name", name)
			} else if !errors.Is(err, sandbox.ErrSecretInEnvironment) {
				t.Errorf("wrong error: %v", err)
			}
		})
	}
}

// The environment a real engine sees must be free of anything credential-like,
// and no secret mount may be present.
func TestEscapeEngineEnvironmentIsClean(t *testing.T) {
	r := newRunner(t)
	res := run(t, r, spec("sh", "-c",
		"env; echo BOUNDARY_MARKER; ls -la /run/secrets 2>&1; ls -la /var/run/secrets 2>&1"))

	out := string(res.Stdout) + string(res.Stderr)
	parts := strings.SplitN(out, "BOUNDARY_MARKER", 2)

	// Only the ENVIRONMENT half is scanned for credential-shaped names.
	//
	// The probe half necessarily contains the word "secrets" — it is looking
	// FOR a secrets mount — and scanning the combined output reported that as a
	// leak the first time this ran. A security test that cries wolf gets
	// ignored, so the halves are separated.
	env := strings.ToLower(parts[0])
	for _, needle := range []string{"token", "secret", "password", "api_key", "credential", "passwd"} {
		if strings.Contains(env, needle) {
			t.Errorf("the container environment mentions %q:\n%s", needle, truncate(env, 500))
		}
	}

	// And no secrets directory was mounted in.
	if len(parts) == 2 && !strings.Contains(strings.ToLower(parts[1]), "no such file") {
		t.Errorf("a secrets mount is present in the engine container:\n%s", truncate(parts[1], 300))
	}
}

// ---------------------------------------------------------------------------
// Build tooling
// ---------------------------------------------------------------------------

// ⚠ NEVER EXECUTE USER BUILD TOOLING.
//
// npm lifecycle scripts and Gradle build files run whatever the repository
// author wrote. The sandbox bounds the damage; not running them removes it.
func TestEscapeBuildToolingIsRefused(t *testing.T) {
	forbidden := [][]string{
		{"npm", "install"},
		{"npm", "ci"},
		{"npm", "run", "build"},
		{"yarn"},
		{"yarn", "--frozen-lockfile"},
		{"pnpm", "install"},
		{"mvn", "dependency:tree"},
		{"gradle", "dependencies"},
		{"pip", "install", "-r", "requirements.txt"},
		{"pip3", "download", "."},
		{"python", "setup.py", "install"},
		{"make"},
		{"cargo", "build"},
		{"go", "generate", "./..."},
		{"bundle", "install"},
		{"composer", "install"},
		// The shell form, where the forbidden command hides in an argument.
		{"sh", "-c", "npm install --ignore-scripts"},
		{"sh", "-c", "cd /workspace && mvn -q dependency:list"},
		{"/usr/local/bin/npm", "install"},
		{"npm.exe", "install"},
	}

	for _, argv := range forbidden {
		t.Run(strings.Join(argv, " "), func(t *testing.T) {
			if err := sandbox.CheckCommand(argv); err == nil {
				t.Errorf("ACCEPTED %v — this executes code from the repository", argv)
			} else if !errors.Is(err, sandbox.ErrForbiddenCommand) {
				t.Errorf("wrong error: %v", err)
			}
		})
	}
}

// Parsing is what engines actually do, and it must not be blocked.
func TestScannerCommandsAreAllowed(t *testing.T) {
	allowed := [][]string{
		{"syft", "dir:/workspace", "-o", "cyclonedx-json"},
		{"grype", "sbom:/workspace/sbom.json", "-o", "json"},
		{"trivy", "fs", "--format", "cyclonedx", "/workspace"},
		{"osv-scanner", "--lockfile", "/workspace/package-lock.json"},
		{"sh", "-c", "cat /workspace/package-lock.json"},
		{"go", "version"},
		{"python", "-c", "import json"},
	}

	for _, argv := range allowed {
		t.Run(strings.Join(argv, " "), func(t *testing.T) {
			if err := sandbox.CheckCommand(argv); err != nil {
				t.Errorf("rejected a legitimate scanner invocation %v: %v", argv, err)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Policy enforcement
// ---------------------------------------------------------------------------

// A permissive policy must be REFUSED at the door, so a caller cannot get a
// weakened sandbox by constructing one.
func TestUnsafePolicyIsRefused(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*sandbox.Policy)
	}{
		{"zero value", func(p *sandbox.Policy) { *p = sandbox.Policy{} }},
		{"writable rootfs", func(p *sandbox.Policy) { p.ReadOnlyRootfs = false }},
		{"new privileges", func(p *sandbox.Policy) { p.NoNewPrivileges = false }},
		{"capabilities kept", func(p *sandbox.Policy) { p.DropAllCapabilities = false }},
		{"root user", func(p *sandbox.Policy) { p.User = "0:0" }},
		{"empty user", func(p *sandbox.Policy) { p.User = "" }},
		{"seccomp unconfined", func(p *sandbox.Policy) { p.SeccompProfile = "unconfined" }},
		{"unbounded tmpfs", func(p *sandbox.Policy) { p.TmpfsSizeMB = 0 }},
		{"bridge network", func(p *sandbox.Policy) { p.Network = "bridge" }},
		{"allowlist with no hosts", func(p *sandbox.Policy) { p.Network = sandbox.NetworkAllowlist }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := sandbox.DefaultPolicy()
			tt.mutate(&p)
			if err := p.Validate(); err == nil {
				t.Errorf("ACCEPTED an unsafe policy: %s", tt.name)
			} else if !errors.Is(err, sandbox.ErrUnsafePolicy) {
				t.Errorf("wrong error: %v", err)
			}
		})
	}

	if err := sandbox.DefaultPolicy().Validate(); err != nil {
		t.Errorf("the default policy does not validate: %v", err)
	}
}

// Zero is REJECTED rather than meaning "unlimited", which is the usual
// convention and exactly the wrong one in a component whose job is bounding.
func TestUnboundedLimitsAreRefused(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*sandbox.Limits)
	}{
		{"zero value", func(l *sandbox.Limits) { *l = sandbox.Limits{} }},
		{"no cpu", func(l *sandbox.Limits) { l.CPUMillis = 0 }},
		{"no memory", func(l *sandbox.Limits) { l.MemoryMB = 0 }},
		{"no pids", func(l *sandbox.Limits) { l.PIDsMax = 0 }},
		{"no wall clock", func(l *sandbox.Limits) { l.WallClock = 0 }},
		{"no output cap", func(l *sandbox.Limits) { l.MaxOutputBytes = 0 }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := sandbox.DefaultLimits()
			tt.mutate(&l)
			if err := l.Validate(); err == nil {
				t.Errorf("ACCEPTED unbounded limits: %s", tt.name)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Cleanup
// ---------------------------------------------------------------------------

// A leaked container holds a tmpfs — that is host RAM. Leaking one per scan
// exhausts the host in a day, and the timeout path is exactly when cleanup is
// most likely to be skipped.
func TestContainerIsRemovedEvenAfterTimeout(t *testing.T) {
	r := newRunner(t)

	s := spec("sh", "-c", "while true; do :; done")
	s.Limits.WallClock = 5 * time.Second

	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	res, err := r.Run(ctx, s)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if res.ContainerID == "" {
		t.Fatal("no container id recorded")
	}

	// Give the deferred removal a moment, then confirm it is gone.
	time.Sleep(2 * time.Second)

	checkCtx, checkCancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer checkCancel()
	exists, err := r.ContainerExists(checkCtx, res.ContainerID)
	if err != nil {
		t.Fatalf("checking for the container: %v", err)
	}
	if exists {
		t.Errorf("container %s survived a timeout kill; it is leaking a tmpfs",
			res.ContainerID[:12])
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
