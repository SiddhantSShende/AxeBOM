package sandbox

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/containerd/errdefs"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/image"
	"github.com/docker/docker/api/types/mount"
	"github.com/docker/docker/client"
	"github.com/docker/docker/pkg/stdcopy"
)

// Spec describes one sandboxed execution.
type Spec struct {
	// Image is the container image, pinned BY DIGEST in production. A tag is
	// mutable, and a mutable reference in a compliance product means the
	// provenance recorded in a report may not describe what actually ran.
	Image string

	// Argv is the command. Checked against CheckCommand before anything runs.
	Argv []string

	// Entrypoint overrides the image's ENTRYPOINT.
	//
	// Needed more often than it looks: alpine/git sets ENTRYPOINT ["git"], so
	// an Argv of ["sh","-c",...] becomes `git sh -c ...` and fails with a
	// confusing "'sh' is not a git command". Found by the first real clone.
	//
	// A nil value leaves the image's entrypoint in place. Whatever it is, the
	// FULL command — entrypoint plus argv — is what CheckCommand inspects, so a
	// forbidden build tool cannot hide in an image's entrypoint.
	Entrypoint []string

	// WorkingDir inside the container. Defaults to the policy's workspace.
	WorkingDir string

	// Mounts are host paths to expose. READ-ONLY is enforced, not requested:
	// see mountsFor.
	Mounts []Mount

	// CopyOut extracts a directory from the container AFTER the process exits
	// and before the container is removed.
	//
	// ⚠ THIS IS HOW A SANDBOXED PROCESS PRODUCES A FILE TREE WITHOUT A WRITABLE
	// HOST MOUNT.
	//
	// mountsFor forces ReadOnly on every bind, deliberately — a writable host
	// mount is how a container escape becomes host compromise. That leaves a
	// process that must produce more than stdout with nowhere to put it. The
	// fetcher is the case: a clone is a directory tree, potentially hundreds of
	// megabytes, so stdout is not an option either.
	//
	// Copying out through the Docker API after the process has exited keeps the
	// property that matters: at no point does the running container hold a
	// writable handle to the host filesystem.
	//
	// The result is written as a RAW TAR, not extracted. Extraction of
	// untrusted content needs path-traversal, size, inode and inflation guards,
	// and those live in the caller (fetcher.ExtractTar) rather than here — the
	// sandbox should not be in the business of interpreting what it copied.
	CopyOut *CopyOut

	// Env is passed to the process.
	//
	// ⚠ MUST NOT CONTAIN A CREDENTIAL. Engine containers receive an archive and
	// nothing else (ADR-0008); assertNoSecrets refuses anything that looks like
	// a token, and the fetcher is the only component that ever holds one.
	Env map[string]string

	Policy Policy
	Limits Limits

	// CredentialsPermitted allows this spec to carry a credential.
	//
	// ⚠ SET BY THE FETCHER AND NOTHING ELSE.
	//
	// ADR-0008: only the fetcher holds git credentials, because engine
	// containers execute third-party scanners over untrusted code. If a scanner
	// held a token, a scanner compromise would yield access to the customer's
	// SOURCE REPOSITORIES rather than just the code it was already scanning.
	//
	// This exists as an explicit, greppable field rather than as a relaxation
	// of assertNoSecrets, so "who is allowed a credential" is answerable by
	// searching for one identifier. Every use is logged.
	//
	// If you are adding a second call site, the design has gone wrong. Route
	// the work through the fetcher instead.
	CredentialsPermitted bool

	// Labels are attached to the container for debugging and for the reaper to
	// find orphans.
	Labels map[string]string
}

// CopyOut describes a directory to extract from a finished container.
type CopyOut struct {
	// MountPath is where the writable volume is mounted.
	//
	// ⚠ IT MUST BE A DIRECTORY THE IMAGE ALREADY MAKES WORLD-WRITABLE, and it
	// is separate from ContainerPath for exactly that reason.
	//
	// A fresh volume inherits the ownership and mode of the image path it
	// covers. Over a path the image does not have — /tmp/src, say — that is
	// root:root 0755, and a sandbox running as uid 65534 cannot write to its
	// own output directory. `mkdir -p` still succeeds, because the parent is
	// writable and the directory already exists, so the failure surfaces later
	// and somewhere else:
	//
	//	touch: /tmp/src/probe: Permission denied
	//
	// Mount at /tmp (1777 by convention) and copy from a subdirectory of it.
	// Empty means the same as ContainerPath.
	MountPath string

	// ContainerPath is the directory to copy out. It must be at or below
	// MountPath.
	ContainerPath string
	// HostTarPath is where the raw tar stream is written.
	HostTarPath string
	// MaxBytes bounds the copy. A container that produced more than expected is
	// refused rather than allowed to fill the host disk — the same reasoning as
	// the output-size cap on stdout.
	MaxBytes int64
}

// Mount is a host path exposed to the container.
type Mount struct {
	Source string
	Target string
}

// Result is the outcome of a sandboxed execution.
type Result struct {
	ExitCode int
	Stdout   []byte
	Stderr   []byte

	// TimedOut reports that the wall clock was exceeded and the container was
	// killed. A distinct signal from a non-zero exit: one is the scanner
	// failing, the other is us stopping it.
	TimedOut bool

	// OOMKilled reports that the memory limit was hit.
	OOMKilled bool

	// OutputTruncated reports that MaxOutputBytes was reached. Surfaced so a
	// downstream parser knows its input is incomplete rather than malformed.
	OutputTruncated bool

	Duration time.Duration

	// DiskQuotaEnforced is false when the host's storage driver does not
	// support a per-container quota. Recorded rather than assumed — an
	// unenforced limit that everyone believes is enforced is worse than a
	// documented gap.
	DiskQuotaEnforced bool

	ContainerID string
}

// Runner executes commands in a sandbox.
type Runner interface {
	Run(ctx context.Context, spec Spec) (Result, error)
	Ping(ctx context.Context) error
	Close() error
}

// DockerRunner runs sandboxes as Docker containers.
type DockerRunner struct {
	cli *client.Client
	log *slog.Logger
}

// NewDockerRunner connects to the Docker daemon.
func NewDockerRunner(logger *slog.Logger) (*DockerRunner, error) {
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return nil, fmt.Errorf("sandbox: docker client: %w", err)
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &DockerRunner{cli: cli, log: logger}, nil
}

func (r *DockerRunner) Ping(ctx context.Context) error {
	_, err := r.cli.Ping(ctx)
	return err
}

// DaemonOS reports which container platform the daemon serves — "linux" or
// "windows".
//
// ⚠ REACHABLE IS NOT THE SAME AS USABLE. Every control this sandbox depends on
// — --network=none, --cap-drop ALL, seccomp, a read-only rootfs, tmpfs
// workdirs, pid and memory quotas — is Linux container semantics with no
// Windows-container equivalent. A daemon in Windows mode answers Ping happily
// and then fails on the first Linux image, so Ping alone is not a precondition
// anything should branch on.
//
// Callers that need the sandbox should treat a non-linux daemon as absent.
func (r *DockerRunner) DaemonOS(ctx context.Context) (string, error) {
	p, err := r.cli.Ping(ctx)
	if err != nil {
		return "", err
	}
	return p.OSType, nil
}

func (r *DockerRunner) Close() error { return r.cli.Close() }

// ErrSecretInEnvironment is returned when a spec carries something that looks
// like a credential.
var ErrSecretInEnvironment = errors.New("sandbox: credential in the engine environment")

// Run executes one command under the full policy.
func (r *DockerRunner) Run(ctx context.Context, spec Spec) (Result, error) {
	// ---- refuse before doing anything -------------------------------------
	//
	// Every check here is cheap and each one, skipped, is a hole. They run in
	// order of how bad the mistake would be.
	if err := spec.Policy.Validate(); err != nil {
		return Result{}, err
	}
	if err := spec.Limits.Validate(); err != nil {
		return Result{}, err
	}
	// The FULL command, not just Argv: a forbidden build tool in an image's
	// entrypoint would otherwise slip past.
	if err := CheckCommand(append(append([]string{}, spec.Entrypoint...), spec.Argv...)); err != nil {
		return Result{}, err
	}
	if spec.CredentialsPermitted {
		// Logged at WARN, every time. A credential entering a container is
		// exactly the event an auditor wants in the record, and making it
		// noisy discourages a second component from adopting the flag.
		r.log.Warn("sandbox: running a container WITH a credential; "+
			"this is permitted only for the fetcher (ADR-0008)",
			"image", spec.Image, "role", spec.Labels["encorebom.role"])
	} else if err := assertNoSecrets(spec.Env); err != nil {
		return Result{}, err
	}
	if spec.Image == "" {
		return Result{}, errors.New("sandbox: no image specified")
	}

	// The wall clock is enforced by US, with a context deadline, and again by
	// the kill below. Relying on the scanner to respect a timeout flag is
	// relying on the untrusted thing to bound itself.
	runCtx, cancel := context.WithTimeout(ctx, spec.Limits.WallClock)
	defer cancel()

	started := time.Now()
	result := Result{DiskQuotaEnforced: spec.Limits.DiskMB > 0}

	hostCfg, containerCfg := r.buildConfig(spec)

	created, err := r.cli.ContainerCreate(runCtx, containerCfg, hostCfg, nil, nil, "")
	if err != nil && isQuotaUnsupported(err) {
		// The host's storage driver has no per-container quota — overlay2 on
		// ext4, which is what Docker Desktop's WSL2 backend uses. Retry
		// WITHOUT it and record the gap: the tmpfs limit still bounds the
		// workspace, which is where a scan writes.
		r.log.Warn("per-container disk quota unsupported on this host; "+
			"the workspace tmpfs limit still applies",
			"cause", err.Error())
		hostCfg.StorageOpt = nil
		result.DiskQuotaEnforced = false
		created, err = r.cli.ContainerCreate(runCtx, containerCfg, hostCfg, nil, nil, "")
	}
	if err != nil {
		return result, fmt.Errorf("sandbox: create container: %w", err)
	}
	result.ContainerID = created.ID

	// ⚠ CLEANUP IS DEFERRED IMMEDIATELY AND UNCONDITIONALLY.
	//
	// A leaked container holds a tmpfs — that is host RAM, not disk — and
	// leaking one per scan exhausts the host in a day. The removal uses a
	// FRESH context because runCtx is already cancelled on the timeout path,
	// which is exactly when cleanup matters most.
	defer func() {
		rmCtx, rmCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer rmCancel()
		if err := r.cli.ContainerRemove(rmCtx, created.ID, container.RemoveOptions{
			Force:         true,
			RemoveVolumes: true,
		}); err != nil && !errdefs.IsNotFound(err) {
			r.log.Error("sandbox: could not remove container; it is leaking a tmpfs",
				"container", created.ID, "cause", err.Error())
		}
	}()

	if err := r.cli.ContainerStart(runCtx, created.ID, container.StartOptions{}); err != nil {
		return result, fmt.Errorf("sandbox: start container: %w", err)
	}

	waitCh, errCh := r.cli.ContainerWait(runCtx, created.ID, container.WaitConditionNotRunning)

	select {
	case waitErr := <-errCh:
		if waitErr != nil && !errors.Is(waitErr, context.DeadlineExceeded) {
			return result, fmt.Errorf("sandbox: waiting for container: %w", waitErr)
		}
		// A deadline here means the wall clock expired; fall through to the
		// kill path below.
		result.TimedOut = true
		r.kill(created.ID)

	case status := <-waitCh:
		result.ExitCode = int(status.StatusCode)

	case <-runCtx.Done():
		result.TimedOut = true
		r.kill(created.ID)
	}

	// Logs are read with a FRESH context: on the timeout path runCtx is dead,
	// and the output of a job that timed out is the output most worth having.
	logCtx, logCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer logCancel()
	r.collectLogs(logCtx, created.ID, &result, spec.Limits.MaxOutputBytes)

	// Inspect for the OOM flag and the real exit code — a killed container's
	// exit code alone does not distinguish "OOM" from "the scanner crashed",
	// and that difference decides whether a retry is worth attempting.
	if info, err := r.cli.ContainerInspect(logCtx, created.ID); err == nil && info.State != nil {
		result.OOMKilled = info.State.OOMKilled
		if !result.TimedOut {
			result.ExitCode = info.State.ExitCode
		}
	}

	// Copy out BEFORE the deferred remove fires. The container has exited, so
	// nothing is still writing, and the tmpfs is still there to read from.
	if spec.CopyOut != nil && result.ExitCode == 0 && !result.TimedOut {
		if err := r.copyOut(logCtx, created.ID, *spec.CopyOut); err != nil {
			return result, fmt.Errorf("sandbox: copy out: %w", err)
		}
	}

	result.Duration = time.Since(started)
	return result, nil
}

// copyOut writes a container directory to a host tar file.
//
// Only called after the process has exited successfully — copying from a
// container that failed or timed out would archive a half-written tree, and a
// partial clone that looks complete is worse than no clone.
func (r *DockerRunner) copyOut(ctx context.Context, id string, spec CopyOut) error {
	rc, _, err := r.cli.CopyFromContainer(ctx, id, spec.ContainerPath)
	if err != nil {
		return fmt.Errorf("reading %s: %w", spec.ContainerPath, err)
	}
	defer func() { _ = rc.Close() }()

	// #nosec G304 -- the destination is chosen by this process, not by the
	// container or by any user input.
	f, err := os.Create(spec.HostTarPath)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()

	limit := spec.MaxBytes
	if limit <= 0 {
		limit = 2 << 30 // 2 GiB
	}

	// One byte over the limit, so "exactly at the limit" is distinguishable
	// from "truncated".
	n, err := io.Copy(f, io.LimitReader(rc, limit+1))
	if err != nil {
		return err
	}
	if n > limit {
		// Remove the partial file: leaving it means the next step extracts a
		// truncated tar and reports a corrupt archive rather than a size limit.
		_ = os.Remove(spec.HostTarPath)
		return fmt.Errorf("copied tree exceeds the %d byte limit", limit)
	}
	return nil
}

func (r *DockerRunner) kill(id string) {
	killCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	// SIGKILL, not SIGTERM. A hostile or wedged process will not honour a
	// polite signal, and the wall clock has already expired.
	if err := r.cli.ContainerKill(killCtx, id, "KILL"); err != nil && !errdefs.IsNotFound(err) {
		r.log.Warn("sandbox: kill failed", "container", id, "cause", err.Error())
	}
}

// buildConfig assembles the Docker configuration from the policy and limits.
//
// Kept as one function so the complete security posture of a container is
// readable in one place — a reviewer should not have to assemble it from six
// call sites.
func (r *DockerRunner) buildConfig(spec Spec) (*container.HostConfig, *container.Config) {
	workdir := spec.WorkingDir
	if workdir == "" {
		workdir = spec.Policy.WorkspacePath
	}

	env := make([]string, 0, len(spec.Env))
	for k, v := range spec.Env {
		env = append(env, k+"="+v)
	}

	uid, gid := spec.Policy.UserIDs()

	securityOpt := []string{"no-new-privileges:true"}
	if spec.Policy.SeccompProfile != "" {
		securityOpt = append(securityOpt, "seccomp="+spec.Policy.SeccompProfile)
	}
	// An empty SeccompProfile leaves Docker's DEFAULT profile in force. Adding
	// "seccomp=unconfined" would disable it, which Policy.Validate refuses.

	hostCfg := &container.HostConfig{
		NetworkMode:    dockerNetworkMode(spec.Policy),
		ReadonlyRootfs: spec.Policy.ReadOnlyRootfs,
		CapDrop:        []string{"ALL"},
		SecurityOpt:    securityOpt,
		// AutoRemove is FALSE on purpose: we remove explicitly, after reading
		// the logs and exit code. AutoRemove races the log read and loses.
		AutoRemove: false,
		Resources: container.Resources{
			NanoCPUs:  spec.Limits.NanoCPUs(),
			Memory:    spec.Limits.MemoryBytes(),
			PidsLimit: int64Ptr(int64(spec.Limits.PIDsMax)),
			// MemorySwap == Memory disables swap. Without this the container
			// can exceed its memory limit by swapping, which turns a bounded
			// memory limit into an unbounded disk one.
			MemorySwap: spec.Limits.MemoryBytes(),
		},
		Tmpfs: map[string]string{
			// noexec: a scanner must not execute anything it just wrote —
			// which is how a downloaded payload becomes a running process.
			// nosuid and nodev close the other two classic tmpfs tricks.
			//
			// uid/gid are NOT optional. A tmpfs mounts root-owned and 0755 by
			// default, so a container running as uid 65534 cannot write to its
			// own workspace — every scanner fails on its first scratch file.
			// Found by TestEscapeWorkspaceIsWritableButNoexec, which is why
			// that test asserts writability as well as noexec: a workspace
			// that is merely locked down is not a working sandbox.
			spec.Policy.WorkspacePath: fmt.Sprintf("rw,noexec,nosuid,nodev,size=%dm,uid=%d,gid=%d,mode=0700",
				spec.Policy.TmpfsSizeMB, uid, gid),
		},
		Mounts: mountsFor(spec.Mounts, spec.CopyOut),
	}

	if spec.Limits.DiskMB > 0 {
		hostCfg.StorageOpt = map[string]string{
			"size": fmt.Sprintf("%dM", spec.Limits.DiskMB),
		}
	}

	labels := map[string]string{"encorebom.sandbox": "true"}
	for k, v := range spec.Labels {
		labels[k] = v
	}

	containerCfg := &container.Config{
		Image:      spec.Image,
		Cmd:        spec.Argv,
		Entrypoint: spec.Entrypoint,
		WorkingDir: workdir,
		Env:        env,
		User:       spec.Policy.User,
		Labels:     labels,
		// No TTY: a TTY merges stdout and stderr into one stream, and the
		// adapters need them separated — a scanner's warnings on stderr must
		// not end up inside the JSON on stdout.
		Tty:             false,
		AttachStdout:    true,
		AttachStderr:    true,
		NetworkDisabled: spec.Policy.Network == NetworkNone,
	}

	return hostCfg, containerCfg
}

// dockerNetworkMode translates our posture into Docker's.
//
// A separate function because OUR modes are not Docker's: passing
// NetworkAllowlist straight through made Docker look for a network NAMED
// "allowlist" and fail at start with "network allowlist not found". Found by
// the first real clone.
func dockerNetworkMode(p Policy) container.NetworkMode {
	switch p.Network {
	case NetworkNone:
		return "none"
	case NetworkAllowlist:
		// Validate has already refused an empty ProxyNetwork, so this is the
		// proxy's network and egress is constrained by the proxy.
		return container.NetworkMode(p.ProxyNetwork)
	case NetworkEgress:
		// The default bridge: unrestricted outbound. Named honestly at the
		// policy layer so nobody reads this as filtered.
		return "bridge"
	default:
		// Unreachable — Validate refuses anything else. Fail closed anyway.
		return "none"
	}
}

// mountsFor converts host mounts, forcing every one read-only.
//
// ReadOnly is set HERE rather than taken from the caller: a writable host mount
// is how a container escape becomes host compromise, and it must not be
// reachable by passing a flag.
func mountsFor(in []Mount, copyOut *CopyOut) []mount.Mount {
	out := make([]mount.Mount, 0, len(in)+1)
	for _, m := range in {
		out = append(out, mount.Mount{
			Type:     mount.TypeBind,
			Source:   m.Source,
			Target:   m.Target,
			ReadOnly: true,
			BindOptions: &mount.BindOptions{
				// Do not propagate host mounts into the container.
				Propagation: mount.PropagationRPrivate,
			},
		})
	}

	// ⚠ AN ANONYMOUS VOLUME, NOT A TMPFS AND NOT A HOST BIND.
	//
	// The only writable mount the sandbox will ever create, and each rejected
	// option was ruled out by measured behaviour rather than preference:
	//
	//   host bind  a writable host mount is how a container escape becomes host
	//              compromise. Never.
	//   tmpfs      `docker cp` DOES NOT DESCEND INTO A TMPFS. Measured: a file
	//              written to a tmpfs and copied out yields a tar containing
	//              only the empty directory. That is exactly what the first
	//              attempt at this produced — an archive of 0 files while every
	//              step reported success.
	//   volume     copies out correctly, and RemoveVolumes cleans it up.
	//
	// Anonymous (no Source), so it is collected with the container instead of
	// accumulating one named volume per scan.
	//
	// ⚠ THE TARGET MATTERS, BECAUSE OF OWNERSHIP. A fresh volume over a path
	// absent from the image is root-owned 0755, and the sandbox runs as uid
	// 65534 — the process could not write to its own output directory. Docker
	// seeds a new volume with the ownership and mode of the image path it
	// covers, so the target must be a directory the image already makes
	// world-writable: /tmp, which is 1777 by convention.
	if copyOut != nil {
		target := copyOut.MountPath
		if target == "" {
			target = copyOut.ContainerPath
		}
		if target != "" {
			out = append(out, mount.Mount{
				Type:   mount.TypeVolume,
				Target: target,
			})
		}
	}
	return out
}

// collectLogs reads stdout and stderr, bounded.
func (r *DockerRunner) collectLogs(ctx context.Context, id string, result *Result, maxBytes int64) {
	rc, err := r.cli.ContainerLogs(ctx, id, container.LogsOptions{
		ShowStdout: true,
		ShowStderr: true,
	})
	if err != nil {
		r.log.Warn("sandbox: could not read logs", "container", id, "cause", err.Error())
		return
	}
	defer func() { _ = rc.Close() }()

	var stdout, stderr bytes.Buffer
	// One extra byte, so "exactly at the limit" is distinguishable from
	// "truncated here" — silently truncated scanner output parses as a
	// malformed document rather than an incomplete one.
	limited := io.LimitReader(rc, maxBytes+1)

	// Docker multiplexes both streams into one connection with an 8-byte
	// frame header; stdcopy demultiplexes it.
	if _, err := stdcopy.StdCopy(&stdout, &stderr, limited); err != nil {
		r.log.Warn("sandbox: log demultiplexing failed", "container", id, "cause", err.Error())
	}

	if int64(stdout.Len()+stderr.Len()) > maxBytes {
		result.OutputTruncated = true
	}
	result.Stdout = stdout.Bytes()
	result.Stderr = stderr.Bytes()
}

// ContainerExists reports whether a container is still present.
//
// Used by the escape suite to prove cleanup happened, and by the orphan reaper
// a later phase adds: a container that outlives its run is holding a tmpfs,
// which is host RAM.
func (r *DockerRunner) ContainerExists(ctx context.Context, id string) (bool, error) {
	_, err := r.cli.ContainerInspect(ctx, id)
	if err == nil {
		return true, nil
	}
	if errdefs.IsNotFound(err) {
		return false, nil
	}
	return false, err
}

// EnsureImage pulls an image if it is absent.
//
// Separate from Run so that pulling — which needs the network — is never part
// of a sandboxed execution.
func (r *DockerRunner) EnsureImage(ctx context.Context, ref string) error {
	if _, err := r.cli.ImageInspect(ctx, ref); err == nil {
		return nil
	}
	rc, err := r.cli.ImagePull(ctx, ref, image.PullOptions{})
	if err != nil {
		return fmt.Errorf("sandbox: pull %s: %w", ref, err)
	}
	defer func() { _ = rc.Close() }()
	// The body must be drained for the pull to complete.
	_, _ = io.Copy(io.Discard, rc)
	return nil
}

// ---------------------------------------------------------------------------
// Secret detection
// ---------------------------------------------------------------------------

// secretishKeys are environment variable names that must never reach an engine.
var secretishKeys = []string{
	"token", "secret", "password", "passwd", "credential", "apikey", "api_key",
	"auth", "private_key", "privatekey", "session", "cookie",
}

// assertNoSecrets refuses a spec carrying anything credential-shaped.
//
// ⚠ THIS IS ADR-0008 ENFORCED IN CODE.
//
// Engine containers receive a content-addressed archive and nothing else.
// Compromising a scanner must yield the code it was already scanning — not a
// token, not another tenant's data, not lateral movement.
//
// The check is by KEY NAME AND VALUE SHAPE, because the mistake this catches is
// somebody adding `GITHUB_TOKEN` "just for this one engine", and a name-only
// check misses `EXTRA_CONFIG=ghp_...`.
func assertNoSecrets(env map[string]string) error {
	for k, v := range env {
		lower := strings.ToLower(k)
		for _, needle := range secretishKeys {
			if strings.Contains(lower, needle) {
				return fmt.Errorf("%w: %q. Engines receive an archive and nothing else "+
					"(ADR-0008); route credential-bearing work through the fetcher",
					ErrSecretInEnvironment, k)
			}
		}
		if looksLikeCredential(v) {
			return fmt.Errorf("%w: the value of %q looks like a credential",
				ErrSecretInEnvironment, k)
		}
	}
	return nil
}

// looksLikeCredential matches the shapes of common tokens, so a
// harmlessly-named variable carrying one is still caught.
func looksLikeCredential(v string) bool {
	if len(v) < 20 {
		return false
	}
	for _, prefix := range []string{
		"ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_", // GitHub
		"glpat-",     // GitLab
		"xox",        // Slack
		"sk-",        // OpenAI and lookalikes
		"AKIA",       // AWS access key id
		"hvs.",       // Vault service token
		"-----BEGIN", // any PEM private key
	} {
		if strings.HasPrefix(v, prefix) {
			return true
		}
	}
	return false
}

func int64Ptr(v int64) *int64 { return &v }

// isQuotaUnsupported reports whether a create failed because the storage driver
// has no quota support, as opposed to a real error.
func isQuotaUnsupported(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "storage-opt") ||
		strings.Contains(msg, "storage opt") ||
		strings.Contains(msg, "quota") ||
		strings.Contains(msg, "size is not supported")
}
