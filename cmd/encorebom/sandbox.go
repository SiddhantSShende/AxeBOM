package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"time"

	"github.com/encorebom/encorebom/libs/go-shared/sandbox"
)

// The sandbox bridge.
//
// ⚠ WHY THIS EXISTS, AND WHY IT IS NOT A PYTHON LIBRARY.
//
// The scan workers are Python; the sandbox policy is Go. The obvious
// alternative — a Python implementation using the Docker SDK — would mean TWO
// implementations of a security control, and the Python one would have no
// escape suite behind it. The first time somebody changed a quota in one and
// not the other, the difference would be invisible until an incident.
//
// So there is exactly ONE sandbox: libs/go-shared/sandbox, with the twelve-case
// escape suite from Phase 5. This subcommand exposes it over stdin/stdout as
// JSON, and the Python adapters call it.
//
// The cost is a process spawn per engine run, which is noise next to a
// container start. The benefit is that "is the sandbox correctly configured?"
// has one answer, provable in one place.

// runSandbox dispatches the sandbox subcommands.
func runSandbox(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return errors.New("usage: encorebom sandbox <run|check> [flags]")
	}
	switch args[0] {
	case "run":
		return sandboxRun(ctx, args[1:])
	case "check":
		return sandboxCheck(ctx)
	default:
		return fmt.Errorf("unknown sandbox subcommand %q (want: run, check)", args[0])
	}
}

// bridgeSpec is the JSON a caller sends on stdin.
//
// A DELIBERATELY NARROW SUBSET of sandbox.Spec. The policy is NOT accepted from
// the caller: a worker cannot ask for a writable rootfs, a network, or root,
// because those fields do not exist here. The only knobs are what the engine
// legitimately needs — image, command, mounts, quotas.
type bridgeSpec struct {
	Image      string            `json:"image"`
	Entrypoint []string          `json:"entrypoint,omitempty"`
	Argv       []string          `json:"argv"`
	WorkingDir string            `json:"working_dir,omitempty"`
	Env        map[string]string `json:"env,omitempty"`

	Mounts []struct {
		Source string `json:"source"`
		Target string `json:"target"`
	} `json:"mounts,omitempty"`

	Limits struct {
		WallClockSec   int   `json:"wall_clock_sec"`
		CPUMillis      int   `json:"cpu_millis"`
		MemoryMB       int   `json:"memory_mb"`
		DiskMB         int   `json:"disk_mb"`
		PIDsMax        int   `json:"pids_max"`
		MaxOutputBytes int64 `json:"max_output_bytes"`
	} `json:"limits"`

	// AllowNetwork requests egress.
	//
	// ⚠ REFUSED unless the caller also names why, and it is REFUSED OUTRIGHT
	// for engine work. Only the fetcher legitimately needs the network, and the
	// fetcher is Go — it does not come through this bridge. A vulnerability
	// engine gets a PRE-WARMED DATABASE VOLUME, never egress.
	AllowNetwork bool `json:"allow_network,omitempty"`

	Labels map[string]string `json:"labels,omitempty"`
}

// bridgeResult is the JSON returned on stdout.
type bridgeResult struct {
	ExitCode int `json:"exit_code"`
	// Stdout and Stderr are base64-free: they are UTF-8 text from a scanner,
	// and JSON string encoding handles them. A scanner emitting binary on
	// stdout is a bug worth seeing rather than smoothing over.
	Stdout string `json:"stdout"`
	Stderr string `json:"stderr"`

	TimedOut        bool `json:"timed_out"`
	OOMKilled       bool `json:"oom_killed"`
	OutputTruncated bool `json:"output_truncated"`

	// ImageDigest is what the daemon resolved the reference to, not what we
	// asked for. Empty when the image carries no registry digest.
	ImageDigest string `json:"image_digest,omitempty"`

	// StartedAt and FinishedAt bracket exactly the interval DurationMS
	// measures. RFC3339 with a literal Z; the worker copies all three into
	// ScanResultV1.invocation, where a reader must be able to reconcile them.
	StartedAt  string `json:"started_at,omitempty"`
	FinishedAt string `json:"finished_at,omitempty"`

	DurationMS        int64  `json:"duration_ms"`
	DiskQuotaEnforced bool   `json:"disk_quota_enforced"`
	ContainerID       string `json:"container_id,omitempty"`

	// Error is set when the run could not be attempted at all — a refused
	// policy, a forbidden command, a missing image. Distinct from a non-zero
	// ExitCode, which means the engine ran and failed.
	Error string `json:"error,omitempty"`
}

// sandboxRun reads a spec from stdin, runs it, and writes the result to stdout.
func sandboxRun(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("sandbox run", flag.ExitOnError)
	pull := fs.Bool("pull", false, "pull the image first if it is absent")
	if err := fs.Parse(args); err != nil {
		return err
	}

	raw, err := io.ReadAll(io.LimitReader(os.Stdin, 1<<20))
	if err != nil {
		return fmt.Errorf("read spec: %w", err)
	}

	var spec bridgeSpec
	if err := json.Unmarshal(raw, &spec); err != nil {
		return emitError(fmt.Errorf("spec is not valid JSON: %w", err))
	}

	runner, err := sandbox.NewDockerRunner(slog.Default())
	if err != nil {
		return emitError(err)
	}
	defer func() { _ = runner.Close() }()

	if *pull {
		pullCtx, cancel := context.WithTimeout(ctx, 10*time.Minute)
		defer cancel()
		if err := runner.EnsureImage(pullCtx, spec.Image); err != nil {
			return emitError(fmt.Errorf("pull %s: %w", spec.Image, err))
		}
	}

	// ⚠ THE POLICY COMES FROM DefaultPolicy(), NOT FROM THE CALLER.
	//
	// This is the whole point of the bridge. A worker cannot weaken the
	// sandbox, because the fields that would weaken it are not in bridgeSpec.
	policy := sandbox.DefaultPolicy()
	if spec.AllowNetwork {
		// Refused. An engine that needs a vulnerability database gets a
		// pre-warmed volume mounted read-only; egress from a container running
		// third-party code over untrusted input is the thing the sandbox
		// exists to prevent.
		return emitError(errors.New(
			"allow_network is refused for engine work: a vulnerability engine gets a " +
				"pre-warmed database volume, not egress (docs/05-SECURITY-MODEL.md §3). " +
				"Only the fetcher talks to the network, and it does not use this bridge"))
	}

	limits := sandbox.DefaultLimits()
	if spec.Limits.WallClockSec > 0 {
		limits.WallClock = time.Duration(spec.Limits.WallClockSec) * time.Second
	}
	if spec.Limits.CPUMillis > 0 {
		limits.CPUMillis = spec.Limits.CPUMillis
	}
	if spec.Limits.MemoryMB > 0 {
		limits.MemoryMB = spec.Limits.MemoryMB
	}
	if spec.Limits.DiskMB > 0 {
		limits.DiskMB = spec.Limits.DiskMB
	}
	if spec.Limits.PIDsMax > 0 {
		limits.PIDsMax = spec.Limits.PIDsMax
	}
	if spec.Limits.MaxOutputBytes > 0 {
		limits.MaxOutputBytes = spec.Limits.MaxOutputBytes
	}

	mounts := make([]sandbox.Mount, 0, len(spec.Mounts))
	for _, m := range spec.Mounts {
		// Read-only is enforced inside the sandbox package, not requested here.
		mounts = append(mounts, sandbox.Mount{Source: m.Source, Target: m.Target})
	}

	result, runErr := runner.Run(ctx, sandbox.Spec{
		Image:      spec.Image,
		Entrypoint: spec.Entrypoint,
		Argv:       spec.Argv,
		WorkingDir: spec.WorkingDir,
		Env:        spec.Env,
		Mounts:     mounts,
		Policy:     policy,
		Limits:     limits,
		Labels:     spec.Labels,
		// CredentialsPermitted is deliberately NOT settable from the bridge.
		// Only the fetcher may carry a credential, and the fetcher is Go.
	})

	out := bridgeResult{
		ExitCode: result.ExitCode,
		Stdout:   string(result.Stdout),
		Stderr:   string(result.Stderr),

		TimedOut:        result.TimedOut,
		OOMKilled:       result.OOMKilled,
		OutputTruncated: result.OutputTruncated,

		ImageDigest: result.ImageDigest,

		StartedAt:  rfc3339Z(result.StartedAt),
		FinishedAt: rfc3339Z(result.FinishedAt),

		DurationMS:        result.Duration.Milliseconds(),
		DiskQuotaEnforced: result.DiskQuotaEnforced,
		ContainerID:       result.ContainerID,
	}
	if runErr != nil {
		out.Error = runErr.Error()
	}

	return json.NewEncoder(os.Stdout).Encode(out)
}

// rfc3339Z renders a timestamp the way every other timestamp in this system is
// rendered: UTC, RFC3339, a literal Z. A zero time renders as "" and is omitted
// rather than published as year 1 — a run that was never attempted has no
// start, and inventing one would be worse than saying nothing.
func rfc3339Z(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339Nano)
}

// sandboxCheck reports whether the sandbox is usable.
//
// Called by workers at startup: a worker that cannot reach Docker should say so
// once, clearly, rather than failing every job with the same error.
func sandboxCheck(ctx context.Context) error {
	runner, err := sandbox.NewDockerRunner(slog.Default())
	if err != nil {
		return emitError(err)
	}
	defer func() { _ = runner.Close() }()

	pingCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := runner.Ping(pingCtx); err != nil {
		return emitError(err)
	}

	return json.NewEncoder(os.Stdout).Encode(map[string]any{
		"available": true,
		"runtime":   "docker",
		"policy":    "network=none, read-only rootfs, cap-drop ALL, non-root, seccomp default",
	})
}

// emitError writes a structured failure to stdout and exits non-zero.
//
// The failure goes to STDOUT as JSON, not stderr as text, so the Python caller
// parses one shape whatever happened. Exiting non-zero as well means a caller
// that forgets to check the JSON still notices.
func emitError(err error) error {
	_ = json.NewEncoder(os.Stdout).Encode(bridgeResult{
		ExitCode: -1,
		Error:    err.Error(),
	})
	return err
}
