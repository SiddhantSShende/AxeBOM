package sandbox

import (
	"errors"
	"fmt"
	"time"
)

// Limits are the resource quotas applied to a sandbox container.
//
// Each defeats a specific denial of service, and each has a default in
// .env.example. A job exceeding one is KILLED AND REPORTED, never silently
// truncated: a scan that quietly produced half a BOM is worse than one that
// failed, because the half-BOM looks complete.
type Limits struct {
	// CPUMillis is CPU time per second — 2000 means two cores' worth.
	CPUMillis int

	// MemoryMB caps the container. Exceeding it is an OOM kill of the
	// CONTAINER, which is the point: without it, a scanner that allocates
	// without bound takes the host down instead.
	MemoryMB int

	// DiskMB bounds the writable layer.
	//
	// ⚠ NOT ENFORCEABLE ON EVERY HOST. Docker's StorageOpt size requires a
	// storage driver with quota support (overlay2 on xfs with pquota, or
	// btrfs). On ext4-backed overlay2 — which is what Docker Desktop's WSL2
	// backend uses — the option is REJECTED at container create.
	//
	// The runner degrades explicitly: it retries without the quota and records
	// DiskQuotaEnforced=false in the result, so the gap is visible rather than
	// assumed. The tmpfs size limit still bounds the workspace, which is where
	// a scan actually writes.
	DiskMB int

	// PIDsMax bounds process count. This is the fork-bomb defence: without it,
	// `:(){ :|:& };:` in a build file exhausts the host's PID table.
	PIDsMax int

	// WallClock bounds total runtime. Defeats infinite loops, and slow-loris
	// behaviour against whatever the scanner talks to.
	WallClock time.Duration

	// MaxOutputBytes caps captured stdout/stderr. A scanner that prints
	// forever must not fill memory or object storage.
	MaxOutputBytes int64
}

// DefaultLimits mirrors .env.example.
func DefaultLimits() Limits {
	return Limits{
		CPUMillis:      2000,              // SANDBOX_CPU_MILLIS
		MemoryMB:       4096,              // SANDBOX_MEMORY_MB
		DiskMB:         20480,             // SANDBOX_DISK_MB
		PIDsMax:        512,               // SANDBOX_PIDS_MAX
		WallClock:      900 * time.Second, // SANDBOX_WALL_CLOCK_SEC
		MaxOutputBytes: 256 << 20,
	}
}

// ErrInvalidLimits is returned when a limit is missing or nonsensical.
var ErrInvalidLimits = errors.New("invalid sandbox limits")

// Validate refuses limits that would leave a resource unbounded.
//
// Zero is REJECTED rather than treated as "no limit", which is the usual
// convention and exactly the wrong one here: an unset field must not silently
// mean unlimited in a component whose job is to bound things.
func (l Limits) Validate() error {
	var problems []string
	if l.CPUMillis <= 0 {
		problems = append(problems, "CPUMillis must be positive")
	}
	if l.MemoryMB <= 0 {
		problems = append(problems, "MemoryMB must be positive")
	}
	if l.PIDsMax <= 0 {
		problems = append(problems, "PIDsMax must be positive, or a fork bomb is unbounded")
	}
	if l.WallClock <= 0 {
		problems = append(problems, "WallClock must be positive, or an infinite loop runs forever")
	}
	if l.MaxOutputBytes <= 0 {
		problems = append(problems, "MaxOutputBytes must be positive")
	}
	// DiskMB is deliberately NOT required: see the field comment. Its absence
	// is recorded in the result rather than blocking the run.

	if len(problems) > 0 {
		return fmt.Errorf("%w: %v", ErrInvalidLimits, problems)
	}
	return nil
}

// NanoCPUs converts CPUMillis to the units Docker expects.
func (l Limits) NanoCPUs() int64 {
	return int64(l.CPUMillis) * 1_000_000
}

// MemoryBytes converts MemoryMB to bytes.
func (l Limits) MemoryBytes() int64 {
	return int64(l.MemoryMB) << 20
}
