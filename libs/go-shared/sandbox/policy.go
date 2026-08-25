// Package sandbox runs untrusted commands in an ephemeral container.
//
// ⚠ THIS IS THE HIGHEST-RISK COMPONENT IN THE PRODUCT.
//
// AxeBOM executes third-party scanner binaries over untrusted user code.
// That is remote code execution by design; the only question is blast radius,
// and everything in this package exists to bound it.
//
// The controls in Policy and Limits are NOT defaults to tune later. Loosening
// any of them is a security decision requiring an ADR
// (docs/05-SECURITY-MODEL.md §3). They are expressed as an explicit struct with
// an unsafe-by-omission zero value — see Policy.Validate — so a caller cannot
// get a permissive sandbox by forgetting a field.
package sandbox

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// NetworkMode is the container's network posture.
type NetworkMode string

const (
	// NetworkNone is the default and the only mode most engines get. It makes
	// exfiltration and SSRF from inside a scan impossible rather than merely
	// filtered.
	NetworkNone NetworkMode = "none"

	// NetworkAllowlist routes through an egress proxy restricted to named
	// upstream hosts. For engines that genuinely need a vulnerability-database
	// refresh — never open egress.
	//
	// ⚠ REQUIRES ProxyNetwork TO BE SET. The proxy itself is not built yet
	// (Phase 16), and Validate REFUSES this mode without one rather than
	// letting it degrade into open egress. A mode named "allowlist" that is
	// actually unrestricted is worse than no mode at all: it tells a reader
	// the traffic is constrained when it is not.
	NetworkAllowlist NetworkMode = "allowlist"

	// NetworkEgress is UNRESTRICTED outbound access.
	//
	// ⚠ THE FETCHER ONLY, AND IT IS NAMED HONESTLY.
	//
	// A clone has to reach the forge, and no egress proxy exists yet. Rather
	// than pretend that traffic is filtered, this mode says what it is. Two
	// things bound it:
	//
	//	the URL is validated before the container starts, and
	//	the fetcher is small, separate, and holds no scanner.
	//
	// What it does NOT bound: a compromised git binary, or a malicious server
	// redirecting the clone at the transport level. Recorded in docs/STATE.md
	// as a known gap — the fix is the egress proxy, and it belongs with the
	// hardening phase.
	//
	// No engine may use this. Engines get NetworkNone.
	NetworkEgress NetworkMode = "egress"
)

// Policy is the security configuration of a sandbox container.
//
// Every field is REQUIRED to be set to a safe value; Validate refuses anything
// else. A zero Policy is invalid rather than permissive, because the failure
// mode of "forgot to set ReadOnlyRootfs" must be a startup error and not a
// writable container.
type Policy struct {
	// Network is the network posture.
	Network NetworkMode

	// AllowlistHosts are the only hosts reachable under NetworkAllowlist.
	// Ignored — and required to be empty — under NetworkNone.
	AllowlistHosts []string

	// ReadOnlyRootfs makes the image's filesystem immutable. Defeats
	// persistence and tampering; the workspace tmpfs is the only writable path.
	ReadOnlyRootfs bool

	// NoNewPrivileges blocks setuid escalation inside the container. Without
	// it, a setuid binary in the scanner image is a path to root-in-container.
	NoNewPrivileges bool

	// DropAllCapabilities drops every Linux capability. A scanner needs none:
	// it reads files and writes to stdout.
	DropAllCapabilities bool

	// User is the uid:gid the process runs as. Must be non-root.
	//
	// A high uid is deliberate: uid 0 in a container without user namespaces is
	// uid 0 on the host if anything escapes, and a low uid may collide with a
	// host account that has meaning.
	User string

	// SeccompProfile is the seccomp profile name. "" means Docker's default
	// profile, which blocks roughly 44 syscalls including the ones used for
	// most kernel-surface attacks. "unconfined" is REFUSED by Validate.
	SeccompProfile string

	// WorkspacePath is where the source archive is mounted, as a tmpfs.
	WorkspacePath string

	// TmpfsSizeMB bounds the writable workspace. Without it a tmpfs can consume
	// host RAM until the kernel OOM-kills something that is not the container.
	TmpfsSizeMB int

	// ProxyNetwork is the Docker network the egress proxy is attached to.
	// REQUIRED by NetworkAllowlist, which is refused without it.
	ProxyNetwork string
}

// DefaultPolicy returns the posture every engine gets unless an ADR says
// otherwise.
func DefaultPolicy() Policy {
	return Policy{
		Network:             NetworkNone,
		ReadOnlyRootfs:      true,
		NoNewPrivileges:     true,
		DropAllCapabilities: true,
		// 65534 is `nobody` on most distributions. Combined with a read-only
		// rootfs there is nothing on the image it can write.
		User:           "65534:65534",
		SeccompProfile: "", // Docker's default profile
		WorkspacePath:  "/workspace",
		TmpfsSizeMB:    2048,
	}
}

// UserIDs parses User into numeric uid and gid.
//
// The tmpfs needs them: a tmpfs mounts root-owned and 0755 by default, so a
// container running as a non-root user cannot write to its own workspace
// unless the mount is created owned by that user.
//
// Falls back to 65534 (nobody) if User is not numeric — a named user cannot be
// resolved from outside the container, and defaulting to nobody is the safe
// direction to be wrong in.
func (p Policy) UserIDs() (uid, gid int) {
	uid, gid = 65534, 65534

	parts := strings.SplitN(p.User, ":", 2)
	if v, err := strconv.Atoi(parts[0]); err == nil {
		uid = v
	}
	if len(parts) == 2 {
		if v, err := strconv.Atoi(parts[1]); err == nil {
			gid = v
		}
	} else {
		gid = uid
	}
	return uid, gid
}

// ErrUnsafePolicy is returned when a policy would weaken the sandbox.
var ErrUnsafePolicy = errors.New("unsafe sandbox policy")

// Validate refuses a policy that is not safe.
//
// This runs on EVERY container creation, not once at startup: a policy can be
// built anywhere, and the check has to be where the container is made.
func (p Policy) Validate() error {
	var problems []string

	switch p.Network {
	case NetworkNone:
		if len(p.AllowlistHosts) > 0 {
			problems = append(problems,
				"AllowlistHosts is set but Network is none — one of the two is a mistake")
		}

	case NetworkAllowlist:
		if len(p.AllowlistHosts) == 0 {
			problems = append(problems,
				"Network is allowlist but no hosts are listed, which would be open egress")
		}
		// Refused rather than degraded. A mode named "allowlist" running
		// unfiltered would tell every reader the traffic is constrained when
		// it is not — and that misreading is exactly how an engine ends up
		// with open egress nobody noticed.
		if p.ProxyNetwork == "" {
			problems = append(problems,
				"Network is allowlist but no ProxyNetwork is configured; the egress proxy "+
					"is not built yet (Phase 16), and this mode must not silently become open egress")
		}

	case NetworkEgress:
		// Permitted, and deliberately not disguised. Only the fetcher sets it.

	default:
		problems = append(problems, fmt.Sprintf("unknown network mode %q", p.Network))
	}

	if !p.ReadOnlyRootfs {
		problems = append(problems, "ReadOnlyRootfs is false: the scanner could modify its own image layer")
	}
	if !p.NoNewPrivileges {
		problems = append(problems, "NoNewPrivileges is false: a setuid binary becomes a privilege escalation")
	}
	if !p.DropAllCapabilities {
		problems = append(problems, "DropAllCapabilities is false: a scanner needs no capabilities")
	}

	switch {
	case p.User == "":
		problems = append(problems, "User is empty, so the container would run as root")
	case p.User == "0", p.User == "0:0", strings.HasPrefix(p.User, "root"):
		problems = append(problems, "User is root")
	}

	if strings.EqualFold(p.SeccompProfile, "unconfined") {
		problems = append(problems, "SeccompProfile is unconfined, which exposes the whole syscall surface")
	}
	if p.WorkspacePath == "" || !strings.HasPrefix(p.WorkspacePath, "/") {
		problems = append(problems, "WorkspacePath must be an absolute path")
	}
	if p.TmpfsSizeMB <= 0 {
		problems = append(problems, "TmpfsSizeMB must be positive, or the workspace can exhaust host memory")
	}

	if len(problems) > 0 {
		return fmt.Errorf("%w: %s", ErrUnsafePolicy, strings.Join(problems, "; "))
	}
	return nil
}

// ---------------------------------------------------------------------------
// Forbidden commands
// ---------------------------------------------------------------------------

// forbiddenCommands execute arbitrary code FROM THE REPOSITORY.
//
// npm lifecycle scripts and Gradle build files are the classic vectors: a
// `postinstall` hook or a `build.gradle` line runs whatever the repository
// author wrote, with our network and our filesystem. The sandbox bounds that,
// but the right answer is not to run it at all.
//
// Lockfile and manifest PARSING only (docs/05-SECURITY-MODEL.md §3).
var forbiddenCommands = map[string][]string{
	"npm":      {"install", "ci", "update", "rebuild", "exec", "run"},
	"yarn":     nil, // any yarn invocation resolves and runs scripts
	"pnpm":     {"install", "add", "update", "exec", "run"},
	"mvn":      nil,
	"gradle":   nil,
	"pip":      {"install", "download", "wheel"},
	"pip3":     {"install", "download", "wheel"},
	"python":   {"setup.py"},
	"make":     nil,
	"cargo":    {"build", "run", "install", "test"},
	"go":       {"generate", "run"},
	"bundle":   {"install"},
	"composer": {"install", "update"},
}

// ErrForbiddenCommand is returned when a command would execute user build
// tooling.
var ErrForbiddenCommand = errors.New("command executes user build tooling")

// CheckCommand refuses a command that would run the repository's own build.
//
// Enforced HERE, in the sandbox, rather than trusting each adapter: an adapter
// is written per engine by whoever adds the engine, and "remember not to run
// npm install" is exactly the kind of rule that survives three adapters and
// fails on the fourth.
func CheckCommand(argv []string) error {
	if len(argv) == 0 {
		return errors.New("sandbox: empty command")
	}

	base := argv[0]
	if i := strings.LastIndexAny(base, `/\`); i >= 0 {
		base = base[i+1:]
	}
	base = strings.TrimSuffix(strings.ToLower(base), ".exe")

	subcommands, listed := forbiddenCommands[base]
	if !listed {
		// A shell is not on the list because a shell is not inherently a build
		// tool — but a shell invoking one is, so inspect the whole argv below.
		return checkShellForm(argv)
	}
	if subcommands == nil {
		return fmt.Errorf("%w: %q resolves and executes code from the repository", ErrForbiddenCommand, base)
	}
	for _, arg := range argv[1:] {
		for _, sub := range subcommands {
			if strings.EqualFold(arg, sub) {
				return fmt.Errorf("%w: %q %q runs repository-supplied scripts",
					ErrForbiddenCommand, base, sub)
			}
		}
	}
	return checkShellForm(argv)
}

// checkShellForm catches `sh -c "npm install"`, where the forbidden command is
// inside a string argument rather than argv[0].
func checkShellForm(argv []string) error {
	joined := strings.ToLower(strings.Join(argv, " "))
	for _, pattern := range []string{
		"npm install", "npm ci", "npm run", "yarn install", "yarn ",
		"pnpm install", "mvn ", "gradle ", "gradlew", "pip install",
		"pip3 install", "setup.py", "cargo build", "go generate",
		"bundle install", "composer install", "make ",
	} {
		if strings.Contains(joined, pattern) {
			return fmt.Errorf("%w: the command contains %q", ErrForbiddenCommand, strings.TrimSpace(pattern))
		}
	}
	return nil
}
