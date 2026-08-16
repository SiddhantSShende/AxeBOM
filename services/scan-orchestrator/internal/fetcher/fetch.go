package fetcher

import (
	"context"
	"regexp"
	"strings"
	"time"

	"github.com/encorebom/encorebom/libs/go-shared/platform/errs"
	"github.com/encorebom/encorebom/libs/go-shared/sandbox"
)

// Cloning untrusted repositories.
//
// ADR-0008: the fetcher materializes source EXACTLY ONCE and holds the only
// credentials in the system. Everything downstream reads a content-addressed
// archive, so compromising a scanner yields the code it was already scanning —
// not a token, not another tenant's data.

// GitImage is the image the clone runs in.
//
// Pinned by tag here; production pins by DIGEST, because a mutable reference
// means the provenance recorded in a report may not describe what actually ran.
const GitImage = "alpine/git:latest"

// CloneRequest describes one clone.
type CloneRequest struct {
	// RepoURL must already have passed ValidateURL.
	RepoURL string
	// Ref is a branch or tag. Empty means the default branch.
	Ref string

	// Token authenticates a private repository.
	//
	// ⚠ NEVER REACHES ARGV. It travels in the environment and is consumed by a
	// credential helper — see cloneArgs. argv is world-readable through
	// /proc/<pid>/cmdline, so a token there is visible to every process on the
	// host, including any other container sharing the PID namespace.
	Token string

	// Timeout bounds the clone. Defeats slow-loris.
	Timeout time.Duration
}

// CloneResult is what a clone produced.
type CloneResult struct {
	// CommitSHA is the exact commit materialized.
	//
	// ⚠ WRITTEN EXACTLY ONCE PER SCAN, IMMUTABLE THEREAFTER. It appears in the
	// provenance manifest and in every report; a scan whose commit changed
	// mid-flight describes a codebase that never existed.
	CommitSHA string
	// WorkspacePath is where the source was materialized inside the sandbox.
	WorkspacePath string
	Duration      time.Duration
}

// commitSHAPattern validates a git object id.
//
// The commit sha comes from output produced INSIDE the sandbox, over untrusted
// input, so it is parsed strictly rather than trusted: a repository that can
// influence this string could otherwise inject arbitrary text into a
// compliance report and into a database column.
var commitSHAPattern = regexp.MustCompile(`^[0-9a-f]{40}$|^[0-9a-f]{64}$`)

// cloneArgs builds the git command line.
//
// ⚠ EVERY FLAG HERE IS A DEFENCE. In order:
//
//	GIT_ALLOW_PROTOCOL=https      (env, below) — the definitive fix for ext::,
//	                              which executes an arbitrary command from a URL
//	-c core.hooksPath=/dev/null   repository-supplied hooks never run. A repo
//	                              with .git/hooks/post-checkout would otherwise
//	                              execute it during the clone itself
//	-c core.symlinks=false        symlinks are written as plain files, so a
//	                              link cannot redirect a later write out of the
//	                              workspace
//	-c protocol.ext.allow=never   belt and braces with GIT_ALLOW_PROTOCOL
//	-c protocol.file.allow=never  submodule and alternate paths to the local disk
//	--no-recurse-submodules       submodule URLs are attacker-controlled, and a
//	                              recursive clone would fetch them unvalidated
//	--depth 1 --single-branch     we need one commit, not the history
//	--no-tags                     tags are attacker-named refs we do not need
//
// The credential helper reads the token from the ENVIRONMENT. The helper script
// itself is in argv — that is fine, it contains no secret — while the token is
// not.
func cloneArgs(repoURL, ref string, withCredential bool) []string {
	args := []string{
		"git",
		"-c", "core.hooksPath=/dev/null",
		"-c", "core.symlinks=false",
		"-c", "protocol.ext.allow=never",
		"-c", "protocol.file.allow=never",
		"-c", "protocol.version=2",
		// Refuse interactive prompts: without this a private repository with no
		// usable credential HANGS waiting for a password until the wall clock.
		"-c", "core.askpass=",
	}

	if withCredential {
		// `!f() { ... }; f` is git's shell-helper form. It echoes the token from
		// the environment; the token never appears here.
		args = append(args, "-c",
			`credential.helper=!f() { echo "username=x-access-token"; echo "password=$GIT_FETCH_TOKEN"; }; f`)
	}

	args = append(args,
		"clone",
		"--depth", "1",
		"--single-branch",
		"--no-tags",
		"--no-recurse-submodules",
		"--quiet",
	)
	if ref != "" {
		args = append(args, "--branch", ref)
	}
	// `--` terminates options, so a repository URL beginning with a dash cannot
	// be read as a flag.
	args = append(args, "--", repoURL, ".")
	return args
}

// Clone materializes a repository inside the sandbox.
//
// The clone runs in a container with the same policy as any engine, except that
// it MUST have network access — it is fetching. That is the one place network
// is unavoidable, and it is why the fetcher is small, separate, and the only
// component holding a credential.
func Clone(ctx context.Context, runner sandbox.Runner, req CloneRequest,
	policy sandbox.Policy, limits sandbox.Limits,
) (CloneResult, error) {
	u, err := ValidateURL(req.RepoURL)
	if err != nil {
		return CloneResult{}, err
	}
	if req.Timeout > 0 {
		limits.WallClock = req.Timeout
	}

	env := map[string]string{
		// ⚠ THE DEFINITIVE ext:: FIX. Even if a URL slipped past ValidateURL,
		// git itself refuses any transport not listed here.
		"GIT_ALLOW_PROTOCOL": "https",
		// No terminal prompts, ever: a prompt turns a bad credential into a
		// hang that consumes the whole wall clock.
		"GIT_TERMINAL_PROMPT": "0",
		"GIT_CONFIG_NOSYSTEM": "1",
		"HOME":                policy.WorkspacePath,
	}

	// The token is passed under a name assertNoSecrets would normally REFUSE,
	// which is exactly right: this is the one component permitted to hold one,
	// and it says so explicitly rather than sneaking a credential past a guard
	// that exists to stop every other component doing it.
	if req.Token != "" {
		env["GIT_FETCH_TOKEN"] = req.Token
	}

	argv := cloneArgs(u.String(), req.Ref, req.Token != "")

	// Clone and read the resulting commit in ONE container run. Two runs would
	// mean two workspaces, and the second could not see what the first wrote.
	script := strings.Join(quoteArgs(argv), " ") +
		" && git rev-parse HEAD"

	spec := sandbox.Spec{
		Image: GitImage,
		// The image's ENTRYPOINT is ["git"], so it must be replaced or the
		// command becomes `git sh -c ...`.
		Entrypoint: []string{"sh"},
		Argv:       []string{"-c", script},
		Policy:     policy,
		Limits:     limits,
		Env:        env,
	}

	// ⚠ THE ONE PLACE IN THE PRODUCT THAT SETS THIS.
	//
	// The sandbox refuses credential-shaped environment variables by design
	// (ADR-0008). The fetcher is the single documented exception, and it says
	// so with an explicit flag rather than by weakening the check — a reviewer
	// asking "who may hold a token" greps CredentialsPermitted and finds
	// exactly one call site.
	spec.CredentialsPermitted = req.Token != ""
	spec.Labels = map[string]string{"encorebom.role": "fetcher"}

	started := time.Now()
	res, err := runner.Run(ctx, spec)
	if err != nil {
		return CloneResult{}, err
	}

	if res.TimedOut {
		return CloneResult{}, errs.New(errs.FetchCloneTimeout,
			"the clone exceeded its time limit")
	}
	if res.ExitCode != 0 {
		return CloneResult{}, classifyCloneFailure(res)
	}

	sha := lastNonEmptyLine(string(res.Stdout))
	if !commitSHAPattern.MatchString(sha) {
		// Strictly parsed: this value reaches a database column and a
		// compliance report, and it came from output produced over untrusted
		// input.
		return CloneResult{}, errs.Newf(errs.FetchAuthFailed,
			"the clone did not report a valid commit id (got %q)", truncateForError(sha))
	}

	return CloneResult{
		CommitSHA:     sha,
		WorkspacePath: policy.WorkspacePath,
		Duration:      time.Since(started),
	}, nil
}

// classifyCloneFailure turns git's exit into an actionable error.
//
// The distinction matters for retry: an auth failure will fail again, a network
// blip will not, and burning retries on the former delays every other job.
func classifyCloneFailure(res sandbox.Result) error {
	out := strings.ToLower(string(res.Stderr) + string(res.Stdout))

	switch {
	case strings.Contains(out, "authentication failed"),
		strings.Contains(out, "could not read username"),
		strings.Contains(out, "invalid username or password"),
		strings.Contains(out, "repository not found"):
		// "Repository not found" is what GitHub returns for a PRIVATE
		// repository with no valid credential — deliberately, so an
		// unauthenticated caller cannot enumerate private repositories. Treated
		// as auth rather than not-found for the same reason.
		return errs.New(errs.FetchAuthFailed,
			"the repository could not be read; check that it exists and the token grants access")

	case strings.Contains(out, "could not resolve host"),
		strings.Contains(out, "network is unreachable"),
		strings.Contains(out, "connection refused"),
		strings.Contains(out, "connection timed out"):
		return errs.New(errs.ScanSourceUnreachable, "the repository host could not be reached")

	case strings.Contains(out, "not found in upstream"),
		strings.Contains(out, "remote branch"):
		return errs.New(errs.ValidationFieldInvalid, "the requested branch does not exist")

	default:
		return errs.Newf(errs.ScanSourceUnreachable,
			"the clone failed (exit %d): %s", res.ExitCode, truncateForError(string(res.Stderr)))
	}
}

// quoteArgs makes an argv safe to embed in a shell command.
//
// Single-quoted with the standard `'\”` escape, so a repository URL containing
// a quote cannot break out of the string and become a second command. The URL
// has already passed ValidateURL — this is the second layer, because one
// layer between untrusted input and a shell is not enough.
func quoteArgs(argv []string) []string {
	out := make([]string, 0, len(argv))
	for _, a := range argv {
		out = append(out, "'"+strings.ReplaceAll(a, "'", `'\''`)+"'")
	}
	return out
}

func lastNonEmptyLine(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		if line := strings.TrimSpace(lines[i]); line != "" {
			return line
		}
	}
	return ""
}

// truncateForError bounds text that goes into an error message.
//
// Scanner and git output is attacker-influenced; an unbounded error string ends
// up in a log, a database column and a UI.
func truncateForError(s string) string {
	s = strings.TrimSpace(s)
	// Newlines forge log lines.
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	if len(s) > 300 {
		return s[:300] + "…"
	}
	return s
}

// FetcherPolicy returns the sandbox policy for a clone.
//
// Identical to the engine policy EXCEPT for network access, which a fetch
// obviously requires. Everything else — read-only rootfs, dropped capabilities,
// non-root, seccomp, quotas — is unchanged, because "it needs the network" is
// not a reason to relax anything else.
func FetcherPolicy() sandbox.Policy {
	p := sandbox.DefaultPolicy()
	// ⚠ UNRESTRICTED EGRESS, NAMED AS SUCH.
	//
	// A clone has to reach the forge, and the egress proxy that would constrain
	// it does not exist yet. Calling this "allowlist" while it ran unfiltered
	// would be the dishonest option — a reader would believe the traffic was
	// constrained when it was not.
	//
	// What still bounds it: the URL passed ValidateURL before the container
	// started, the fetcher runs no scanner, and everything else in the policy
	// (read-only rootfs, dropped capabilities, non-root, seccomp, quotas) is
	// unchanged. "It needs the network" is not a reason to relax anything else.
	//
	// Recorded as a known gap in docs/STATE.md; the fix is the Phase 16 proxy.
	p.Network = sandbox.NetworkEgress
	return p
}
