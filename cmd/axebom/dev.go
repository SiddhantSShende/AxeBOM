package main

import (
	"context"
	"flag"
	"fmt"
	"os/exec"
	"strings"
)

// devImages are the images `task dev` builds locally, tagged `:dev`
// (deploy/compose/docker-compose.app.yml). Kept as a literal list rather than
// parsed from the compose files at run time: this command has no YAML
// dependency, and the set of AxeBOM-built images changes rarely enough that
// duplicating it here is the honest cost.
var devImages = []string{
	"gateway", "auth", "project", "scan-orchestrator", "report",
	"campaign", "comment", "notification", "fetcher", "worker", "cli", "frontend",
}

func runDev(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: axebom dev <snapshot|rollback>")
	}
	switch args[0] {
	case "snapshot":
		return devSnapshot(ctx, args[1:])
	case "rollback":
		return devRollback(ctx, args[1:])
	default:
		return fmt.Errorf("unknown dev subcommand %q", args[0])
	}
}

// devSnapshot tags every locally-built `:dev` image as `:good`.
//
// `task dev` calls this only after `axebom health --wait` has confirmed the
// whole stack is actually serving — so `:good` always names images already
// proven to work, never merely images that finished building. That is the
// entire rollback mechanism: `devRollback` just retags `:good` back to
// `:dev` and lets `docker compose up -d --no-build` recreate containers from
// it, with no registry, CI or production deploy pipeline required.
func devSnapshot(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("dev snapshot", flag.ExitOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}

	var tagged, skipped []string
	for _, svc := range devImages {
		image := "axebom/" + svc
		if !imageExists(ctx, image+":dev") {
			skipped = append(skipped, svc)
			continue
		}
		if err := dockerTag(ctx, image+":dev", image+":good"); err != nil {
			return fmt.Errorf("dev snapshot: tag %s: %w", svc, err)
		}
		tagged = append(tagged, svc)
	}

	fmt.Printf("snapshotted %d image(s) as last-known-good: %s\n", len(tagged), joinOrNone(tagged))
	if len(skipped) > 0 {
		fmt.Printf("skipped (no :dev image built yet): %s\n", joinOrNone(skipped))
	}
	return nil
}

// devRollback retags every service's last snapshotted `:good` image back to
// `:dev`. The caller (`task dev:rollback`) still has to run
// `docker compose up -d --no-build` afterward to recreate containers from it —
// this command only touches image tags, never containers, so a caller that
// wants to inspect before recreating can do that.
func devRollback(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("dev rollback", flag.ExitOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}

	var restored, missing []string
	for _, svc := range devImages {
		image := "axebom/" + svc
		if !imageExists(ctx, image+":good") {
			missing = append(missing, svc)
			continue
		}
		if err := dockerTag(ctx, image+":good", image+":dev"); err != nil {
			return fmt.Errorf("dev rollback: restore %s: %w", svc, err)
		}
		restored = append(restored, svc)
	}

	if len(restored) == 0 {
		return fmt.Errorf("no service has a snapshotted :good image yet — " +
			"run `task dev` successfully at least once before rolling back")
	}

	fmt.Printf("restored %d image(s) from last-known-good: %s\n", len(restored), joinOrNone(restored))
	if len(missing) > 0 {
		// Not fatal: a service added after the last successful snapshot, or one
		// nobody has built locally, has nothing to roll back to — every other
		// service still gets restored.
		fmt.Printf("no snapshot to restore, left as-is: %s\n", joinOrNone(missing))
	}
	return nil
}

func imageExists(ctx context.Context, ref string) bool {
	// #nosec G204 -- ref is built from the literal devImages list above plus a
	// fixed ":dev"/":good" suffix, never from caller-supplied input.
	cmd := exec.CommandContext(ctx, "docker", "image", "inspect", ref)
	return cmd.Run() == nil
}

func dockerTag(ctx context.Context, src, dst string) error {
	// #nosec G204 -- src/dst are built the same way as imageExists' ref.
	cmd := exec.CommandContext(ctx, "docker", "tag", src, dst)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func joinOrNone(names []string) string {
	if len(names) == 0 {
		return "none"
	}
	return strings.Join(names, ", ")
}
