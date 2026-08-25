package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/axebom/axebom/libs/go-shared/fetcher"
	"github.com/axebom/axebom/libs/go-shared/sandbox"
	"github.com/axebom/axebom/libs/go-shared/toolctl"
)

// toolctlPull pre-pulls every container-mode engine image.
//
// # Why this command has to exist
//
// Engines run with `--network=none`. That is the central sandbox control: we
// execute third-party binaries over untrusted user code, so they get no network
// at all. It also means an engine container CANNOT PULL ITS OWN IMAGE.
//
// `toolctl sync` skips container-mode engines with the note that "containers
// are pulled by the sandbox at run time". They are not, and cannot be. The
// sandbox has EnsureImage — deliberately kept out of Run, precisely so pulling
// never happens inside a sandboxed execution — but nothing ever called it.
//
// The result, on a machine that has not happened to pull the images by other
// means, is every container engine reporting:
//
//	ENGINE_UNAVAILABLE: syft could not be started: sandbox: create container:
//	No such image: anchore/syft:v1.51.0
//
// which is an honest gap, correctly reported — and completely avoidable. This
// is the provisioning step that avoids it, and it is the container-mode
// counterpart to `toolctl sync` for binaries and `dbsync` for databases.
//
// Pulling is an OPERATOR action with network, exactly like database
// provisioning: no user repository is mounted and no scan is in flight.
func toolctlPull(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("toolctl pull", flag.ExitOnError)
	path := manifestFlag(fs)
	only := fs.String("only", "", "pull a single engine by id")
	parallel := fs.Int("parallel", 3, "concurrent pulls")
	timeout := fs.Duration("timeout", 20*time.Minute, "overall timeout")
	if err := fs.Parse(args); err != nil {
		return err
	}

	m, err := loadManifest(*path)
	if err != nil {
		return err
	}

	runner, err := sandbox.NewDockerRunner(nil)
	if err != nil {
		return fmt.Errorf("%w\n\nIs the Docker daemon running? `task preflight` reports its status", err)
	}

	type job struct {
		id  string
		ref string
	}
	var jobs []job

	for _, t := range m.Tools {
		if *only != "" && t.ID != *only {
			continue
		}
		r := toolctl.Resolve(t, m.Defaults)
		if r.Mode != toolctl.ModeContainer || r.ImageRef == "" {
			continue
		}
		jobs = append(jobs, job{id: t.ID, ref: r.ImageRef})
	}

	// The fetcher's git image is NOT in the manifest — it is not a scanner, it
	// is how source is materialized — but it is pulled here for exactly the
	// same reason: the clone runs in a container that cannot fetch its own
	// image. Omitting it made every scan fail at the first step with
	// "No such image: alpine/git:latest", after the fetch job had already been
	// queued and retried three times.
	if *only == "" || *only == "fetcher" {
		jobs = append(jobs, job{id: "fetcher-git", ref: fetcher.GitImage})
	}

	if len(jobs) == 0 {
		if *only != "" {
			return fmt.Errorf("engine %q is not a container-mode engine, or is not in the manifest", *only)
		}
		fmt.Println("no container-mode engines in the manifest")
		return nil
	}

	sort.Slice(jobs, func(i, k int) bool { return jobs[i].id < jobs[k].id })

	ctx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()

	fmt.Printf("Pulling %d engine image(s). Images are large; the first run takes a while.\n\n", len(jobs))

	if *parallel < 1 {
		*parallel = 1
	}
	sem := make(chan struct{}, *parallel)
	var mu sync.Mutex
	var wg sync.WaitGroup

	failures := map[string]error{}

	for _, j := range jobs {
		wg.Add(1)
		go func(j job) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			start := time.Now()
			err := runner.EnsureImage(ctx, j.ref)

			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				failures[j.id] = err
				fmt.Printf("  FAIL  %-20s %s\n        %v\n", j.id, j.ref, err)
				return
			}
			fmt.Printf("  ok    %-20s %s  (%s)\n", j.id, j.ref, time.Since(start).Round(time.Second))
		}(j)
	}
	wg.Wait()

	fmt.Printf("\n%d pulled, %d failed\n", len(jobs)-len(failures), len(failures))

	if len(failures) > 0 {
		ids := make([]string, 0, len(failures))
		for id := range failures {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		fmt.Fprintf(os.Stderr,
			"\nThose engines will report `unavailable` with a stated reason rather than\n"+
				"silently returning nothing. Re-run to retry: %s\n",
			"axebom toolctl pull --only "+strings.Join(ids, " / --only "))
		return exitError{code: 1}
	}
	return nil
}
