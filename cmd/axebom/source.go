package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/axebom/axebom/libs/go-shared/fetcher"
	"github.com/axebom/axebom/libs/go-shared/platform/blob"
	"github.com/axebom/axebom/libs/go-shared/platform/config"
)

// runSource materializes a scan's source archive into a worker's workspace.
//
// # Why this is a CLI subcommand rather than Python
//
// The engine workers are Python and the archive is untrusted content — it is a
// customer's repository. Extracting it safely needs path-traversal, size, inode
// and inflation guards, and those already exist, hardened and tested, in
// fetcher.ExtractTar. Writing a second extractor in Python would mean two
// implementations of the same security-critical logic, and the second one would
// be the weaker.
//
// So the workers shell out here, exactly as they already do for the sandbox
// bridge (`axebom sandbox run`). See CLAUDE.md §Conventions — anything a
// script would do, the CLI does.
//
// # The gap this closes
//
// The fetcher uploads a content-addressed `source.tar.zst` and the orchestrator
// pins `source_archive_ref`, then fans out one job per engine with
// `workspace.artifact_uri` pointing at it. Nothing downloaded it. Every engine
// ran against an empty directory and reported honestly on nothing: syft and
// trivy-fs `partial`, osv-scanner `failed`.
func runSource(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return errors.New("usage: axebom source materialize [flags]")
	}
	switch args[0] {
	case "materialize":
		return sourceMaterialize(ctx, args[1:])
	default:
		return fmt.Errorf("unknown source subcommand %q", args[0])
	}
}

// stampName marks a workspace as completely materialized.
//
// Written LAST, so a directory that exists but has no stamp is a half-finished
// extraction and is treated as absent. The same rule the engine-database
// provisioner uses, and for the same reason: a partial tree that looks complete
// makes an engine report a clean project.
const stampName = ".axebom-source.json"

type sourceStamp struct {
	ArtifactURI    string `json:"artifact_uri"`
	SHA256         string `json:"sha256"`
	Files          int    `json:"files"`
	UncompressedB  int64  `json:"uncompressed_bytes"`
	MaterializedAt string `json:"materialized_at"`
}

func sourceMaterialize(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("source materialize", flag.ContinueOnError)
	var (
		uri    = fs.String("uri", "", "object-storage key of the source archive")
		digest = fs.String("sha256", "", "expected sha256 of the COMPRESSED archive")
		dest   = fs.String("dest", "", "directory to materialize into")
		force  = fs.Bool("force", false, "re-extract even if already materialized")
	)
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr,
			"Usage: axebom source materialize --uri <key> --sha256 <digest> --dest <dir>")
		fmt.Fprintln(os.Stderr,
			"\nDownloads the scan's content-addressed source archive, verifies its digest,\n"+
				"and extracts it through the same guards the fetcher uses. Idempotent: several\n"+
				"engine workers share one scan workspace and may call this concurrently.")
	}
	if err := fs.Parse(args); err != nil {
		return exitError{code: 2, err: err}
	}
	if *uri == "" || *dest == "" {
		fs.Usage()
		return exitError{code: 2, err: errors.New("--uri and --dest are required")}
	}

	// ⚠ ALREADY DONE IS THE COMMON CASE, NOT THE EXCEPTION.
	//
	// A scan fans out one job per engine — six, typically — and every one of
	// them needs the same tree. Re-extracting per engine would multiply the
	// download by six and, worse, let one worker rewrite a directory another is
	// mid-scan on.
	if !*force {
		if st, ok := readStamp(*dest); ok && st.ArtifactURI == *uri {
			fmt.Printf("already materialized: %s (%d files)\n", *dest, st.Files)
			return nil
		}
	}

	cfg, err := config.LoadService("gateway")
	if err != nil {
		return err
	}
	store, err := blob.Open(ctx, cfg.S3)
	if err != nil {
		return fmt.Errorf("open object storage: %w", err)
	}

	// ⚠ EXTRACT TO A SIBLING, THEN RENAME. NEVER INTO dest DIRECTLY.
	//
	// Concurrency here is real: several workers race for the same scan
	// workspace. rename(2) is atomic, so the loser sees the winner's finished
	// tree rather than a half-written one — and no lock file has to be cleaned
	// up after a worker is killed mid-extraction.
	parent := filepath.Dir(*dest)
	if err := os.MkdirAll(parent, 0o755); err != nil { // #nosec G301 -- shared scan workspace
		return fmt.Errorf("preparing %s: %w", parent, err)
	}
	staging, err := os.MkdirTemp(parent, ".materialize-*")
	if err != nil {
		return fmt.Errorf("staging directory: %w", err)
	}
	defer func() { _ = os.RemoveAll(staging) }()

	res, sum, err := extractVerified(ctx, store, *uri, staging)
	if err != nil {
		return err
	}

	// ⚠ VERIFY AFTER EXTRACTION, PUBLISH ONLY AFTER VERIFYING.
	//
	// The digest covers the whole compressed stream, so it cannot be known
	// until the last byte. Extracting first and checking second is therefore
	// unavoidable — what is avoidable is letting unverified content become the
	// workspace, which is why the rename happens below this check and not above
	// it.
	if *digest != "" && sum != *digest {
		return fmt.Errorf(
			"source archive digest mismatch for %s: expected %s, got %s. "+
				"The archive is content-addressed, so this means the object was "+
				"replaced or corrupted; refusing to scan it", *uri, *digest, sum)
	}

	// ⚠ THE ENGINE RUNS AS uid 65534 AND MOUNTS THIS TREE READ-ONLY.
	//
	// os.MkdirTemp creates 0700, and rename preserves it, so the published
	// workspace was root-owned and unreadable by every engine container. The
	// engines did not fail — they walked a directory they could not enter,
	// found nothing, and reported `partial`. Measured: express materialized 213
	// files and syft still reported zero packages.
	//
	// This is the same rule the engine-database provisioner already applies for
	// the same reason (dbsync's _make_world_readable, and the
	// _readable_as_scan_user check that proves it). A tree the scanner cannot
	// read is indistinguishable, in the output, from a project with nothing in
	// it.
	if err := makeReadable(staging); err != nil {
		return err
	}

	if err := writeStamp(staging, sourceStamp{
		ArtifactURI:    *uri,
		SHA256:         sum,
		Files:          res.Files,
		UncompressedB:  res.UncompressedB,
		MaterializedAt: time.Now().UTC().Format(time.RFC3339),
	}); err != nil {
		return err
	}

	if *force {
		_ = os.RemoveAll(*dest)
	}
	if err := os.Rename(staging, *dest); err != nil {
		// Another worker won the race. Its tree is as good as ours — same
		// content-addressed archive — so this is success, not a conflict.
		if st, ok := readStamp(*dest); ok && st.ArtifactURI == *uri {
			fmt.Printf("already materialized by another worker: %s (%d files)\n",
				*dest, st.Files)
			return nil
		}
		return fmt.Errorf("publishing the workspace: %w", err)
	}

	fmt.Printf("materialized %s -> %s (%d files, %d bytes)\n",
		*uri, *dest, res.Files, res.UncompressedB)
	return nil
}

// extractVerified streams the archive into dir, returning the extraction result
// and the sha256 of the COMPRESSED bytes.
func extractVerified(ctx context.Context, store *blob.Store, uri, dir string) (
	fetcher.ExtractResult, string, error,
) {
	rc, counted, err := fetcher.OpenArchive(ctx, store, uri)
	if err != nil {
		return fetcher.ExtractResult{}, "", fmt.Errorf("opening %s: %w", uri, err)
	}
	defer func() { _ = rc.Close() }()

	// The hash is taken on the COMPRESSED side, because that is what the key is
	// derived from. Hashing the decompressed tree would produce a digest that
	// matches nothing anyone recorded.
	hasher := sha256.New()
	counted.Tee(hasher)

	res, err := fetcher.ExtractTar(rc, counted, dir, fetcher.DefaultExtractLimits())
	if err != nil {
		return res, "", fmt.Errorf("extracting %s: %w", uri, err)
	}
	return res, hex.EncodeToString(hasher.Sum(nil)), nil
}

func readStamp(dir string) (sourceStamp, bool) {
	// #nosec G304 -- dir is this process's own workspace argument.
	b, err := os.ReadFile(filepath.Join(dir, stampName))
	if err != nil {
		return sourceStamp{}, false
	}
	var st sourceStamp
	if err := json.Unmarshal(b, &st); err != nil {
		return sourceStamp{}, false
	}
	return st, true
}

func writeStamp(dir string, st sourceStamp) error {
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	// #nosec G306 -- the workspace is read by engine containers running as a
	// different uid; the stamp carries no secret.
	if err := os.WriteFile(filepath.Join(dir, stampName), b, 0o644); err != nil {
		return fmt.Errorf("writing the stamp: %w", err)
	}
	return nil
}

// makeReadable makes a tree readable by any uid.
//
// Directories need the execute bit to be traversable, files only read. Nothing
// is made writable: the engine mounts this read-only and must not be able to
// alter what it is reporting on — a scanner that could modify its input could
// make a report describe something the customer never wrote.
//
// ⚠ ROOT-SCOPED AND BY DESCRIPTOR, BECAUSE THE TREE IS UNTRUSTED.
//
// This is a customer's repository, just extracted. Two separate hazards:
//
//   - filepath.Walk hands back a PATH, and chmod-ing it resolves that path a
//     second time. An entry that was a regular file at Lstat can be a symlink
//     by the time chmod runs, and the chmod then lands outside the tree.
//   - even within one open, chmod-by-path follows symlinks.
//
// os.Root confines every resolution below the workspace, and O_NOFOLLOW plus
// chmod-on-the-descriptor removes the race: the fd is bound to the inode that
// was checked. os.Root.Chmod alone would not be enough — its own documentation
// records that it stays racy on Unix.
func makeReadable(dir string) error {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return fmt.Errorf("opening the workspace root: %w", err)
	}
	defer func() { _ = root.Close() }()

	return makeReadableIn(root, ".")
}

func makeReadableIn(root *os.Root, name string) error {
	info, err := root.Lstat(name)
	if err != nil {
		return err
	}
	// Symlinks carry no meaningful mode of their own, and anything they point
	// at inside the tree is chmod-ed in its own right.
	if info.Mode()&os.ModeSymlink != 0 {
		return nil
	}

	mode := os.FileMode(0o644)
	flags := os.O_RDONLY | syscall.O_NOFOLLOW
	if info.IsDir() {
		mode = 0o755
		flags |= syscall.O_DIRECTORY
	}

	f, err := root.OpenFile(name, flags, 0)
	if err != nil {
		// ELOOP or ENOTDIR means the entry changed between Lstat and open —
		// the race this exists to close. Skipping is correct: an entry that
		// moved under us is not one to chmod.
		return nil //nolint:nilerr // a racing entry is skipped, not fatal
	}
	defer func() { _ = f.Close() }()

	if err := f.Chmod(mode); err != nil {
		return err
	}
	if !info.IsDir() {
		return nil
	}

	entries, err := f.ReadDir(-1)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if err := makeReadableIn(root, filepath.Join(name, e.Name())); err != nil {
			return err
		}
	}
	return nil
}
