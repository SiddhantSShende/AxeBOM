package work

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/axebom/axebom/libs/go-shared/fetcher"
	"github.com/axebom/axebom/libs/go-shared/platform/blob"
	"github.com/axebom/axebom/libs/go-shared/platform/errs"
	"github.com/axebom/axebom/libs/go-shared/projectsource"
)

// Every upload, one workspace.
//
// ⚠ ONLY THE NEWEST UPLOAD WAS EVER SCANNED. The project service answered an
// upload project with `uploads[0]` and the wizard let a user stage several
// files, so a project registered with a source archive AND a lockfile produced a
// BOM of whichever arrived last — with nothing anywhere saying the other had
// been ignored. That is the silent omission invariant 12 names as worse than no
// BOM at all.
//
// Now every upload is placed into the same workspace and the single
// content-addressed archive is built once, afterwards (ADR-0008 unchanged: one
// archive per scan). The layout is contractual — docs/02-CONTRACTS.md §3 — and
// deterministic, so the same uploads always produce the same archive bytes.

// uploadsDir is where a multi-upload project's files land, under the workspace.
const uploadsDir = "uploads"

// maxUploadNameBytes matches the project service's own bound on a stored
// filename, so a single upload's name is never cut shorter than it was stored.
const maxUploadNameBytes = 120

// uploadPlacement is where one upload lands.
type uploadPlacement struct {
	upload projectsource.Upload
	// rel is slash-separated and relative to the workspace root. Empty only for
	// a single source_archive, which is extracted at the root exactly as before.
	rel string
	// extract is true for a source_archive: rel names a directory to extract into.
	extract bool
}

// planUploadLayout decides where every upload lands. Pure and deterministic:
// the same uploads, in any order, always produce the same placements.
//
// ⚠ ONE UPLOAD KEEPS TODAY'S LAYOUT EXACTLY. An archive is extracted at the
// workspace root and a single file is written there under its own name, so a
// project with one upload scans byte-for-byte as it always has and no engine
// sees a different tree.
func planUploadLayout(uploads []projectsource.Upload) []uploadPlacement {
	sorted := make([]projectsource.Upload, len(uploads))
	copy(sorted, uploads)
	// Upload ids are UUIDv7 (project.uploads DEFAULT app.uuid_v7()), so id order
	// is upload order. Sorted here rather than trusted from the wire: the
	// placement must not depend on how the project service happened to order
	// its answer.
	sort.SliceStable(sorted, func(i, j int) bool {
		return strings.ToLower(sorted[i].UploadID) < strings.ToLower(sorted[j].UploadID)
	})

	if len(sorted) == 1 {
		u := sorted[0]
		if u.UploadKind == "source_archive" {
			return []uploadPlacement{{upload: u, extract: true}}
		}
		return []uploadPlacement{{upload: u, rel: uploadEntryName(u.OriginalFilename, "source")}}
	}

	// used holds the first path segment under uploads/, case-folded: two names
	// that differ only in case would collide on a case-insensitive filesystem,
	// and the archive has to mean the same thing wherever it is extracted.
	used := map[string]bool{}
	out := make([]uploadPlacement, 0, len(sorted))
	for _, u := range sorted {
		name := uploadEntryName(u.OriginalFilename, "upload")
		if u.UploadKind == "source_archive" {
			dir := claimName(used, archiveStem(name), u.UploadID)
			out = append(out, uploadPlacement{upload: u, rel: uploadsDir + "/" + dir, extract: true})
			continue
		}
		if key := strings.ToLower(name); !used[key] {
			used[key] = true
			out = append(out, uploadPlacement{upload: u, rel: uploadsDir + "/" + name})
			continue
		}
		// ⚠ A SAME-NAMED FILE KEEPS ITS BASENAME. Engines find lockfiles and
		// manifests by their exact name — package-lock.json, go.sum — so renaming
		// the second `package.json` would hide it from every engine that reads
		// it. It gets a directory of its own, named by its upload id, instead.
		dir := claimName(used, idSuffix(u.UploadID), u.UploadID)
		out = append(out, uploadPlacement{upload: u, rel: uploadsDir + "/" + dir + "/" + name})
	}
	return out
}

// claimName returns want, or a deterministic id-suffixed variant of it, that
// no earlier upload has taken.
func claimName(used map[string]bool, want, uploadID string) string {
	for _, candidate := range []string{
		want,
		want + "-" + idSuffix(uploadID),
		want + "-" + idCompact(uploadID),
	} {
		if key := strings.ToLower(candidate); !used[key] {
			used[key] = true
			return candidate
		}
	}
	// Unreachable for distinct upload ids; still deterministic if it happens.
	for n := 2; ; n++ {
		candidate := fmt.Sprintf("%s-%s-%d", want, idCompact(uploadID), n)
		if key := strings.ToLower(candidate); !used[key] {
			used[key] = true
			return candidate
		}
	}
}

// idCompact is the upload id as lowercase hex with nothing else.
func idCompact(uploadID string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(uploadID) {
		if (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') {
			b.WriteRune(r)
		}
	}
	if b.Len() == 0 {
		return "noid"
	}
	return b.String()
}

// idSuffix is the last twelve hex digits of the upload id.
//
// ⚠ THE LAST, NOT THE FIRST. A UUIDv7 begins with its millisecond timestamp,
// so two uploads made within the same minute share a prefix; the tail is the
// random part.
func idSuffix(uploadID string) string {
	compact := idCompact(uploadID)
	if len(compact) > 12 {
		return compact[len(compact)-12:]
	}
	return compact
}

// archiveSuffixes are stripped from an archive's name to name its directory, so
// `src.zip` lands in `uploads/src/` rather than a directory named like a file.
var archiveSuffixes = []string{".tar.gz", ".tar.zst", ".tgz", ".tzst", ".zip", ".tar"}

func archiveStem(name string) string {
	lower := strings.ToLower(name)
	for _, suffix := range archiveSuffixes {
		if strings.HasSuffix(lower, suffix) && len(name) > len(suffix) {
			return strings.TrimRight(name[:len(name)-len(suffix)], ".")
		}
	}
	return name
}

// windowsReserved are device names a Windows filesystem refuses as a file or
// directory name. Prefixed rather than dropped, so the name still reads.
var windowsReserved = map[string]bool{
	"con": true, "prn": true, "aux": true, "nul": true,
	"com1": true, "com2": true, "com3": true, "com4": true, "com5": true,
	"com6": true, "com7": true, "com8": true, "com9": true,
	"lpt1": true, "lpt2": true, "lpt3": true, "lpt4": true, "lpt5": true,
	"lpt6": true, "lpt7": true, "lpt8": true, "lpt9": true,
}

// uploadEntryName turns an uploaded file's stored name into one path segment.
//
// ⚠ THE CLIENT'S FILENAME IS NEVER TRUSTED, INCLUDING HERE. The project service
// sanitizes a name before storing it, and this used to rely on that and join
// the stored string straight onto the workspace. A second line of defence costs
// nothing: basename only (either separator convention), a safe alphabet, no
// leading dot or dash (a hidden file, or an argument an engine could read as a
// flag), no `..`, and a bounded length.
func uploadEntryName(original, fallback string) string {
	name := original
	if i := strings.LastIndexAny(name, `/\`); i >= 0 {
		name = name[i+1:]
	}

	var b strings.Builder
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9',
			r == '.', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteRune('_')
		}
	}

	// ASCII only by construction, so a byte cut cannot split a rune.
	out := strings.TrimLeft(b.String(), ".-")
	if len(out) > maxUploadNameBytes {
		out = out[:maxUploadNameBytes]
	}
	out = strings.TrimRight(out, ".")
	if out == "" {
		return fallback
	}
	stem := strings.ToLower(out)
	if i := strings.IndexByte(stem, '.'); i >= 0 {
		stem = stem[:i]
	}
	if windowsReserved[stem] {
		out = "_" + out
	}
	return out
}

// uploadBudget is the extraction ceiling shared by every upload in one scan.
//
// ⚠ ONE BUDGET, NOT ONE PER UPLOAD. The byte and file limits bound what a scan
// may place on the fetcher's disk. Applied per upload, ten uploads would be
// allowed ten times the ceiling — the limit would be a suggestion.
type uploadBudget struct {
	lim fetcher.ExtractLimits
	// bytes and files remain across every upload materialized so far.
	bytes int64
	files int
	// combined is true when more than one upload shares the budget, so a limit
	// message can say the limit is over all of them together.
	combined bool
}

func newUploadBudget(lim fetcher.ExtractLimits, uploads int) *uploadBudget {
	if lim.MaxBytes <= 0 {
		lim = fetcher.DefaultExtractLimits()
	}
	return &uploadBudget{lim: lim, bytes: lim.MaxBytes, files: lim.MaxFiles, combined: uploads > 1}
}

func (b *uploadBudget) tooLarge() *fetchFailure {
	if b.combined {
		return &fetchFailure{code: string(errs.FetchArchiveTooLarge), message: fmt.Sprintf(
			"the project's uploads together exceed the %d MiB limit", b.lim.MaxBytes>>20)}
	}
	return &fetchFailure{code: string(errs.FetchArchiveTooLarge), message: fmt.Sprintf(
		"upload exceeds the %d MiB limit", b.lim.MaxBytes>>20)}
}

func (b *uploadBudget) tooManyFiles() *fetchFailure {
	return &fetchFailure{code: string(errs.FetchTooManyFiles), message: fmt.Sprintf(
		"the project's uploads together exceed the %d file limit", b.lim.MaxFiles)}
}

// placeUpload materializes one upload at its planned place under dest.
func (w *Worker) placeUpload(ctx context.Context, p uploadPlacement, dest string, budget *uploadBudget) error {
	if p.upload.StorageRef == "" {
		return &fetchFailure{code: "FETCH_NO_SOURCE", message: "the upload has no stored object"}
	}

	target := dest
	if p.rel != "" {
		// Every segment of rel is already a sanitized name; SafeJoin is the
		// containment check that holds regardless.
		joined, err := fetcher.SafeJoin(dest, p.rel)
		if err != nil {
			var taxonomy *errs.Error
			if errors.As(err, &taxonomy) {
				return &fetchFailure{code: string(taxonomy.Code), message: taxonomy.Message}
			}
			return err
		}
		target = joined
	}

	rc, err := w.store.Get(ctx, p.upload.StorageRef)
	if err != nil {
		if errors.Is(err, blob.ErrNotFound) {
			return &fetchFailure{code: "FETCH_NO_SOURCE",
				message: "the uploaded file could not be found in storage"}
		}
		return fmt.Errorf("read upload: %w", err) // a storage blip; retryable
	}
	defer func() { _ = rc.Close() }()

	if !p.extract {
		if err := os.MkdirAll(filepath.Dir(target), 0o750); err != nil {
			return fmt.Errorf("prepare workspace directory: %w", err)
		}
		return budget.writeFile(rc, target)
	}
	if err := os.MkdirAll(target, 0o750); err != nil {
		return fmt.Errorf("prepare workspace directory: %w", err)
	}
	return budget.extract(p.upload.OriginalFilename, rc, target)
}

// writeFile places a single-file upload — manifest, lockfile, sbom, hbom_csv,
// image_tarball — as-is. One file is a perfectly valid, if tiny, source tree.
func (b *uploadBudget) writeFile(r io.Reader, path string) error {
	if b.files < 1 {
		return b.tooManyFiles()
	}
	// #nosec G304 -- path is this job's own workspace joined with sanitized
	// segments and checked by fetcher.SafeJoin (see placeUpload).
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("create workspace file: %w", err)
	}
	// +1 byte: reading exactly the remaining budget cannot tell "exactly at the
	// limit" from "truncated here".
	n, copyErr := io.Copy(f, io.LimitReader(r, b.bytes+1))
	closeErr := f.Close()
	if copyErr != nil {
		return fmt.Errorf("write workspace file: %w", copyErr)
	}
	if closeErr != nil {
		return fmt.Errorf("write workspace file: %w", closeErr)
	}
	if n > b.bytes {
		return b.tooLarge()
	}
	b.bytes -= n
	b.files--
	return nil
}

// extract stages a source_archive locally and extracts it into dest within
// what remains of the budget.
func (b *uploadBudget) extract(filename string, r io.Reader, dest string) error {
	// ⚠ CHECKED BEFORE EXTRACTING, NOT LEFT TO THE EXTRACTOR. fetcher.ExtractTar
	// and ExtractZip treat a zero MaxBytes as "use the defaults", so an
	// exhausted budget handed to them would reset to the full ceiling.
	if b.bytes <= 0 {
		return b.tooLarge()
	}
	if b.files <= 0 {
		return b.tooManyFiles()
	}

	// zip needs random access to its central directory, so the archive is staged
	// to a local temp file first rather than extracted from the object stream.
	tmp, err := os.CreateTemp("", "axebom-upload-*")
	if err != nil {
		return fmt.Errorf("stage upload: %w", err)
	}
	tmpPath := tmp.Name()
	defer func() {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
	}()

	// The staged COMPRESSED bytes are bounded by the full ceiling, as before; the
	// project service already caps one upload at 256 MiB, so this is depth.
	written, err := io.Copy(tmp, io.LimitReader(r, b.lim.MaxBytes+1))
	if err != nil {
		return fmt.Errorf("stage upload: %w", err)
	}
	if written > b.lim.MaxBytes {
		return &fetchFailure{code: string(errs.FetchArchiveTooLarge),
			message: fmt.Sprintf("upload exceeds the %d MiB limit", b.lim.MaxBytes>>20)}
	}
	if _, err := tmp.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("stage upload: %w", err)
	}

	lim := b.lim
	lim.MaxBytes = b.bytes
	lim.MaxFiles = b.files
	res, err := fetcher.ExtractArchive(filename, tmp, written, dest, lim)
	if err != nil {
		var taxonomy *errs.Error
		if errors.As(err, &taxonomy) {
			switch {
			case b.combined && taxonomy.Code == errs.FetchArchiveTooLarge:
				return b.tooLarge()
			case b.combined && taxonomy.Code == errs.FetchTooManyFiles:
				return b.tooManyFiles()
			}
			return &fetchFailure{code: string(taxonomy.Code), message: taxonomy.Message}
		}
		return fmt.Errorf("extract upload: %w", err)
	}
	b.bytes -= res.UncompressedB
	b.files -= res.Files
	return nil
}

// namedFailure says WHICH upload failed. A fetch that fails over one of five
// uploads has to name it, or the user is left guessing which file to replace.
func namedFailure(u projectsource.Upload, err error) error {
	label := u.OriginalFilename
	if label == "" {
		label = "unnamed upload"
	}
	var fail *fetchFailure
	if errors.As(err, &fail) {
		return &fetchFailure{code: fail.code,
			message: fmt.Sprintf("upload %q (%s): %s", label, u.UploadID, fail.message)}
	}
	return fmt.Errorf("upload %q (%s): %w", label, u.UploadID, err)
}
