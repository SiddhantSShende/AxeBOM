package fetcher

import (
	"archive/zip"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/klauspost/compress/zstd"

	"github.com/axebom/axebom/libs/go-shared/platform/errs"
)

// ExtractArchive extracts an uploaded source archive of unknown-but-declared
// format into dest, dispatching on the filename's extension.
//
// ⚠ THE FORMAT IS DECLARED, NEVER SNIFFED.
//
// Guessing a format from magic bytes to "be helpful" about a missing or wrong
// extension is exactly how a parser ends up extracting a format nobody
// validated the guards for. An unrecognized extension is refused with a clear
// reason instead.
//
// f must be seekable — zip needs random access to its central directory,
// which sits at the end of the file — so the caller stages an upload to a
// local temp file first rather than extracting straight from the object-store
// stream. That is also what lets the SAME f serve every branch below.
func ExtractArchive(filename string, f *os.File, size int64, dest string, lim ExtractLimits) (ExtractResult, error) {
	lower := strings.ToLower(filename)

	switch {
	case strings.HasSuffix(lower, ".zip"):
		return ExtractZip(f, size, dest, lim)

	case strings.HasSuffix(lower, ".tar.zst") || strings.HasSuffix(lower, ".tzst"):
		counted := NewCountingReader(f)
		zr, err := zstd.NewReader(counted)
		if err != nil {
			return ExtractResult{}, errs.Wrap(err, errs.FetchPathTraversal, "corrupt archive")
		}
		defer zr.Close() // returns nothing
		return ExtractTar(zr, counted, dest, lim)

	case strings.HasSuffix(lower, ".tar.gz") || strings.HasSuffix(lower, ".tgz"):
		counted := NewCountingReader(f)
		gr, err := gzip.NewReader(counted)
		if err != nil {
			return ExtractResult{}, errs.Wrap(err, errs.FetchPathTraversal, "corrupt archive")
		}
		defer func() { _ = gr.Close() }()
		return ExtractTar(gr, counted, dest, lim)

	case strings.HasSuffix(lower, ".tar"):
		// No compression, so there is no inflation ratio to compute — MaxBytes
		// alone bounds an uncompressed archive, and it is enforced unconditionally
		// inside copyGuarded regardless of whether a ratio was ever evaluated.
		return ExtractTar(f, nil, dest, lim)

	default:
		return ExtractResult{}, errs.Newf(errs.FetchUnsupportedArchiveFormat,
			"%q is not a recognized source archive format; use .zip, .tar, .tar.gz or .tar.zst", filename)
	}
}

// ExtractZip extracts a zip archive into dest, enforcing the same guards as
// ExtractTar: path traversal, links refused, a file-count ceiling, and a
// decompression-bomb ceiling on total bytes written.
//
// Zip differs from tar in one structural way that shapes this signature: the
// central directory sits at the END of the file, so a zip reader needs random
// access (io.ReaderAt) rather than a single forward pass. size is the whole
// archive's byte count, known from the upload before extraction starts.
func ExtractZip(ra io.ReaderAt, size int64, dest string, lim ExtractLimits) (ExtractResult, error) {
	if lim.MaxBytes <= 0 {
		lim = DefaultExtractLimits()
	}

	zr, err := zip.NewReader(ra, size)
	if err != nil {
		return ExtractResult{}, errs.Wrap(err, errs.FetchPathTraversal, "corrupt archive")
	}

	destAbs, err := filepath.Abs(dest)
	if err != nil {
		return ExtractResult{}, fmt.Errorf("resolve destination: %w", err)
	}
	// EvalSymlinks on the DESTINATION itself, exactly as ExtractTar does: if
	// dest is reached through a symlink, every containment check below would
	// compare against the wrong prefix and conclude an escape was fine.
	if resolved, err := filepath.EvalSymlinks(destAbs); err == nil {
		destAbs = resolved
	}

	var result ExtractResult

	for _, entry := range zr.File {
		if result.Files >= lim.MaxFiles {
			return result, errs.Newf(errs.FetchTooManyFiles,
				"archive exceeds the %d file limit", lim.MaxFiles)
		}

		mode := entry.Mode()
		switch {
		case mode&os.ModeSymlink != 0:
			// A zip stores a symlink's target as the entry's "content" when the
			// archiver recorded the Unix mode bits. Refused outright, same reason
			// as tar: a link created early can redirect a later entry outside the
			// workspace, so "check where it points" is racy against archive order.
			result.SkippedEntries = append(result.SkippedEntries, SkippedEntry{
				Path:   entry.Name,
				Reason: "links are not extracted: a link can redirect a later entry outside the workspace",
			})
			continue

		case mode.IsDir():
			rel, err := SafeJoin(destAbs, entry.Name)
			if err != nil {
				return result, err
			}
			if err := os.MkdirAll(rel, 0o700); err != nil {
				return result, fmt.Errorf("create directory: %w", err)
			}
			continue

		case !mode.IsRegular():
			result.SkippedEntries = append(result.SkippedEntries, SkippedEntry{
				Path:   entry.Name,
				Reason: "only regular files and directories are extracted",
			})
			continue
		}

		rel, err := SafeJoin(destAbs, entry.Name)
		if err != nil {
			// Zip slip. A hard failure, matching ExtractTar: an archive containing
			// ../../etc/passwd is hostile, and continuing to extract the rest of a
			// hostile archive is not a service anyone wants.
			return result, err
		}
		if err := os.MkdirAll(filepath.Dir(rel), 0o700); err != nil {
			return result, fmt.Errorf("create parent: %w", err)
		}

		rc, err := entry.Open()
		if err != nil {
			return result, errs.Wrap(err, errs.FetchPathTraversal, "corrupt archive entry")
		}
		written, err := copyGuardedZip(rc, rel, size, &result, lim)
		_ = rc.Close()
		if err != nil {
			return result, err
		}
		result.UncompressedB += written
		result.Files++
	}

	result.CompressedB = size
	return result, nil
}

// copyGuardedZip writes one entry, checking the size and inflation limits AS
// IT GOES — the same decompression-bomb defence as copyGuarded.
//
// ⚠ THE RATIO USES THE WHOLE ARCHIVE'S SIZE, NOT A PER-ENTRY COMPRESSED SIZE.
//
// A zip's central directory declares a per-entry compressed size, but it is
// attacker-controlled metadata a crafted header can lie about. The archive's
// own size on disk — known from the upload before extraction ever starts —
// cannot be lied about the same way, so the ratio is evaluated against that
// fixed total instead. As more entries are written the ratio only grows, so a
// bomb spread across many small entries is caught exactly as a bomb in one
// large entry would be.
func copyGuardedZip(src io.Reader, path string, archiveCompressedB int64,
	result *ExtractResult, lim ExtractLimits,
) (int64, error) {
	// #nosec G304 -- path comes from SafeJoin, which has already refused
	// absolute paths, drive letters, any ".." segment, and anything resolving
	// outside the destination.
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC|os.O_EXCL, 0o600)
	if errors.Is(err, os.ErrExist) {
		// A second entry for the same path. Refusing is safer than overwriting.
		// #nosec G304 -- same SafeJoin-validated path as above.
		f, err = os.OpenFile(path, os.O_WRONLY|os.O_TRUNC, 0o600)
	}
	if err != nil {
		return 0, fmt.Errorf("create file: %w", err)
	}

	closed := false
	closeOnce := func() {
		if !closed {
			_ = f.Close()
			closed = true
		}
	}
	defer closeOnce()

	abort := func() {
		closeOnce()
		_ = os.Remove(path)
	}

	const chunk = 64 << 10
	buf := make([]byte, chunk)
	var written int64

	for {
		n, readErr := src.Read(buf)
		if n > 0 {
			if _, werr := f.Write(buf[:n]); werr != nil {
				return written, fmt.Errorf("write file: %w", werr)
			}
			written += int64(n)
			result.UncompressedB += int64(n)

			if result.UncompressedB > lim.MaxBytes {
				abort()
				return written, errs.Newf(errs.FetchArchiveTooLarge,
					"archive exceeds the %d MiB uncompressed limit; aborted mid-extraction",
					lim.MaxBytes>>20)
			}

			if archiveCompressedB > 0 && result.UncompressedB > ratioCheckFloor {
				ratio := result.UncompressedB / archiveCompressedB
				if ratio > lim.MaxInflationRatio {
					abort()
					return written, errs.Newf(errs.FetchInflationRatio,
						"decompression ratio %d:1 exceeds the %d:1 limit; aborted mid-extraction "+
							"after %d bytes", ratio, lim.MaxInflationRatio, result.UncompressedB)
				}
			}
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			return written, fmt.Errorf("read archive entry: %w", readErr)
		}
	}

	// Undo the double count: the caller adds `written` as well, mirroring
	// copyGuarded exactly.
	result.UncompressedB -= written
	return written, nil
}
