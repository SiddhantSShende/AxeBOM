package fetcher

import (
	"archive/tar"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"unicode/utf8"

	"github.com/encorebom/encorebom/libs/go-shared/platform/errs"
)

// Archive extraction over untrusted input.
//
// Every guard here corresponds to a real, named attack. The ordering matters:
// the inflation check runs DURING the stream, because a check afterwards means
// the bomb has already landed on the disk it was meant to fill.

// ExtractLimits bounds an extraction. Defaults come from .env.example.
type ExtractLimits struct {
	// MaxBytes is the total uncompressed size permitted.
	MaxBytes int64
	// MaxFiles bounds inode exhaustion: a million one-byte files fills an
	// inode table long before it fills a disk, and df reports plenty free.
	MaxFiles int
	// MaxInflationRatio is uncompressed:compressed. A 10 GB archive from 1 MB
	// of input is not a plausible source tree.
	MaxInflationRatio int64
	// MaxPathBytes truncates a stored path. Postgres text has no limit, but a
	// filesystem does, and an 8 KB path is an attack rather than a filename.
	MaxPathBytes int
}

// DefaultExtractLimits mirrors .env.example.
func DefaultExtractLimits() ExtractLimits {
	return ExtractLimits{
		MaxBytes:          2048 << 20, // FETCH_MAX_ARCHIVE_MB
		MaxFiles:          500_000,    // FETCH_MAX_FILES
		MaxInflationRatio: 100,        // FETCH_MAX_INFLATION_RATIO
		MaxPathBytes:      1024,
	}
}

// ExtractResult reports what an extraction produced.
type ExtractResult struct {
	Files          int
	UncompressedB  int64
	CompressedB    int64
	SkippedEntries []SkippedEntry
}

// SkippedEntry is one refused archive member.
//
// Refused entries are REPORTED, not silently dropped. An archive that quietly
// loses files produces a BOM missing components, which is exactly the false
// negative this product exists to avoid.
type SkippedEntry struct {
	Path   string
	Reason string
}

// CountingReader counts bytes read from the COMPRESSED stream, so the inflation
// ratio can be evaluated continuously rather than at the end.
//
// Exported because the caller has to wrap the compressed source BEFORE handing
// it to the decompressor — the ratio needs both numbers, and only the caller
// can see both sides of the decompression.
// ⚠ THE COUNTER IS ATOMIC BECAUSE IT IS WRITTEN AND READ ON DIFFERENT
// GOROUTINES, AND THAT IS NOT OBVIOUS FROM THE CALL SITE.
//
// The caller wraps the compressed source and then hands it to a zstd Decoder.
// klauspost/compress runs its stream decoder on ITS OWN GOROUTINE, so Read is
// driven from there while ExtractTar evaluates the ratio from the caller's
// goroutine. Nothing in this file suggests concurrency; the second goroutine
// belongs to a dependency.
//
// Caught by `go test -race`:
//
//	Read at ... by goroutine 75:  fetcher.ExtractTar()
//	Previous write by goroutine 84: fetcher.(*CountingReader).Read()
//	  ... zstd.(*Decoder).startStreamDecoder()
//
// This is not merely a detector complaint. The counter is the DECOMPRESSION
// BOMB GUARD: an unsynchronised read can observe a stale value, so the ratio is
// evaluated against fewer compressed bytes than were actually consumed — which
// biases the computed ratio UPWARD and could reject a legitimate archive, or,
// with different interleaving, delay the check on a hostile one.
type CountingReader struct {
	r   io.Reader
	n   atomic.Int64
	tee io.Writer
}

// NewCountingReader wraps r.
func NewCountingReader(r io.Reader) *CountingReader {
	return &CountingReader{r: r}
}

func (c *CountingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n.Add(int64(n))
	if n > 0 && c.tee != nil {
		// Errors are ignored deliberately: the tee is an observer (a hasher),
		// and failing the extraction because an observer complained would let a
		// diagnostic break the thing it observes. A hash.Hash never errors.
		_, _ = c.tee.Write(p[:n])
	}
	return n, err
}

// Tee sends every byte read to w as well.
//
// Used to hash the COMPRESSED stream while extracting it, which is the only way
// to verify a content-addressed archive without reading it twice — the key is
// derived from the compressed bytes, and they are consumed by the decompressor
// as they arrive.
//
// ⚠ MUST BE SET BEFORE THE FIRST READ. There is no synchronisation here: the
// reader is driven by the decompressor's goroutine, so setting the tee mid-
// stream would be a data race AND would silently hash a suffix.
func (c *CountingReader) Tee(w io.Writer) { c.tee = w }

// Count returns the compressed bytes read so far.
func (c *CountingReader) Count() int64 { return c.n.Load() }

// ExtractTar extracts a tar stream into dest, enforcing every guard.
//
// `compressed` is the reader BEFORE decompression, so the inflation ratio can
// be computed. Pass the same reader when the stream is not compressed.
func ExtractTar(r io.Reader, compressed *CountingReader, dest string, lim ExtractLimits) (ExtractResult, error) {
	if lim.MaxBytes <= 0 {
		lim = DefaultExtractLimits()
	}

	destAbs, err := filepath.Abs(dest)
	if err != nil {
		return ExtractResult{}, fmt.Errorf("resolve destination: %w", err)
	}
	// EvalSymlinks on the DESTINATION itself: if dest is reached through a
	// symlink, every containment check below would compare against the wrong
	// prefix and conclude an escape was fine.
	if resolved, err := filepath.EvalSymlinks(destAbs); err == nil {
		destAbs = resolved
	}

	var result ExtractResult
	tr := tar.NewReader(r)

	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return result, errs.Wrap(err, errs.FetchPathTraversal, "corrupt archive")
		}

		if result.Files >= lim.MaxFiles {
			return result, errs.Newf(errs.FetchTooManyFiles,
				"archive exceeds the %d file limit", lim.MaxFiles)
		}

		// ⚠ TYPE FILTER FIRST, before any path handling.
		//
		// A symlink entry is refused outright rather than resolved and checked:
		// a link created early in the stream can be the parent directory of a
		// later entry, so "check where it points" is racy against the archive's
		// own ordering. Hard links alias a file we may not control. Device and
		// FIFO entries have no business in source and are a way to hand a
		// scanner something that blocks forever or reads a device.
		switch hdr.Typeflag {
		case tar.TypeReg, tar.TypeDir:
			// permitted
		case tar.TypeSymlink, tar.TypeLink:
			result.SkippedEntries = append(result.SkippedEntries, SkippedEntry{
				Path:   hdr.Name,
				Reason: "links are not extracted: a link can redirect a later entry outside the workspace",
			})
			continue
		case tar.TypeChar, tar.TypeBlock, tar.TypeFifo:
			result.SkippedEntries = append(result.SkippedEntries, SkippedEntry{
				Path:   hdr.Name,
				Reason: "device and FIFO entries are never extracted",
			})
			continue
		default:
			result.SkippedEntries = append(result.SkippedEntries, SkippedEntry{
				Path:   hdr.Name,
				Reason: fmt.Sprintf("unsupported tar entry type %q", hdr.Typeflag),
			})
			continue
		}

		rel, err := SafeJoin(destAbs, hdr.Name)
		if err != nil {
			// Zip slip. A HARD failure, not a skip: an archive containing
			// ../../etc/passwd is hostile, and continuing to extract the rest
			// of a hostile archive is not a service anyone wants.
			return result, err
		}

		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(rel, 0o700); err != nil {
				return result, fmt.Errorf("create directory: %w", err)
			}
			continue

		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(rel), 0o700); err != nil {
				return result, fmt.Errorf("create parent: %w", err)
			}

			written, err := copyGuarded(tr, rel, compressed, &result, lim)
			if err != nil {
				return result, err
			}
			result.UncompressedB += written
			result.Files++
		}
	}

	if compressed != nil {
		result.CompressedB = compressed.Count()
	}
	return result, nil
}

// ratioCheckFloor is how much must be written before the inflation ratio is
// meaningful. Below it, a few hundred bytes of archive header can legitimately
// expand enormously and produce a false positive.
const ratioCheckFloor = 1 << 20 // 1 MiB

// copyGuarded writes one file, checking the size and inflation limits AS IT
// GOES.
//
// ⚠ THE DECOMPRESSION-BOMB DEFENCE.
//
// A 10 GB file from a 1 MB archive must be refused after a few megabytes, not
// after 10 GB. So the ratio is evaluated every chunk, and the write is abandoned
// mid-file the moment it is exceeded. Checking `if totalSize > limit` after the
// loop is the version of this code that fills the disk first and then reports
// that the disk was filled.
func copyGuarded(src io.Reader, path string, compressed *CountingReader,
	result *ExtractResult, lim ExtractLimits,
) (int64, error) {
	// #nosec G304 -- path comes from SafeJoin, which has already refused
	// absolute paths, drive letters, any ".." segment, and anything resolving
	// outside the destination. That check is the point of this file.
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC|os.O_EXCL, 0o600)
	if errors.Is(err, os.ErrExist) {
		// A second entry for the same path. Refusing is safer than overwriting:
		// an archive that writes a file twice is trying to win a race with
		// whatever read the first version.
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

	// abort closes the file BEFORE removing it.
	//
	// On Windows an open file cannot be unlinked, so a deferred Close would
	// leave the partial bomb exactly where it was meant to land — the disk it
	// was filling. Found by the bomb test on this machine.
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

			// The ratio is evaluated once enough has been written for it to
			// mean something.
			//
			// The threshold is on the UNCOMPRESSED side, deliberately. Gating on
			// compressed bytes instead lets a bomb run far longer than
			// necessary: gzip needs only ~200 KB of input to produce 200 MB, so
			// a "wait for 64 KB compressed" rule permits ~65 MB of output before
			// the first check. Measured at 32% of a 200 MB bomb before this
			// changed. Gating on 1 MiB written bounds the damage to roughly
			// that, and no legitimate source tree trips a 100:1 ratio at 1 MiB.
			// Read the counter ONCE, and only after the nil check. It is
			// written concurrently by the decompressor's goroutine, so loading
			// it twice — once for the guard, once for the division — could see
			// two different values and divide by a zero the guard had just
			// cleared. `compressed` is nil for an uncompressed stream, where
			// there is no ratio to evaluate.
			var compressedB int64
			if compressed != nil {
				compressedB = compressed.Count()
			}
			if compressedB > 0 && result.UncompressedB > ratioCheckFloor {
				ratio := result.UncompressedB / compressedB
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

	// Undo the double count: the caller adds `written` as well.
	result.UncompressedB -= written
	return written, nil
}

// ---------------------------------------------------------------------------
// Path handling
// ---------------------------------------------------------------------------

// SafeJoin resolves an archive member path inside root, or refuses.
//
// ⚠ THE ZIP-SLIP DEFENCE.
//
// filepath.Join(root, name) is NOT safe on its own: Join cleans the result, so
// `../../etc/passwd` becomes a path outside root and Join returns it happily.
// The containment check after the join is what matters, and it compares against
// root + separator so that `/workspace-evil` is not accepted as being inside
// `/workspace`.
func SafeJoin(root, name string) (string, error) {
	if name == "" {
		return "", errs.New(errs.FetchPathTraversal, "archive entry has an empty name")
	}
	if strings.ContainsRune(name, 0) {
		return "", errs.New(errs.FetchPathTraversal, "archive entry name contains a NUL byte")
	}

	// Reject absolute paths in BOTH conventions regardless of host OS: an
	// archive built on Linux is extracted on Windows and vice versa, and
	// filepath.IsAbs only understands the local one.
	if strings.HasPrefix(name, "/") || strings.HasPrefix(name, `\`) {
		return "", errs.Newf(errs.FetchPathTraversal, "archive entry %q is an absolute path", name)
	}
	if len(name) >= 2 && name[1] == ':' {
		return "", errs.Newf(errs.FetchPathTraversal, "archive entry %q is a drive-absolute path", name)
	}

	// Normalize separators before inspecting segments; a tar built on Windows
	// can carry backslashes that a Unix host does not treat as separators.
	unified := strings.ReplaceAll(name, `\`, "/")
	for _, seg := range strings.Split(unified, "/") {
		if seg == ".." {
			return "", errs.Newf(errs.FetchPathTraversal,
				"archive entry %q contains a parent-directory segment", name)
		}
	}

	joined := filepath.Join(root, filepath.FromSlash(unified))

	// The check that actually holds: after cleaning, is it still under root?
	// The separator suffix matters — without it, /workspace-evil passes a
	// prefix test against /workspace.
	rootWithSep := root
	if !strings.HasSuffix(rootWithSep, string(os.PathSeparator)) {
		rootWithSep += string(os.PathSeparator)
	}
	if joined != root && !strings.HasPrefix(joined, rootWithSep) {
		return "", errs.Newf(errs.FetchPathTraversal,
			"archive entry %q resolves outside the workspace", name)
	}
	return joined, nil
}

// SanitizePath makes an untrusted path safe to STORE.
//
// Called before any database insert. Real archives contain NUL bytes, newlines,
// RTL overrides and 8 KB paths, and each breaks something different:
//
//	NUL         silently TRUNCATES a Postgres text value, so what is stored is
//	            not what was scanned — the most dangerous of the four, because
//	            it is invisible.
//	newline     forges a log line, and splits a CSV cell.
//	RTL/BiDi    renders `exe.txt` as `txt.exe` in a report a human approves.
//	8 KB path   overflows filesystem limits and bloats every index.
//
// Returns the cleaned path and whether anything was changed, so the caller can
// record that the stored name differs from the archived one.
func SanitizePath(p string, maxBytes int) (string, bool) {
	if maxBytes <= 0 {
		maxBytes = 1024
	}
	original := p

	var b strings.Builder
	b.Grow(len(p))
	for _, r := range p {
		switch {
		case r == 0:
			// Dropped entirely rather than replaced: a NUL is never meaningful
			// in a filename and its whole danger is being invisible.
			continue
		case r == '\n' || r == '\r' || r == '\t':
			b.WriteRune('_')
		case r == utf8.RuneError:
			// Invalid UTF-8. Postgres rejects it outright on a text column, so
			// a row would fail to insert rather than store something wrong.
			b.WriteRune('_')
		case isBiDiControl(r):
			// RTL override and friends. Kept visible as an underscore so the
			// name still reads, rather than silently reordering.
			b.WriteRune('_')
		case r < 0x20 || r == 0x7f:
			b.WriteRune('_')
		default:
			// 4-byte emoji and other astral-plane runes pass through: they are
			// valid UTF-8 and valid filenames, and mangling them would corrupt
			// legitimate international paths.
			b.WriteRune(r)
		}
	}

	out := b.String()

	// Truncate on a RUNE boundary. Cutting mid-rune produces invalid UTF-8,
	// which Postgres refuses — turning a long filename into a failed insert.
	if len(out) > maxBytes {
		cut := out[:maxBytes]
		for len(cut) > 0 && !utf8.ValidString(cut) {
			cut = cut[:len(cut)-1]
		}
		out = cut
	}

	return out, out != original
}

// isBiDiControl reports whether r is a bidirectional control character.
//
// These reorder rendered text without changing the bytes, so a filename can
// display as "report exe.txt" while actually ending in .exe — in a UI where
// somebody decides whether to trust it.
//
// Written as \u ESCAPES, not literals. Literal bidi characters in source are
// the Trojan Source vulnerability in miniature: they are invisible in most
// editors, so the code a reviewer reads is not the code that compiles. gosec
// G116 flagged this file when they were literals, which is the check working.
func isBiDiControl(r rune) bool {
	switch r {
	case '\u061C', // Arabic letter mark
		'\u200E', '\u200F', // LRM, RLM
		'\u202A', '\u202B', '\u202C', '\u202D', '\u202E', // embedding, override
		'\u2066', '\u2067', '\u2068', '\u2069': // isolates
		return true
	}
	return false
}
