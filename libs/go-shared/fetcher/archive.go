package fetcher

import (
	"archive/tar"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/klauspost/compress/zstd"

	"github.com/axebom/axebom/libs/go-shared/platform/blob"
	"github.com/axebom/axebom/libs/go-shared/platform/errs"
)

// Archiving materialized source into a content-addressed tar.zst.
//
// The archive is what every engine reads (ADR-0008): the fetcher produces it
// exactly once, and six engines then see identical bytes. That is what removes
// the class of bug where a push between clones puts components from one commit
// and vulnerabilities from another into a single report.

// Archive describes a produced source archive.
type Archive struct {
	// Key is the object-storage key.
	Key string
	// SHA256 is the digest of the COMPRESSED archive, computed while streaming.
	SHA256 string
	// SizeBytes is the compressed size.
	SizeBytes int64
	// FileCount is how many files went in.
	FileCount int
	// UncompressedBytes is the total input size.
	UncompressedBytes int64
	// Deduplicated reports that an identical archive already existed and was
	// reused rather than re-uploaded.
	Deduplicated bool
}

// ArchiveLimits bounds what may be archived.
type ArchiveLimits struct {
	MaxFiles     int
	MaxBytes     int64
	MaxPathBytes int
}

// DefaultArchiveLimits mirrors .env.example.
func DefaultArchiveLimits() ArchiveLimits {
	return ArchiveLimits{
		MaxFiles:     500_000,
		MaxBytes:     2048 << 20,
		MaxPathBytes: 1024,
	}
}

// skipDirs are never archived.
//
// `.git` is the important one: it is large, it contains the full history we
// pinned a single commit from, and — most of all — it carries `hooks/`, which
// is a directory of executable scripts an attacker controls. Nothing downstream
// should be handed those, even in a sandbox.
var skipDirs = map[string]bool{
	".git": true, ".hg": true, ".svn": true, ".bzr": true,
}

// CreateArchive tars, compresses and uploads a directory.
//
// The digest is computed over the COMPRESSED bytes as they stream, so the
// archive is content-addressed by exactly what was stored — not by a digest of
// something re-derived later.
func CreateArchive(ctx context.Context, store *blob.Store, srcDir, keyPrefix string,
	lim ArchiveLimits,
) (Archive, error) {
	if lim.MaxFiles <= 0 {
		lim = DefaultArchiveLimits()
	}

	// Two passes. The first builds the archive to a temporary file while
	// hashing; the second uploads it under a key derived from that hash.
	//
	// Streaming straight to object storage would be one pass, but the KEY
	// depends on the digest of the whole archive, so it is not known until the
	// last byte. Writing a temp file is the honest way to have both content
	// addressing and a bounded memory footprint.
	tmp, err := os.CreateTemp("", "axebom-archive-*.tar.zst")
	if err != nil {
		return Archive{}, fmt.Errorf("create temporary archive: %w", err)
	}
	tmpPath := tmp.Name()
	defer func() {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
	}()

	hasher := sha256.New()
	// Write to the temp file AND the hasher in one pass.
	multi := io.MultiWriter(tmp, hasher)

	zw, err := zstd.NewWriter(multi, zstd.WithEncoderLevel(zstd.SpeedDefault))
	if err != nil {
		return Archive{}, fmt.Errorf("zstd writer: %w", err)
	}
	tw := tar.NewWriter(zw)

	result := Archive{}
	if err := walkInto(ctx, tw, srcDir, lim, &result); err != nil {
		return Archive{}, err
	}

	if err := tw.Close(); err != nil {
		return Archive{}, fmt.Errorf("close tar: %w", err)
	}
	if err := zw.Close(); err != nil {
		return Archive{}, fmt.Errorf("close zstd: %w", err)
	}

	size, err := tmp.Seek(0, io.SeekCurrent)
	if err != nil {
		return Archive{}, err
	}
	if _, err := tmp.Seek(0, io.SeekStart); err != nil {
		return Archive{}, err
	}

	result.SHA256 = hex.EncodeToString(hasher.Sum(nil))
	result.SizeBytes = size
	result.Key = fmt.Sprintf("%s/%s/source.tar.zst",
		objectKeyPrefix(keyPrefix), result.SHA256)

	// CONTENT ADDRESSING MEANS DEDUPLICATION IS FREE: an identical commit
	// archived again produces the same key, so the upload can be skipped.
	if rc, err := store.Get(ctx, result.Key); err == nil {
		_ = rc.Close()
		result.Deduplicated = true
		return result, nil
	}

	obj, err := store.Put(ctx, result.Key, tmp, blob.PutOptions{
		ContentType: "application/zstd",
		MaxBytes:    lim.MaxBytes,
	})
	if err != nil {
		return Archive{}, errs.Wrap(err, errs.InternalDependency, "could not store the source archive")
	}

	// The store recomputes the digest from what it actually wrote. If the two
	// disagree, something corrupted the stream and the archive must not be
	// trusted — a report built on it would describe code that was never here.
	if obj.SHA256 != result.SHA256 {
		return Archive{}, fmt.Errorf(
			"archive digest mismatch: computed %s, stored %s", result.SHA256, obj.SHA256)
	}
	return result, nil
}

// walkInto adds a directory tree to the tar, enforcing the limits.
func walkInto(ctx context.Context, tw *tar.Writer, srcDir string,
	lim ArchiveLimits, result *Archive,
) error {
	root, err := filepath.Abs(srcDir)
	if err != nil {
		return err
	}

	// Collected and SORTED so the archive is byte-identical for identical
	// input. Without it, filesystem iteration order changes the archive, the
	// digest changes, and content addressing silently stops deduplicating.
	var paths []string
	walkErr := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if skipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		// Only regular files. A symlink in the working tree is not followed:
		// following one would archive whatever it points at, including files
		// outside the workspace.
		if !d.Type().IsRegular() {
			return nil
		}
		paths = append(paths, path)
		return nil
	})
	if walkErr != nil {
		return fmt.Errorf("walk source: %w", walkErr)
	}
	sort.Strings(paths)

	for _, path := range paths {
		if err := ctx.Err(); err != nil {
			return err
		}
		if result.FileCount >= lim.MaxFiles {
			return errs.Newf(errs.FetchTooManyFiles,
				"source contains more than %d files", lim.MaxFiles)
		}

		info, err := os.Stat(path)
		if err != nil {
			return fmt.Errorf("stat %s: %w", path, err)
		}
		if result.UncompressedBytes+info.Size() > lim.MaxBytes {
			return errs.Newf(errs.FetchArchiveTooLarge,
				"source exceeds the %d MiB limit", lim.MaxBytes>>20)
		}

		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		// Forward slashes in the archive regardless of host OS, so an archive
		// built on Windows extracts correctly on Linux.
		name := filepath.ToSlash(rel)

		// Sanitized BEFORE it reaches the archive or a database row.
		name, _ = SanitizePath(name, lim.MaxPathBytes)

		hdr := &tar.Header{
			Name:     name,
			Mode:     0o644,
			Size:     info.Size(),
			Typeflag: tar.TypeReg,
			// Timestamps ZEROED. A tar carrying mtimes produces a different
			// archive for identical content checked out twice, which breaks
			// content addressing for no benefit — git does not preserve them
			// either.
			ModTime: zeroTime,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return fmt.Errorf("write header %s: %w", name, err)
		}

		// #nosec G304 -- path came from WalkDir over our own workspace
		// directory, not from user input.
		f, err := os.Open(path)
		if err != nil {
			return fmt.Errorf("open %s: %w", path, err)
		}
		written, err := io.Copy(tw, f)
		_ = f.Close()
		if err != nil {
			return fmt.Errorf("copy %s: %w", name, err)
		}

		result.FileCount++
		result.UncompressedBytes += written
	}
	return nil
}

// OpenArchive streams a stored archive, decompressing it.
//
// Returns the decompressed reader AND the CountingReader over the compressed
// bytes, because ExtractTar needs both to evaluate the inflation ratio.
func OpenArchive(ctx context.Context, store *blob.Store, key string) (io.ReadCloser, *CountingReader, error) {
	rc, err := store.Get(ctx, key)
	if err != nil {
		return nil, nil, err
	}

	counted := NewCountingReader(rc)
	zr, err := zstd.NewReader(counted)
	if err != nil {
		_ = rc.Close()
		return nil, nil, fmt.Errorf("zstd reader: %w", err)
	}

	return &zstdReadCloser{r: zr, underlying: rc}, counted, nil
}

// zstdReadCloser closes both the decompressor and the object stream.
type zstdReadCloser struct {
	r          *zstd.Decoder
	underlying io.ReadCloser
}

func (z *zstdReadCloser) Read(p []byte) (int, error) { return z.r.Read(p) }

func (z *zstdReadCloser) Close() error {
	z.r.Close() // returns nothing
	return z.underlying.Close()
}

// zeroTime is the timestamp written into every archive header.
//
// Not time.Time{}: some tar readers reject a zero year. The Unix epoch is
// unambiguous and produces a stable archive for identical content.
var zeroTime = time.Unix(0, 0).UTC()

// objectKeyPrefix turns a job's output prefix into a bucket-relative key.
//
// ⚠ A URI IS NOT AN OBJECT KEY, AND THE DEFAULT PREFIX IS A URI.
//
// The orchestrator builds Output.Prefix as
// "<ArtifactPrefix>/scans/<id>/raw/<engine>/<job>/", and ArtifactPrefix
// defaults to "s3://axebom" — documented as "the object-storage root".
// Passed through unchanged, the object name literally began "s3://axebom/",
// and MinIO rejected it:
//
//	Object name contains unsupported characters
//
// which names neither the key nor the colon that caused it. The upload sits on
// a RETRYABLE path, so the fetch job naked and redelivered indefinitely and the
// scan never progressed past `queued`.
//
// The store is already bucket-scoped, so the bucket must not appear in the key.
// Normalising here rather than at the one caller because every caller would
// otherwise have to know it: a key carrying a scheme is never correct.
func objectKeyPrefix(prefix string) string {
	if i := strings.Index(prefix, "://"); i >= 0 {
		rest := prefix[i+len("://"):]
		// Drop the bucket/host segment too; what follows is the key.
		if j := strings.Index(rest, "/"); j >= 0 {
			prefix = rest[j+1:]
		} else {
			prefix = ""
		}
	}
	// A leading slash is equally invalid, and an empty ArtifactPrefix produces
	// one.
	return strings.Trim(prefix, "/")
}
