package fetcher_test

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"testing"

	"github.com/klauspost/compress/zstd"

	"github.com/axebom/axebom/libs/go-shared/fetcher"
	"github.com/axebom/axebom/libs/go-shared/platform/errs"
)

// The zip escape suite, mirroring extract_test.go's tar suite entry for entry:
// the same real attacks, the same names, aimed at ExtractZip instead of
// ExtractTar — because an uploaded source_archive reaches this code path just
// as untrusted as a cloned repository does.

// zipEntry is one archive member to build.
type zipEntry struct {
	name    string
	body    string
	isDir   bool
	symlink string // non-empty means this entry is a symlink pointing here
	// method controls compression. Zero value (zip.Deflate) is fine for most
	// cases; zip.Store is used where a test needs compressed size ≈ content
	// size, so only the byte-count guard trips rather than the ratio guard.
	method uint16
}

func buildZip(t *testing.T, entries []zipEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)

	for _, e := range entries {
		if e.isDir {
			if _, err := zw.Create(e.name + "/"); err != nil {
				t.Fatalf("create dir %q: %v", e.name, err)
			}
			continue
		}

		method := e.method
		if method == 0 {
			method = zip.Deflate
		}
		hdr := &zip.FileHeader{Name: e.name, Method: method}
		if e.symlink != "" {
			hdr.SetMode(os.ModeSymlink | 0o777)
		} else {
			hdr.SetMode(0o644)
		}

		w, err := zw.CreateHeader(hdr)
		if err != nil {
			t.Fatalf("create %q: %v", e.name, err)
		}
		body := e.body
		if e.symlink != "" {
			body = e.symlink
		}
		if _, err := w.Write([]byte(body)); err != nil {
			t.Fatalf("write %q: %v", e.name, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("close zip: %v", err)
	}
	return buf.Bytes()
}

func extractZipInto(t *testing.T, archive []byte, lim fetcher.ExtractLimits) (string, fetcher.ExtractResult, error) {
	t.Helper()
	dest := t.TempDir()
	res, err := fetcher.ExtractZip(bytes.NewReader(archive), int64(len(archive)), dest, lim)
	return dest, res, err
}

// ---------------------------------------------------------------------------
// Zip slip
// ---------------------------------------------------------------------------

func TestZipFormatPathTraversalIsRejected(t *testing.T) {
	attacks := []struct{ name, why string }{
		{"../../etc/passwd", "classic traversal"},
		{"../outside.txt", "one level is enough"},
		{"a/b/../../../escape.txt", "traversal hidden mid-path"},
		{"/etc/passwd", "absolute path"},
		{`\windows\system32\drivers\etc\hosts`, "windows absolute path"},
		{`..\..\windows\evil.txt`, "windows traversal"},
		{"C:\\evil.txt", "drive-absolute path"},
	}

	for _, a := range attacks {
		t.Run(a.name, func(t *testing.T) {
			archive := buildZip(t, []zipEntry{{name: a.name, body: "pwned"}})
			dest, _, err := extractZipInto(t, archive, fetcher.DefaultExtractLimits())

			if err == nil {
				t.Fatalf("ACCEPTED %q — %s", a.name, a.why)
			}
			if !errs.Is(err, errs.FetchPathTraversal) {
				t.Errorf("wrong code: %v", err)
			}

			parent := filepath.Dir(dest)
			for _, leaked := range []string{"outside.txt", "escape.txt", "evil.txt", "hosts", "passwd"} {
				if _, statErr := os.Stat(filepath.Join(parent, leaked)); statErr == nil {
					t.Errorf("%s was written outside the workspace", leaked)
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Links and special entries
// ---------------------------------------------------------------------------

// A zip stores a symlink's target as the entry's own "content" when the
// archiver recorded the Unix mode bits — a shape unique to zip among the
// formats this package extracts, so it gets its own test rather than reusing
// the tar symlink fixture.
func TestZipSymlinksAreNotExtracted(t *testing.T) {
	archive := buildZip(t, []zipEntry{
		{name: "safe.txt", body: "ok"},
		{name: "shadow-link", symlink: "/etc/shadow"},
		{name: "escape-link", symlink: "../../../"},
	})

	dest, res, err := extractZipInto(t, archive, fetcher.DefaultExtractLimits())
	if err != nil {
		t.Fatalf("extraction failed: %v", err)
	}

	for _, name := range []string{"shadow-link", "escape-link"} {
		if _, err := os.Lstat(filepath.Join(dest, name)); err == nil {
			t.Errorf("%s was created", name)
		}
	}
	if len(res.SkippedEntries) != 2 {
		t.Errorf("skipped %d entries, want 2: %+v", len(res.SkippedEntries), res.SkippedEntries)
	}
	for _, s := range res.SkippedEntries {
		if s.Reason == "" {
			t.Errorf("entry %q was skipped with no reason", s.Path)
		}
	}
	if _, err := os.Stat(filepath.Join(dest, "safe.txt")); err != nil {
		t.Errorf("the safe file was not extracted: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Resource limits
// ---------------------------------------------------------------------------

// ⚠ THE DECOMPRESSION BOMB, ZIP SHAPE.
//
// The requirement, exactly as for tar, is "abort MID-EXTRACTION" — not merely
// "reject eventually". A single highly-compressible entry, deflated, produces
// an enormous ratio between the whole archive's on-disk size and the entry's
// uncompressed content, and copyGuardedZip must abort long before the
// declared size lands on disk.
func TestZipDecompressionBombAbortsMidExtraction(t *testing.T) {
	const declared = 200 << 20 // 200 MiB of zeros

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.CreateHeader(&zip.FileHeader{Name: "bomb.bin", Method: zip.Deflate})
	if err != nil {
		t.Fatalf("create entry: %v", err)
	}
	chunk := make([]byte, 1<<20)
	for written := 0; written < declared; written += len(chunk) {
		if _, err := w.Write(chunk); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("close zip: %v", err)
	}

	archive := buf.Bytes()
	t.Logf("archive: %d bytes on disk -> %d uncompressed (ratio %d:1)",
		len(archive), declared, declared/len(archive))

	lim := fetcher.DefaultExtractLimits()
	lim.MaxInflationRatio = 100

	dest, res, err := extractZipInto(t, archive, lim)
	if err == nil {
		t.Fatal("the bomb extracted successfully")
	}
	if !errs.Is(err, errs.FetchInflationRatio) && !errs.Is(err, errs.FetchArchiveTooLarge) {
		t.Errorf("wrong code: %v", err)
	}

	// ⚠ THE ASSERTION THAT MATTERS: it stopped EARLY.
	if res.UncompressedB >= declared {
		t.Errorf("wrote %d bytes of a %d-byte bomb — the check is not mid-stream",
			res.UncompressedB, declared)
	}
	t.Logf("aborted after %d bytes of %d (%.2f%%)",
		res.UncompressedB, declared, float64(res.UncompressedB)/float64(declared)*100)

	if _, err := os.Stat(filepath.Join(dest, "bomb.bin")); err == nil {
		t.Error("the partial bomb file was left on disk")
	}
}

// TestZipTotalSizeLimitAborts isolates the raw byte-count ceiling from the
// ratio guard by storing the entry UNCOMPRESSED (zip.Store): compressed size
// on disk is then approximately equal to content size, so only MaxBytes can
// trip, not the ratio.
func TestZipTotalSizeLimitAborts(t *testing.T) {
	const size = 4 << 20 // 4 MiB
	archive := buildZip(t, []zipEntry{
		{name: "big.bin", body: string(make([]byte, size)), method: zip.Store},
	})

	lim := fetcher.DefaultExtractLimits()
	lim.MaxBytes = 1 << 20 // 1 MiB, well under the 4 MiB entry

	dest, _, err := extractZipInto(t, archive, lim)
	if err == nil {
		t.Fatal("an oversized archive extracted successfully")
	}
	if !errs.Is(err, errs.FetchArchiveTooLarge) {
		t.Errorf("wrong code: %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(dest, "big.bin")); statErr == nil {
		t.Error("the partial oversized file was left on disk")
	}
}

func TestZipFileCountLimitHolds(t *testing.T) {
	entries := make([]zipEntry, 10)
	for i := range entries {
		entries[i] = zipEntry{name: filepath.Join("f", string(rune('a'+i))), body: "x"}
	}
	archive := buildZip(t, entries)

	lim := fetcher.DefaultExtractLimits()
	lim.MaxFiles = 5

	_, _, err := extractZipInto(t, archive, lim)
	if err == nil {
		t.Fatal("an archive over the file-count limit extracted successfully")
	}
	if !errs.Is(err, errs.FetchTooManyFiles) {
		t.Errorf("wrong code: %v", err)
	}
}

func TestZipNormalArchiveExtractsCorrectly(t *testing.T) {
	archive := buildZip(t, []zipEntry{
		{name: "README.md", body: "hello"},
		{name: "src", isDir: true},
		{name: "src/main.go", body: "package main"},
		{name: "src/nested/deep.go", body: "package nested"},
	})

	dest, res, err := extractZipInto(t, archive, fetcher.DefaultExtractLimits())
	if err != nil {
		t.Fatalf("extraction failed: %v", err)
	}
	if res.Files != 3 {
		t.Errorf("extracted %d files, want 3", res.Files)
	}
	for _, want := range []struct{ path, body string }{
		{"README.md", "hello"},
		{"src/main.go", "package main"},
		{"src/nested/deep.go", "package nested"},
	} {
		got, err := os.ReadFile(filepath.Join(dest, want.path))
		if err != nil {
			t.Errorf("%s: %v", want.path, err)
			continue
		}
		if string(got) != want.body {
			t.Errorf("%s: got %q, want %q", want.path, got, want.body)
		}
	}
}

func TestZipCorruptArchiveIsRejected(t *testing.T) {
	garbage := []byte("this is not a zip file")
	_, _, err := extractZipInto(t, garbage, fetcher.DefaultExtractLimits())
	if err == nil {
		t.Fatal("corrupt data was accepted as a valid archive")
	}
}

// ---------------------------------------------------------------------------
// ExtractArchive's format dispatch
// ---------------------------------------------------------------------------

// stageFile writes b to a temp file and returns it opened for reading, so
// ExtractArchive's seekable-file requirement is satisfied the same way the
// fetcher's own upload staging satisfies it.
func stageFile(t *testing.T, b []byte) (*os.File, int64) {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "staged-*")
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	t.Cleanup(func() { _ = f.Close() })
	if _, err := f.Write(b); err != nil {
		t.Fatalf("write temp file: %v", err)
	}
	if _, err := f.Seek(0, 0); err != nil {
		t.Fatalf("seek temp file: %v", err)
	}
	return f, int64(len(b))
}

func TestExtractArchiveDispatchesZip(t *testing.T) {
	archive := buildZip(t, []zipEntry{{name: "a.txt", body: "hello"}})
	f, size := stageFile(t, archive)

	dest := t.TempDir()
	res, err := fetcher.ExtractArchive("upload.zip", f, size, dest, fetcher.DefaultExtractLimits())
	if err != nil {
		t.Fatalf("dispatch to zip failed: %v", err)
	}
	if res.Files != 1 {
		t.Errorf("extracted %d files, want 1", res.Files)
	}
}

func TestExtractArchiveDispatchesTar(t *testing.T) {
	archive := buildTar(t, []tarEntry{{name: "a.txt", body: "hello"}})
	f, size := stageFile(t, archive)

	dest := t.TempDir()
	res, err := fetcher.ExtractArchive("upload.tar", f, size, dest, fetcher.DefaultExtractLimits())
	if err != nil {
		t.Fatalf("dispatch to tar failed: %v", err)
	}
	if res.Files != 1 {
		t.Errorf("extracted %d files, want 1", res.Files)
	}
}

func TestExtractArchiveDispatchesTarGz(t *testing.T) {
	raw := buildTar(t, []tarEntry{{name: "a.txt", body: "hello"}})
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	if _, err := zw.Write(raw); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}

	for _, name := range []string{"upload.tar.gz", "upload.tgz"} {
		t.Run(name, func(t *testing.T) {
			f, size := stageFile(t, gz.Bytes())
			dest := t.TempDir()
			res, err := fetcher.ExtractArchive(name, f, size, dest, fetcher.DefaultExtractLimits())
			if err != nil {
				t.Fatalf("dispatch to tar.gz failed: %v", err)
			}
			if res.Files != 1 {
				t.Errorf("extracted %d files, want 1", res.Files)
			}
		})
	}
}

func TestExtractArchiveDispatchesTarZst(t *testing.T) {
	raw := buildTar(t, []tarEntry{{name: "a.txt", body: "hello"}})
	var zst bytes.Buffer
	zw, err := zstd.NewWriter(&zst)
	if err != nil {
		t.Fatalf("zstd writer: %v", err)
	}
	if _, err := zw.Write(raw); err != nil {
		t.Fatalf("zstd write: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zstd close: %v", err)
	}

	f, size := stageFile(t, zst.Bytes())
	dest := t.TempDir()
	res, err := fetcher.ExtractArchive("upload.tar.zst", f, size, dest, fetcher.DefaultExtractLimits())
	if err != nil {
		t.Fatalf("dispatch to tar.zst failed: %v", err)
	}
	if res.Files != 1 {
		t.Errorf("extracted %d files, want 1", res.Files)
	}
}

// ⚠ AN UNRECOGNIZED EXTENSION IS REFUSED, NEVER GUESSED AT.
//
// Sniffing magic bytes to "be helpful" about a missing or wrong extension is
// exactly how a parser ends up extracting a format nobody validated the
// guards for.
func TestExtractArchiveRejectsUnknownFormat(t *testing.T) {
	f, size := stageFile(t, []byte("whatever"))
	dest := t.TempDir()
	_, err := fetcher.ExtractArchive("upload.rar", f, size, dest, fetcher.DefaultExtractLimits())
	if err == nil {
		t.Fatal("an unrecognized archive format was accepted")
	}
	if !errs.Is(err, errs.FetchUnsupportedArchiveFormat) {
		t.Errorf("wrong code: %v", err)
	}
}
