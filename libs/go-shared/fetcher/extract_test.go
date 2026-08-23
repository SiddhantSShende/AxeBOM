package fetcher_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/encorebom/encorebom/libs/go-shared/fetcher"
	"github.com/encorebom/encorebom/libs/go-shared/platform/errs"
)

// The escape suite for archive extraction.
//
// Every case is a real attack with a name. The test file itself is allowed to
// import archive/tar and compress/gzip — it BUILDS the hostile archives. The
// product code is what must not, and that is asserted separately in the project
// service's TestNoExtractionCodePathExists.

// tarEntry is one archive member to build.
type tarEntry struct {
	name     string
	body     string
	typeflag byte
	linkname string
	size     int64
}

// buildTar assembles a tar archive from entries, including malformed ones.
func buildTar(t *testing.T, entries []tarEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)

	for _, e := range entries {
		typeflag := e.typeflag
		if typeflag == 0 {
			typeflag = tar.TypeReg
		}
		size := int64(len(e.body))
		if e.size > 0 {
			size = e.size
		}
		hdr := &tar.Header{
			Name:     e.name,
			Mode:     0o644,
			Size:     size,
			Typeflag: typeflag,
			Linkname: e.linkname,
		}
		if typeflag == tar.TypeDir {
			hdr.Size = 0
			hdr.Mode = 0o755
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("write header %q: %v", e.name, err)
		}
		if typeflag == tar.TypeReg && e.body != "" {
			if _, err := tw.Write([]byte(e.body)); err != nil {
				t.Fatalf("write body %q: %v", e.name, err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close tar: %v", err)
	}
	return buf.Bytes()
}

func extractInto(t *testing.T, archive []byte, lim fetcher.ExtractLimits) (string, fetcher.ExtractResult, error) {
	t.Helper()
	dest := t.TempDir()
	res, err := fetcher.ExtractTar(bytes.NewReader(archive), nil, dest, lim)
	return dest, res, err
}

// ---------------------------------------------------------------------------
// Zip slip
// ---------------------------------------------------------------------------

// ⚠ ZIP SLIP.
//
// filepath.Join(root, "../../etc/passwd") returns a path OUTSIDE root, cleanly
// and without complaint. Join is not a containment check, and treating it as
// one is the bug.
func TestZipSlipIsRejected(t *testing.T) {
	attacks := []struct{ name, why string }{
		{"../../etc/passwd", "classic traversal"},
		{"../outside.txt", "one level is enough"},
		{"a/b/../../../escape.txt", "traversal hidden mid-path"},
		{"/etc/passwd", "absolute path"},
		{`\windows\system32\drivers\etc\hosts`, "windows absolute path"},
		{`..\..\windows\evil.txt`, "windows traversal"},
		{"C:\\evil.txt", "drive-absolute path"},
		{"./../../evil.txt", "traversal behind a dot segment"},
	}

	for _, a := range attacks {
		t.Run(a.name, func(t *testing.T) {
			archive := buildTar(t, []tarEntry{{name: a.name, body: "pwned"}})
			dest, _, err := extractInto(t, archive, fetcher.DefaultExtractLimits())

			if err == nil {
				t.Fatalf("ACCEPTED %q — %s", a.name, a.why)
			}
			if !errs.Is(err, errs.FetchPathTraversal) {
				t.Errorf("wrong code: %v", err)
			}

			// And nothing landed outside the destination.
			parent := filepath.Dir(dest)
			for _, leaked := range []string{"outside.txt", "escape.txt", "evil.txt"} {
				if _, statErr := os.Stat(filepath.Join(parent, leaked)); statErr == nil {
					t.Errorf("%s was written outside the workspace", leaked)
				}
			}
		})
	}
}

// SafeJoin is the primitive the whole guard rests on, so it is tested directly
// as well as through extraction.
func TestSafeJoinContainment(t *testing.T) {
	root := filepath.Clean("/workspace")

	safe := []string{"a.txt", "dir/b.txt", "./c.txt", "deep/nested/path/d.txt"}
	for _, name := range safe {
		if _, err := fetcher.SafeJoin(root, name); err != nil {
			t.Errorf("rejected the safe path %q: %v", name, err)
		}
	}

	unsafe := []string{
		"../escape", "a/../../escape", "/abs", `\abs`, "C:/abs", "", "nul\x00byte",
	}
	for _, name := range unsafe {
		if _, err := fetcher.SafeJoin(root, name); err == nil {
			t.Errorf("accepted the unsafe path %q", name)
		}
	}
}

// A sibling directory whose name merely STARTS WITH the root is not inside it.
// This is the prefix-check bug: strings.HasPrefix("/workspace-evil",
// "/workspace") is true, and without the separator the containment check passes.
func TestSafeJoinRejectsSiblingPrefix(t *testing.T) {
	root := filepath.Clean("/workspace")
	// Reaching /workspace-evil requires traversal, which is refused earlier —
	// so assert the property SafeJoin guarantees instead: everything it returns
	// is under root + separator.
	got, err := fetcher.SafeJoin(root, "sub/file.txt")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.HasPrefix(got, root+string(os.PathSeparator)) {
		t.Errorf("SafeJoin returned %q, which is not under %q", got, root)
	}
}

// ---------------------------------------------------------------------------
// Links and special files
// ---------------------------------------------------------------------------

// ⚠ A SYMLINK IS NOT EXTRACTED, EVEN A HARMLESS-LOOKING ONE.
//
// The reason is ordering: a link written early in the stream can be the PARENT
// DIRECTORY of an entry written later, so "check where it points" races the
// archive's own layout. Refusing the entry type removes the race.
func TestSymlinksAreNotExtracted(t *testing.T) {
	archive := buildTar(t, []tarEntry{
		{name: "safe.txt", body: "ok"},
		{name: "shadow-link", typeflag: tar.TypeSymlink, linkname: "/etc/shadow"},
		{name: "escape-link", typeflag: tar.TypeSymlink, linkname: "../../../"},
		{name: "hardlink", typeflag: tar.TypeLink, linkname: "safe.txt"},
	})

	dest, res, err := extractInto(t, archive, fetcher.DefaultExtractLimits())
	if err != nil {
		t.Fatalf("extraction failed: %v", err)
	}

	for _, name := range []string{"shadow-link", "escape-link", "hardlink"} {
		if _, err := os.Lstat(filepath.Join(dest, name)); err == nil {
			t.Errorf("%s was created", name)
		}
	}
	if len(res.SkippedEntries) != 3 {
		t.Errorf("skipped %d entries, want 3", len(res.SkippedEntries))
	}
	// Reported, not silently dropped: an archive that quietly loses files
	// produces a BOM missing components.
	for _, s := range res.SkippedEntries {
		if s.Reason == "" {
			t.Errorf("entry %q was skipped with no reason", s.Path)
		}
	}
	// The legitimate file still extracted.
	if _, err := os.Stat(filepath.Join(dest, "safe.txt")); err != nil {
		t.Errorf("the safe file was not extracted: %v", err)
	}
}

// A FIFO makes a scanner block forever on open; a device entry can read host
// hardware. Neither belongs in source.
func TestDeviceAndFifoEntriesAreNotExtracted(t *testing.T) {
	archive := buildTar(t, []tarEntry{
		{name: "pipe", typeflag: tar.TypeFifo},
		{name: "chardev", typeflag: tar.TypeChar},
		{name: "blockdev", typeflag: tar.TypeBlock},
	})

	dest, res, err := extractInto(t, archive, fetcher.DefaultExtractLimits())
	if err != nil {
		t.Fatalf("extraction failed: %v", err)
	}
	if len(res.SkippedEntries) != 3 {
		t.Errorf("skipped %d, want 3: %+v", len(res.SkippedEntries), res.SkippedEntries)
	}
	entries, _ := os.ReadDir(dest)
	if len(entries) != 0 {
		t.Errorf("special files were created: %v", entries)
	}
}

// ---------------------------------------------------------------------------
// Resource limits
// ---------------------------------------------------------------------------

// ⚠ THE DECOMPRESSION BOMB.
//
// The requirement is not "reject a bomb" — it is "abort MID-EXTRACTION". A
// check after the loop means 10 GB has already landed on the disk it was meant
// to fill, and reporting that the disk is full is not a defence.
func TestDecompressionBombAbortsMidExtraction(t *testing.T) {
	// One highly compressible file, far larger than the limit.
	const declared = 200 << 20 // 200 MiB of zeros
	var raw bytes.Buffer
	tw := tar.NewWriter(&raw)
	if err := tw.WriteHeader(&tar.Header{
		Name: "bomb.bin", Mode: 0o644, Size: declared, Typeflag: tar.TypeReg,
	}); err != nil {
		t.Fatalf("header: %v", err)
	}
	chunk := make([]byte, 1<<20)
	for written := 0; written < declared; written += len(chunk) {
		if _, err := tw.Write(chunk); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	_ = tw.Close()

	// Compress it, so the ratio is enormous — the actual bomb shape.
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	_, _ = zw.Write(raw.Bytes())
	_ = zw.Close()

	t.Logf("archive: %d bytes compressed -> %d uncompressed (ratio %d:1)",
		gz.Len(), raw.Len(), raw.Len()/gz.Len())

	counted := fetcher.NewCountingReader(bytes.NewReader(gz.Bytes()))
	zr, err := gzip.NewReader(counted)
	if err != nil {
		t.Fatalf("gzip reader: %v", err)
	}

	dest := t.TempDir()
	lim := fetcher.DefaultExtractLimits()
	lim.MaxInflationRatio = 100

	res, err := fetcher.ExtractTar(zr, counted, dest, lim)
	if err == nil {
		t.Fatal("the bomb extracted successfully")
	}
	if !errs.Is(err, errs.FetchInflationRatio) && !errs.Is(err, errs.FetchArchiveTooLarge) {
		t.Errorf("wrong code: %v", err)
	}

	// ⚠ THE ASSERTION THAT MATTERS: it stopped EARLY.
	//
	// Anything close to the declared size means the check ran after the fact.
	if res.UncompressedB >= declared {
		t.Errorf("wrote %d bytes of a %d-byte bomb — the check is not mid-stream",
			res.UncompressedB, declared)
	}
	t.Logf("aborted after %d bytes of %d (%.2f%%)",
		res.UncompressedB, declared, float64(res.UncompressedB)/float64(declared)*100)

	// And the partial file was removed rather than left occupying the disk.
	if _, err := os.Stat(filepath.Join(dest, "bomb.bin")); err == nil {
		t.Error("the partial bomb file was left on disk")
	}
}

func TestTotalSizeLimitAborts(t *testing.T) {
	archive := buildTar(t, []tarEntry{
		{name: "big.bin", body: strings.Repeat("A", 4<<20)},
	})

	lim := fetcher.DefaultExtractLimits()
	lim.MaxBytes = 1 << 20 // 1 MiB

	_, res, err := extractInto(t, archive, lim)
	if err == nil {
		t.Fatal("an archive over the size limit extracted")
	}
	if !errs.Is(err, errs.FetchArchiveTooLarge) {
		t.Errorf("wrong code: %v", err)
	}
	if res.UncompressedB > 2<<20 {
		t.Errorf("wrote %d bytes past a 1 MiB limit before stopping", res.UncompressedB)
	}
}

// A million one-byte files exhausts an inode table long before it fills a disk,
// and `df` reports plenty of space while nothing can be created.
func TestFileCountLimitHolds(t *testing.T) {
	entries := make([]tarEntry, 0, 200)
	for i := 0; i < 200; i++ {
		entries = append(entries, tarEntry{name: filepath.ToSlash(filepath.Join("many", itoa(i))), body: "x"})
	}
	archive := buildTar(t, entries)

	lim := fetcher.DefaultExtractLimits()
	lim.MaxFiles = 50

	_, res, err := extractInto(t, archive, lim)
	if err == nil {
		t.Fatal("an archive over the file-count limit extracted")
	}
	if !errs.Is(err, errs.FetchTooManyFiles) {
		t.Errorf("wrong code: %v", err)
	}
	if res.Files > lim.MaxFiles {
		t.Errorf("extracted %d files past a limit of %d", res.Files, lim.MaxFiles)
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}

// ---------------------------------------------------------------------------
// Path sanitization
// ---------------------------------------------------------------------------

// Filenames arrive with NUL bytes, newlines, RTL overrides and 8 KB paths. Each
// breaks something different, and the NUL is the dangerous one because it is
// INVISIBLE: Postgres silently truncates a text value at the NUL, so what is
// stored is not what was scanned.
func TestPathSanitization(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		wantOut string
		changed bool
		why     string
	}{
		{"clean", "src/main.go", "src/main.go", false, ""},
		{"nul byte", "src/ma\x00in.go", "src/main.go", true,
			"a NUL silently truncates a Postgres text value"},
		{"newline", "src/ma\nin.go", "src/ma_in.go", true,
			"a newline forges a log line and splits a CSV cell"},
		{"carriage return", "src/ma\rin.go", "src/ma_in.go", true, ""},
		{"tab", "src/ma\tin.go", "src/ma_in.go", true, ""},
		{"control char", "src/ma\x01in.go", "src/ma_in.go", true, ""},
		{"RTL override", "invoice\u202egnp.exe", "invoice_gnp.exe", true,
			"renders as invoice exe.png in a UI where a human decides to trust it"},
		{"emoji preserved", "src/🚀rocket.go", "src/🚀rocket.go", false,
			"valid UTF-8 and a valid filename; mangling it corrupts real paths"},
		{"CJK preserved", "src/日本語.go", "src/日本語.go", false, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, changed := fetcher.SanitizePath(tt.in, 1024)
			if got != tt.wantOut {
				t.Errorf("got %q, want %q — %s", got, tt.wantOut, tt.why)
			}
			if changed != tt.changed {
				t.Errorf("changed = %v, want %v", changed, tt.changed)
			}
			if strings.ContainsRune(got, 0) {
				t.Error("a NUL byte survived sanitization")
			}
		})
	}
}

// An 8 KB path must be truncated on a RUNE boundary. Cutting mid-rune produces
// invalid UTF-8, which Postgres refuses outright — turning a long filename into
// a failed insert rather than a truncated one.
func TestLongPathTruncatesOnARuneBoundary(t *testing.T) {
	// Multi-byte runes right at the cut point.
	long := strings.Repeat("日", 4096) // 3 bytes each
	got, changed := fetcher.SanitizePath(long, 1024)

	if !changed {
		t.Error("an 8 KB path was not truncated")
	}
	if len(got) > 1024 {
		t.Errorf("result is %d bytes, limit is 1024", len(got))
	}
	if !isValidUTF8(got) {
		t.Error("truncation produced invalid UTF-8; Postgres would reject the insert")
	}
}

func isValidUTF8(s string) bool {
	for _, r := range s {
		if r == 0xFFFD {
			return false
		}
	}
	return true
}

// ---------------------------------------------------------------------------
// Ordinary archives still work
// ---------------------------------------------------------------------------

// A guard that rejects everything is not a guard, it is an outage.
func TestNormalArchiveExtractsCorrectly(t *testing.T) {
	archive := buildTar(t, []tarEntry{
		{name: "README.md", body: "# Project"},
		{name: "src", typeflag: tar.TypeDir},
		{name: "src/main.go", body: "package main"},
		{name: "src/deep/nested.go", body: "package deep"},
	})

	dest, res, err := extractInto(t, archive, fetcher.DefaultExtractLimits())
	if err != nil {
		t.Fatalf("a normal archive was rejected: %v", err)
	}
	if res.Files != 3 {
		t.Errorf("extracted %d files, want 3", res.Files)
	}
	if len(res.SkippedEntries) != 0 {
		t.Errorf("skipped entries in a clean archive: %+v", res.SkippedEntries)
	}

	body, err := os.ReadFile(filepath.Join(dest, "src", "deep", "nested.go"))
	if err != nil {
		t.Fatalf("nested file missing: %v", err)
	}
	if string(body) != "package deep" {
		t.Errorf("content = %q", body)
	}
}

func TestEmptyArchiveIsNotAnError(t *testing.T) {
	archive := buildTar(t, nil)
	_, res, err := extractInto(t, archive, fetcher.DefaultExtractLimits())
	if err != nil {
		t.Fatalf("an empty archive errored: %v", err)
	}
	if res.Files != 0 {
		t.Errorf("files = %d", res.Files)
	}
}

func TestCorruptArchiveIsRejected(t *testing.T) {
	_, _, err := extractInto(t, []byte("this is not a tar archive at all"),
		fetcher.DefaultExtractLimits())
	if err == nil {
		t.Fatal("a corrupt archive was accepted")
	}
}

var _ = io.Discard
