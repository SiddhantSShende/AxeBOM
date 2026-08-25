package service_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/axebom/axebom/libs/go-shared/platform/blob"
	"github.com/axebom/axebom/libs/go-shared/platform/config"
	"github.com/axebom/axebom/libs/go-shared/platform/db"
	"github.com/axebom/axebom/libs/go-shared/vault"
	"github.com/axebom/axebom/services/project/internal/service"
	"github.com/axebom/axebom/services/project/internal/store"
)

// Uploads: STORED, never extracted.
//
// Extraction is where zip slip, symlink escape and decompression bombs live. It
// belongs in the Phase 5 sandbox or nowhere, and TestNoExtractionCodePathExists
// below asserts that mechanically rather than by convention.

// newUploadFixture builds a fixture with real object storage attached.
func newUploadFixture(t *testing.T) *fixture {
	t.Helper()
	if os.Getenv("SKIP_DB_TESTS") != "" {
		t.Skip("SKIP_DB_TESTS is set")
	}
	cfg, err := config.LoadService("project")
	if err != nil {
		t.Fatalf("config: %v", err)
	}

	pool, err := db.Open(t.Context(), cfg.Postgres)
	if err != nil {
		t.Skipf("database unavailable (%v) — run `task dev`", err)
	}
	t.Cleanup(pool.Close)

	blobStore, err := blob.Open(t.Context(), cfg.S3)
	if err != nil {
		t.Skipf("object storage unavailable (%v) — run `task dev`", err)
	}

	st := store.New(pool)
	mem := vault.NewMemory()
	return &fixture{
		svc:   service.New(service.Config{Store: st, Blob: blobStore, Vault: mem}),
		store: st, vault: mem, pool: pool,
	}
}

func TestUploadStoresContentAndHashesIt(t *testing.T) {
	f := newUploadFixture(t)
	p := createProject(t, f, tenantA)

	content := []byte(`{"name":"acme-app","lockfileVersion":3,"packages":{}}`)
	want := sha256.Sum256(content)

	u, err := f.svc.Upload(t.Context(), tenantA, p.ID, userA, service.UploadInput{
		Kind:     "lockfile",
		Filename: "package-lock.json",
		Size:     int64(len(content)),
		Content:  bytes.NewReader(content),
	})
	if err != nil {
		t.Fatalf("upload: %v", err)
	}

	// The digest must be computed from the bytes ACTUALLY WRITTEN, never taken
	// from the client — a caller-supplied hash would let any content claim any
	// digest and defeat every integrity check built on it later.
	if u.SHA256 != hex.EncodeToString(want[:]) {
		t.Errorf("sha256 = %s, want %s", u.SHA256, hex.EncodeToString(want[:]))
	}
	if u.SizeBytes != int64(len(content)) {
		t.Errorf("size = %d, want %d", u.SizeBytes, len(content))
	}
	if u.StorageRef == "" {
		t.Error("no storage reference recorded")
	}
	// The key must be tenant-prefixed, so per-tenant lifecycle rules and
	// deletion are possible without scanning the whole bucket.
	if !strings.HasPrefix(u.StorageRef, "uploads/"+tenantA+"/") {
		t.Errorf("storage key %q is not tenant-prefixed", u.StorageRef)
	}
}

// User filenames genuinely contain traversal sequences, NUL bytes and newlines.
// A NUL silently truncates a Postgres text value; a traversal escapes the
// object-key prefix that tenant isolation in storage depends on.
func TestUploadSanitizesTheFilename(t *testing.T) {
	f := newUploadFixture(t)
	p := createProject(t, f, tenantA)

	tests := []struct {
		name     string
		filename string
	}{
		{"unix traversal", "../../../etc/passwd"},
		{"windows traversal", `..\..\windows\system32\config\sam`},
		{"absolute path", "/etc/shadow"},
		{"newline", "evil\nname.json"},
		{"nul byte", "trunc\x00ated.json"},
		{"only dots", "..."},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u, err := f.svc.Upload(t.Context(), tenantA, p.ID, userA, service.UploadInput{
				Kind: "manifest", Filename: tt.filename,
				Content: bytes.NewReader([]byte("{}")),
			})
			if err != nil {
				t.Fatalf("upload: %v", err)
			}

			if strings.ContainsAny(u.OriginalFilename, `/\`) {
				t.Errorf("filename %q retains a path separator", u.OriginalFilename)
			}
			if strings.Contains(u.OriginalFilename, "..") {
				t.Errorf("filename %q retains a traversal sequence", u.OriginalFilename)
			}
			if strings.ContainsAny(u.OriginalFilename, "\x00\n\r") {
				t.Errorf("filename %q retains a control character", u.OriginalFilename)
			}
			if strings.ContainsAny(u.StorageRef, "\x00\n\r") || strings.Contains(u.StorageRef, "..") {
				t.Errorf("storage key %q is unsafe", u.StorageRef)
			}
		})
	}
}

func TestUploadRejectsAnUnknownKind(t *testing.T) {
	f := newUploadFixture(t)
	p := createProject(t, f, tenantA)

	if _, err := f.svc.Upload(t.Context(), tenantA, p.ID, userA, service.UploadInput{
		Kind: "executable", Filename: "payload.bin",
		Content: bytes.NewReader([]byte("MZ")),
	}); err == nil {
		t.Error("an upload kind outside the schema's CHECK constraint was accepted")
	}
}

// A cross-tenant project id must not consume storage: without the ownership
// check BEFORE writing bytes, this is a write primitive against another
// tenant's quota.
func TestUploadToAnotherTenantsProjectIsRefused(t *testing.T) {
	f := newUploadFixture(t)
	p := createProject(t, f, tenantA)

	_, err := f.svc.Upload(t.Context(), tenantB, p.ID, userA, service.UploadInput{
		Kind: "manifest", Filename: "package.json",
		Content: bytes.NewReader([]byte("{}")),
	})
	if err == nil {
		t.Fatal("tenant B uploaded to tenant A's project")
	}
	assertNotFound(t, err)
}

// A ZIP is stored as opaque bytes. Nothing opens it, enumerates it, or writes a
// member to disk — including a zip-slip archive, which must be as boring as any
// other blob at this stage.
func TestArchiveIsStoredWithoutBeingOpened(t *testing.T) {
	f := newUploadFixture(t)
	p := createProject(t, f, tenantA)

	// A minimal ZIP whose single entry name is a traversal path. If anything
	// in this phase extracted, this is the input that would write outside the
	// destination.
	zipWithTraversal := buildZipSlip(t)

	u, err := f.svc.Upload(t.Context(), tenantA, p.ID, userA, service.UploadInput{
		Kind: "source_archive", Filename: "src.zip",
		Content: bytes.NewReader(zipWithTraversal),
	})
	if err != nil {
		t.Fatalf("upload: %v", err)
	}

	// Stored byte-for-byte: the digest matches the input exactly, which is only
	// true if nothing rewrote, repacked or normalized it.
	want := sha256.Sum256(zipWithTraversal)
	if u.SHA256 != hex.EncodeToString(want[:]) {
		t.Error("the archive was modified in transit; it must be stored verbatim")
	}
	if u.SizeBytes != int64(len(zipWithTraversal)) {
		t.Errorf("size = %d, want %d", u.SizeBytes, len(zipWithTraversal))
	}

	// And the malicious member name must not exist anywhere on disk.
	for _, candidate := range []string{
		filepath.Join(os.TempDir(), "evil.txt"),
		filepath.Join(".", "evil.txt"),
	} {
		if _, err := os.Stat(candidate); err == nil {
			t.Errorf("%s exists — the archive was extracted", candidate)
		}
	}
}

// buildZipSlip returns a tiny ZIP whose entry name escapes the destination.
func buildZipSlip(t *testing.T) []byte {
	t.Helper()
	// Hand-built rather than via archive/zip, so this test file does not itself
	// import an archive package — see TestNoExtractionCodePathExists.
	const name = "../../evil.txt"
	body := []byte("pwned")

	var b bytes.Buffer
	// Local file header, stored (no compression), zeroed CRC and sizes are
	// enough: this is never parsed by the product, only stored.
	b.Write([]byte("PK\x03\x04\x14\x00\x00\x00\x00\x00"))
	b.Write(make([]byte, 12))
	b.WriteByte(byte(len(name)))
	b.WriteByte(0)
	b.Write([]byte{0, 0})
	b.WriteString(name)
	b.Write(body)
	return b.Bytes()
}

// ---------------------------------------------------------------------------
// The static assertion the phase asks for
// ---------------------------------------------------------------------------

// ⚠ "Assert no extraction code path exists" (PHASE-04 test requirements).
//
// This parses the service's own source and fails on any import that could open
// an archive or decompress a stream. A comment saying "we do not extract" is a
// promise; this is a check.
//
// When Phase 5 adds real extraction it will live in the SANDBOX, not here, and
// this test will keep it that way.
func TestNoExtractionCodePathExists(t *testing.T) {
	// Packages that can open an archive or decompress a stream.
	forbidden := map[string]string{
		"archive/zip":               "opens ZIP archives",
		"archive/tar":               "opens TAR archives",
		"compress/gzip":             "decompresses gzip streams",
		"compress/bzip2":            "decompresses bzip2 streams",
		"compress/flate":            "decompresses DEFLATE streams",
		"compress/zlib":             "decompresses zlib streams",
		"compress/lzw":              "decompresses LZW streams",
		"os/exec":                   "could shell out to tar or unzip",
		"github.com/mholt/archiver": "extracts archives",
	}

	roots := []string{".", "../store", "../handler", "../github"}
	for _, root := range roots {
		checkNoForbiddenImports(t, root, forbidden)
	}
}

func checkNoForbiddenImports(t *testing.T, dir string, forbidden map[string]string) {
	t.Helper()

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}

	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") {
			continue
		}
		// Test files may legitimately reference these while PROVING the
		// product does not extract. The product files are what matter.
		if strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}

		path := filepath.Join(dir, e.Name())
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}

		for _, imp := range file.Imports {
			p := strings.Trim(imp.Path.Value, `"`)
			if why, bad := forbidden[p]; bad {
				t.Errorf("%s imports %q, which %s.\n"+
					"    This phase STORES uploads and must never open them: "+
					"extraction is untrusted-input handling (zip slip, symlink "+
					"escape, decompression bombs) and belongs in the Phase 5 "+
					"sandbox. See CLAUDE.md invariant 7.", path, p, why)
			}
		}
	}
	_ = ast.Print // keep the ast import meaningful for future structural checks
}

// The blob layer must reject keys that escape their prefix, independently of
// whatever the service passes it.
func TestBlobRejectsUnsafeKeys(t *testing.T) {
	if os.Getenv("SKIP_DB_TESTS") != "" {
		t.Skip("SKIP_DB_TESTS is set")
	}
	cfg, err := config.LoadService("project")
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	store, err := blob.Open(t.Context(), cfg.S3)
	if err != nil {
		t.Skipf("object storage unavailable (%v)", err)
	}

	for _, key := range []string{
		"", "/absolute/key", "uploads/../../etc/passwd", "uploads/\x00null",
	} {
		if _, err := store.Put(t.Context(), key, strings.NewReader("x"), blob.PutOptions{}); err == nil {
			t.Errorf("blob accepted the unsafe key %q", key)
		}
	}
}

// An unbounded upload is the cheapest denial of service in the product: one
// request fills the object store for every tenant.
func TestBlobEnforcesTheSizeCap(t *testing.T) {
	if os.Getenv("SKIP_DB_TESTS") != "" {
		t.Skip("SKIP_DB_TESTS is set")
	}
	cfg, err := config.LoadService("project")
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	bs, err := blob.Open(t.Context(), cfg.S3)
	if err != nil {
		t.Skipf("object storage unavailable (%v)", err)
	}

	key := "uploads/test/size-cap-" + uniqueName(t)
	_, err = bs.Put(t.Context(), key, io.LimitReader(zeros{}, 4096),
		blob.PutOptions{MaxBytes: 1024})
	if err == nil {
		t.Fatal("an upload exceeding its cap was accepted")
	}
	if !strings.Contains(err.Error(), "exceeds") {
		t.Errorf("rejected for the wrong reason: %v", err)
	}
}

// zeros is an infinite reader, for testing the cap without allocating.
type zeros struct{}

func (zeros) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 0
	}
	return len(p), nil
}
