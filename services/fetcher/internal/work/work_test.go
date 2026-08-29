package work

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/axebom/axebom/libs/go-shared/bus"
	"github.com/axebom/axebom/libs/go-shared/events"
	"github.com/axebom/axebom/libs/go-shared/platform/blob"
	"github.com/axebom/axebom/libs/go-shared/platform/config"
	"github.com/axebom/axebom/libs/go-shared/projectsource"
	"github.com/axebom/axebom/libs/go-shared/sandbox"
)

// Upload materialization, against REAL object storage.
//
// Matching the convention this codebase already uses for this layer (see
// libs/go-shared/bus/bus_test.go, services/project/internal/service/
// upload_test.go): a mocked blob store would prove nothing about whether
// materialization actually reads what was actually stored, extracts it
// correctly, and refuses what it should refuse. This is package `work`
// (internal, not `work_test`) specifically so these tests can reach
// materializeUpload directly — it is unexported, and the point of testing it
// here is the format-dispatch and archive-guard behavior, not the NATS
// plumbing around it (Bus and sandbox.Runner are still required by New, but
// neither is exercised by materializeUpload itself).

// refusingRunner fails the test if the sandbox is ever invoked.
// materializeUpload must never start a container — there is nothing to clone.
type refusingRunner struct{ t *testing.T }

func (rr refusingRunner) Run(context.Context, sandbox.Spec) (sandbox.Result, error) {
	rr.t.Fatal("the sandbox runner was invoked while materializing an upload")
	return sandbox.Result{}, nil
}
func (refusingRunner) Ping(context.Context) error { return nil }
func (refusingRunner) Close() error               { return nil }

// noopResolver is never called by these tests — materializeUpload takes a
// Source directly — but New requires a non-nil Resolver.
type noopResolver struct{}

func (noopResolver) Resolve(context.Context, string, string) (projectsource.Source, error) {
	return projectsource.Source{}, errors.New("not used by these tests")
}

// newFetchFixture is the bus+store connection setup New requires for
// construction regardless of which materialize* path a test exercises — even
// the ones (materializeUpload, materializeURL) that never call a method on
// either. Real infra, not mocks, matching the convention this codebase
// already uses for this layer.
func newFetchFixture(t *testing.T) (*bus.Bus, *blob.Store) {
	t.Helper()
	if os.Getenv("SKIP_DB_TESTS") != "" {
		t.Skip("SKIP_DB_TESTS is set")
	}

	cfg, err := config.LoadService("fetcher")
	if err != nil {
		t.Fatalf("config: %v", err)
	}

	store, err := blob.Open(t.Context(), cfg.S3)
	if err != nil {
		t.Skipf("object storage unavailable (%v) — run `task dev`", err)
	}

	b, err := bus.Connect(t.Context(), bus.Config{URL: cfg.NATS.URL, Name: "work-test"})
	if err != nil {
		t.Skipf("NATS unavailable (%v) — run `task dev`", err)
	}
	t.Cleanup(func() { _ = b.Close() })

	return b, store
}

func newUploadWorkerFixture(t *testing.T) (*Worker, *blob.Store) {
	t.Helper()
	b, store := newFetchFixture(t)

	w, err := New(Options{
		Bus:           b,
		Runner:        refusingRunner{t: t},
		Store:         store,
		Resolver:      noopResolver{},
		WorkspaceRoot: t.TempDir(),
	})
	if err != nil {
		t.Fatalf("new worker: %v", err)
	}
	return w, store
}

func uniqueKey(t *testing.T, name string) string {
	t.Helper()
	return fmt.Sprintf("test-uploads/%s-%d/%s", t.Name(), time.Now().UnixNano(), name)
}

func stage(t *testing.T, store *blob.Store, name string, content []byte) string {
	t.Helper()
	key := uniqueKey(t, name)
	if _, err := store.Put(t.Context(), key, bytes.NewReader(content), blob.PutOptions{}); err != nil {
		t.Fatalf("stage fixture upload %q: %v", key, err)
	}
	return key
}

func buildZipFixture(t *testing.T, entries map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, body := range entries {
		f, err := zw.Create(name)
		if err != nil {
			t.Fatalf("zip create %q: %v", name, err)
		}
		if _, err := f.Write([]byte(body)); err != nil {
			t.Fatalf("zip write %q: %v", name, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zip close: %v", err)
	}
	return buf.Bytes()
}

func buildTarGzFixture(t *testing.T, entries map[string]string) []byte {
	t.Helper()
	var raw bytes.Buffer
	tw := tar.NewWriter(&raw)
	for name, body := range entries {
		if err := tw.WriteHeader(&tar.Header{
			Name: name, Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg,
		}); err != nil {
			t.Fatalf("tar header %q: %v", name, err)
		}
		if _, err := tw.Write([]byte(body)); err != nil {
			t.Fatalf("tar write %q: %v", name, err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("tar close: %v", err)
	}

	var gz bytes.Buffer
	gw := gzip.NewWriter(&gz)
	if _, err := gw.Write(raw.Bytes()); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := gw.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	return gz.Bytes()
}

func TestMaterializeUploadExtractsAZipSourceArchive(t *testing.T) {
	w, store := newUploadWorkerFixture(t)

	archive := buildZipFixture(t, map[string]string{
		"README.md":       "hello",
		"src/main.go":     "package main",
		"src/nested/a.go": "package nested",
	})
	key := stage(t, store, "src.zip", archive)

	dest := t.TempDir()
	src := projectsource.Source{
		Kind: events.SourceUpload, StorageRef: key,
		UploadKind: "source_archive", OriginalFilename: "src.zip",
	}
	if err := w.materializeUpload(t.Context(), src, dest); err != nil {
		t.Fatalf("materializeUpload: %v", err)
	}

	for path, want := range map[string]string{
		"README.md":       "hello",
		"src/main.go":     "package main",
		"src/nested/a.go": "package nested",
	} {
		got, err := os.ReadFile(filepath.Join(dest, path))
		if err != nil {
			t.Errorf("%s: %v", path, err)
			continue
		}
		if string(got) != want {
			t.Errorf("%s: got %q, want %q", path, got, want)
		}
	}
}

func TestMaterializeUploadExtractsATarGzSourceArchive(t *testing.T) {
	w, store := newUploadWorkerFixture(t)

	archive := buildTarGzFixture(t, map[string]string{"lib/util.go": "package lib"})
	key := stage(t, store, "src.tar.gz", archive)

	dest := t.TempDir()
	src := projectsource.Source{
		Kind: events.SourceUpload, StorageRef: key,
		UploadKind: "source_archive", OriginalFilename: "src.tar.gz",
	}
	if err := w.materializeUpload(t.Context(), src, dest); err != nil {
		t.Fatalf("materializeUpload: %v", err)
	}

	got, err := os.ReadFile(filepath.Join(dest, "lib/util.go"))
	if err != nil {
		t.Fatalf("extracted file missing: %v", err)
	}
	if string(got) != "package lib" {
		t.Errorf("got %q", got)
	}
}

// A manifest/lockfile/sbom/hbom_csv upload is never extracted — it is placed
// into the workspace under its own name, unopened, exactly as the project
// service's own upload path never opens it either (services/project/internal/
// service/upload_test.go's TestNoExtractionCodePathExists asserts that side;
// this asserts the fetcher does the equivalent thing correctly on the way in).
func TestMaterializeUploadPlacesASingleFileWithoutExtracting(t *testing.T) {
	w, store := newUploadWorkerFixture(t)

	content := []byte(`{"name":"acme-app","dependencies":{}}`)
	key := stage(t, store, "package.json", content)

	dest := t.TempDir()
	src := projectsource.Source{
		Kind: events.SourceUpload, StorageRef: key,
		UploadKind: "manifest", OriginalFilename: "package.json",
	}
	if err := w.materializeUpload(t.Context(), src, dest); err != nil {
		t.Fatalf("materializeUpload: %v", err)
	}

	got, err := os.ReadFile(filepath.Join(dest, "package.json"))
	if err != nil {
		t.Fatalf("file missing: %v", err)
	}
	if string(got) != string(content) {
		t.Errorf("got %q, want %q", got, content)
	}
}

func TestMaterializeUploadFailsCleanlyWhenTheObjectIsMissing(t *testing.T) {
	w, _ := newUploadWorkerFixture(t)

	src := projectsource.Source{
		Kind: events.SourceUpload, StorageRef: uniqueKey(t, "never-uploaded.zip"),
		UploadKind: "source_archive", OriginalFilename: "never-uploaded.zip",
	}
	err := w.materializeUpload(t.Context(), src, t.TempDir())
	if err == nil {
		t.Fatal("materialization succeeded against an object that was never stored")
	}

	var fail *fetchFailure
	if !errors.As(err, &fail) {
		t.Fatalf("expected a *fetchFailure (terminal, not retried), got %T: %v", err, err)
	}
	if fail.code != "FETCH_NO_SOURCE" {
		t.Errorf("code = %q, want FETCH_NO_SOURCE", fail.code)
	}
}

// An upload whose filename carries an unrecognized extension is refused with
// a clear taxonomy code, not guessed at by sniffing content.
func TestMaterializeUploadRefusesAnUnrecognizedArchiveFormat(t *testing.T) {
	w, store := newUploadWorkerFixture(t)

	key := stage(t, store, "src.rar", []byte("not actually a rar file, or anything else"))

	src := projectsource.Source{
		Kind: events.SourceUpload, StorageRef: key,
		UploadKind: "source_archive", OriginalFilename: "src.rar",
	}
	err := w.materializeUpload(t.Context(), src, t.TempDir())
	if err == nil {
		t.Fatal("an unrecognized archive format was accepted")
	}

	var fail *fetchFailure
	if !errors.As(err, &fail) {
		t.Fatalf("expected a *fetchFailure, got %T: %v", err, err)
	}
	if fail.code != "FETCH_UNSUPPORTED_ARCHIVE_FORMAT" {
		t.Errorf("code = %q, want FETCH_UNSUPPORTED_ARCHIVE_FORMAT", fail.code)
	}
}

// A hostile zip-slip archive uploaded by a user is exactly as untrusted as one
// cloned from git, and must not write anything outside the workspace.
func TestMaterializeUploadRejectsPathTraversal(t *testing.T) {
	w, store := newUploadWorkerFixture(t)

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	// A distinctive name, not a real path like /etc/passwd: checking for its
	// escape below must not accidentally observe a file that already exists on
	// the host for reasons unrelated to this test.
	f, err := zw.Create("../../axebom-test-escape-marker.txt")
	if err != nil {
		t.Fatalf("zip create: %v", err)
	}
	_, _ = f.Write([]byte("pwned"))
	if err := zw.Close(); err != nil {
		t.Fatalf("zip close: %v", err)
	}
	key := stage(t, store, "evil.zip", buf.Bytes())

	dest := t.TempDir()
	src := projectsource.Source{
		Kind: events.SourceUpload, StorageRef: key,
		UploadKind: "source_archive", OriginalFilename: "evil.zip",
	}
	if err := w.materializeUpload(t.Context(), src, dest); err == nil {
		t.Fatal("a path-traversal archive was extracted without error")
	}

	// Two levels up from dest is exactly where the entry's ".." segments
	// resolve to, mirroring SafeJoin's own containment math.
	escaped := filepath.Join(dest, "..", "..", "axebom-test-escape-marker.txt")
	if _, statErr := os.Stat(escaped); statErr == nil {
		t.Error("the traversal entry escaped the workspace")
		_ = os.Remove(escaped)
	}
}

// The production path — handle() dispatching on src.Kind — uses the
// SSRF-hardened SafeHTTPClient default, not a test override. This pins that
// New() wires it in when Options.HTTPClient is left unset, so a live fetch
// job (the GitHub Dependency Graph call) cannot silently end up on an
// unguarded client.
func TestNewDefaultsToTheSafeHTTPClient(t *testing.T) {
	b, store := newFetchFixture(t)
	w, err := New(Options{
		Bus: b, Runner: refusingRunner{t: t}, Store: store, Resolver: noopResolver{},
		WorkspaceRoot: t.TempDir(),
		// HTTPClient deliberately left unset.
	})
	if err != nil {
		t.Fatalf("new worker: %v", err)
	}
	if w.httpClient == nil {
		t.Fatal("httpClient is nil; materializeURL/fetchDependencyGraphSBOM would panic")
	}
	if w.httpClient == http.DefaultClient {
		t.Error("httpClient defaulted to http.DefaultClient, not the SSRF-hardened SafeHTTPClient")
	}
}
