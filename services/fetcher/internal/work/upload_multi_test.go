package work

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/axebom/axebom/libs/go-shared/events"
	"github.com/axebom/axebom/libs/go-shared/fetcher"
	"github.com/axebom/axebom/libs/go-shared/projectsource"
)

// Every upload, one workspace — against REAL object storage, the same
// convention as work_test.go.

// tree maps every regular file under root (slash-separated, relative) to its
// content.
func tree(t *testing.T, root string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		// #nosec G304 -- path comes from walking the test's own temp directory.
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		out[filepath.ToSlash(rel)] = string(data)
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
	return out
}

func assertTree(t *testing.T, got, want map[string]string) {
	t.Helper()
	if len(got) != len(want) {
		t.Errorf("workspace holds %d files, want %d: %v", len(got), len(want), keys(got))
	}
	for path, body := range want {
		g, ok := got[path]
		if !ok {
			t.Errorf("%s is missing from the workspace (have %v)", path, keys(got))
			continue
		}
		if g != body {
			t.Errorf("%s = %q, want %q", path, g, body)
		}
	}
}

func keys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func uploadSource(uploads ...projectsource.Upload) projectsource.Source {
	return projectsource.Source{Kind: events.SourceUpload, Uploads: uploads}
}

func asFailure(t *testing.T, err error) *fetchFailure {
	t.Helper()
	if err == nil {
		t.Fatal("materialization succeeded; it should have failed the source step")
	}
	var fail *fetchFailure
	if !errors.As(err, &fail) {
		t.Fatalf("expected a terminal *fetchFailure, got %T: %v", err, err)
	}
	return fail
}

func TestMaterializeUploadPlacesEveryUpload(t *testing.T) {
	w, store := newUploadWorkerFixture(t)
	archive := stage(t, store, "src.zip", buildZipFixture(t, map[string]string{
		"main.go": "package main\n", "go.mod": "module example.com/x\n",
	}))
	lock := stage(t, store, "package-lock.json", []byte(`{"lockfileVersion":3}`))

	// Listed newest first on purpose: placement follows upload id, not the
	// order the project service happened to send.
	src := uploadSource(
		projectsource.Upload{UploadID: idB, UploadKind: "lockfile", StorageRef: lock, OriginalFilename: "package-lock.json"},
		projectsource.Upload{UploadID: idA, UploadKind: "source_archive", StorageRef: archive, OriginalFilename: "src.zip"},
	)
	dest := t.TempDir()
	if err := w.materializeUpload(t.Context(), src, dest); err != nil {
		t.Fatalf("materializeUpload: %v", err)
	}

	assertTree(t, tree(t, dest), map[string]string{
		"uploads/src/main.go":       "package main\n",
		"uploads/src/go.mod":        "module example.com/x\n",
		"uploads/package-lock.json": `{"lockfileVersion":3}`,
	})
}

func TestMaterializeUploadIsByteIdenticalOnReplay(t *testing.T) {
	w, store := newUploadWorkerFixture(t)
	archive := stage(t, store, "app.tar.gz", buildTarGzFixture(t, map[string]string{
		"requirements.txt": "flask==3.0.0\n", "app.py": "print('hi')\n",
	}))
	manifest := stage(t, store, "package.json", []byte(`{"name":"x"}`))
	a := projectsource.Upload{UploadID: idA, UploadKind: "source_archive", StorageRef: archive, OriginalFilename: "app.tar.gz"}
	b := projectsource.Upload{UploadID: idB, UploadKind: "manifest", StorageRef: manifest, OriginalFilename: "package.json"}

	first, second := t.TempDir(), t.TempDir()
	if err := w.materializeUpload(t.Context(), uploadSource(a, b), first); err != nil {
		t.Fatalf("first materialization: %v", err)
	}
	if err := w.materializeUpload(t.Context(), uploadSource(b, a), second); err != nil {
		t.Fatalf("second materialization: %v", err)
	}

	prefix := uniqueKey(t, "archives")
	one, err := fetcher.CreateArchive(t.Context(), store, first, prefix, fetcher.DefaultArchiveLimits())
	if err != nil {
		t.Fatalf("archive first: %v", err)
	}
	two, err := fetcher.CreateArchive(t.Context(), store, second, prefix, fetcher.DefaultArchiveLimits())
	if err != nil {
		t.Fatalf("archive second: %v", err)
	}
	if one.SHA256 != two.SHA256 {
		t.Fatalf("the same uploads produced two different archives: %s vs %s", one.SHA256, two.SHA256)
	}
}

func TestMaterializeUploadKeepsSameNamedFilesApart(t *testing.T) {
	w, store := newUploadWorkerFixture(t)
	older := stage(t, store, "package.json", []byte(`{"name":"older"}`))
	newer := stage(t, store, "package.json", []byte(`{"name":"newer"}`))

	src := uploadSource(
		projectsource.Upload{UploadID: idA, UploadKind: "manifest", StorageRef: older, OriginalFilename: "package.json"},
		projectsource.Upload{UploadID: idB, UploadKind: "manifest", StorageRef: newer, OriginalFilename: "package.json"},
	)
	dest := t.TempDir()
	if err := w.materializeUpload(t.Context(), src, dest); err != nil {
		t.Fatalf("materializeUpload: %v", err)
	}

	// Neither overwrote the other, and both kept the basename engines look for.
	assertTree(t, tree(t, dest), map[string]string{
		"uploads/package.json":              `{"name":"older"}`,
		"uploads/00000000000b/package.json": `{"name":"newer"}`,
	})
}

// ⚠ THE CEILING IS ONE BUDGET PER SCAN. Each case's uploads are individually
// within the limit and only their sum exceeds it — proven by materializing
// each one alone under the same limits first.
func TestMaterializeUploadEnforcesLimitsAcrossAllUploads(t *testing.T) {
	w, store := newUploadWorkerFixture(t)
	// 200 bytes each against a 300-byte ceiling: any one upload fits, any two do
	// not. The ceiling also has to exceed a small zip's COMPRESSED size, which
	// is staged against the same limit before extraction.
	body := strings.Repeat("x", 200)

	lockA := stage(t, store, "a.lock", []byte(body))
	lockB := stage(t, store, "b.lock", []byte(body))
	twoFiles := stage(t, store, "two.zip", buildZipFixture(t, map[string]string{"1.txt": "1", "2.txt": "2"}))
	bigZip := stage(t, store, "big.zip", buildZipFixture(t, map[string]string{"f.txt": body}))

	cases := []struct {
		name     string
		limits   fetcher.ExtractLimits
		uploads  []projectsource.Upload
		wantCode string
		failing  string // the upload the message must name
	}{
		{
			name:   "bytes across two files",
			limits: fetcher.ExtractLimits{MaxBytes: 300, MaxFiles: 100, MaxInflationRatio: 100, MaxPathBytes: 1024},
			uploads: []projectsource.Upload{
				{UploadID: idA, UploadKind: "lockfile", StorageRef: lockA, OriginalFilename: "a.lock"},
				{UploadID: idB, UploadKind: "lockfile", StorageRef: lockB, OriginalFilename: "b.lock"},
			},
			wantCode: "FETCH_ARCHIVE_TOO_LARGE",
			failing:  "b.lock",
		},
		{
			name:   "bytes across a file and an archive",
			limits: fetcher.ExtractLimits{MaxBytes: 300, MaxFiles: 100, MaxInflationRatio: 100, MaxPathBytes: 1024},
			uploads: []projectsource.Upload{
				{UploadID: idA, UploadKind: "lockfile", StorageRef: lockA, OriginalFilename: "a.lock"},
				{UploadID: idB, UploadKind: "source_archive", StorageRef: bigZip, OriginalFilename: "big.zip"},
			},
			wantCode: "FETCH_ARCHIVE_TOO_LARGE",
			failing:  "big.zip",
		},
		{
			name:   "files across an archive and a file",
			limits: fetcher.ExtractLimits{MaxBytes: 1 << 20, MaxFiles: 2, MaxInflationRatio: 100, MaxPathBytes: 1024},
			uploads: []projectsource.Upload{
				{UploadID: idA, UploadKind: "source_archive", StorageRef: twoFiles, OriginalFilename: "two.zip"},
				{UploadID: idB, UploadKind: "lockfile", StorageRef: lockB, OriginalFilename: "b.lock"},
			},
			wantCode: "FETCH_TOO_MANY_FILES",
			failing:  "b.lock",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w.extractLimits = tc.limits
			defer func() { w.extractLimits = fetcher.ExtractLimits{} }()

			for _, u := range tc.uploads {
				if err := w.materializeUpload(t.Context(), uploadSource(u), t.TempDir()); err != nil {
					t.Fatalf("%s alone should fit the limit: %v", u.OriginalFilename, err)
				}
			}

			fail := asFailure(t, w.materializeUpload(t.Context(), uploadSource(tc.uploads...), t.TempDir()))
			if fail.code != tc.wantCode {
				t.Errorf("code = %q, want %q", fail.code, tc.wantCode)
			}
			if !strings.Contains(fail.message, tc.failing) || !strings.Contains(fail.message, "together") {
				t.Errorf("message %q must name %s and say the limit is over all uploads together",
					fail.message, tc.failing)
			}
		})
	}
}

func TestMaterializeUploadSanitizesHostileFilenames(t *testing.T) {
	w, store := newUploadWorkerFixture(t)
	body := []byte(`{"lockfileVersion":3}`)

	t.Run("a single upload cannot escape the workspace", func(t *testing.T) {
		key := stage(t, store, "escape.txt", body)
		parent := t.TempDir()
		dest := filepath.Join(parent, "ws")
		if err := os.MkdirAll(dest, 0o750); err != nil {
			t.Fatal(err)
		}

		src := projectsource.Source{Kind: events.SourceUpload, UploadID: idA,
			UploadKind: "lockfile", StorageRef: key, OriginalFilename: "../escape.txt"}
		if err := w.materializeUpload(t.Context(), src, dest); err != nil {
			t.Fatalf("materializeUpload: %v", err)
		}
		if _, err := os.Stat(filepath.Join(parent, "escape.txt")); err == nil {
			t.Fatal("an upload named ../escape.txt was written OUTSIDE the workspace")
		}
		assertTree(t, tree(t, dest), map[string]string{"escape.txt": string(body)})
	})

	t.Run("several uploads each land as one safe segment", func(t *testing.T) {
		one := stage(t, store, "passwd", body)
		two := stage(t, store, "x.json", body)
		dest := t.TempDir()

		src := uploadSource(
			projectsource.Upload{UploadID: idA, UploadKind: "lockfile", StorageRef: one, OriginalFilename: "../../etc/passwd"},
			projectsource.Upload{UploadID: idB, UploadKind: "manifest", StorageRef: two, OriginalFilename: `..\x.json`},
		)
		if err := w.materializeUpload(t.Context(), src, dest); err != nil {
			t.Fatalf("materializeUpload: %v", err)
		}
		assertTree(t, tree(t, dest), map[string]string{
			"uploads/passwd": string(body),
			"uploads/x.json": string(body),
		})
	})
}

// ⚠ NO UPLOAD IS SKIPPED. One that cannot be materialized fails the whole
// source step with its own code and a message naming it (invariant 12).
func TestMaterializeUploadFailsTheStepWhenAnyUploadFails(t *testing.T) {
	w, store := newUploadWorkerFixture(t)
	good := stage(t, store, "package.json", []byte(`{"name":"x"}`))
	rar := stage(t, store, "src.rar", []byte("not a rar"))
	goodUpload := projectsource.Upload{UploadID: idA, UploadKind: "manifest", StorageRef: good, OriginalFilename: "package.json"}

	cases := []struct {
		name     string
		broken   projectsource.Upload
		wantCode string
	}{
		{
			name: "an object missing from storage",
			broken: projectsource.Upload{UploadID: idB, UploadKind: "source_archive",
				StorageRef: uniqueKey(t, "gone.zip"), OriginalFilename: "gone.zip"},
			wantCode: "FETCH_NO_SOURCE",
		},
		{
			name:     "an upload with no stored object at all",
			broken:   projectsource.Upload{UploadID: idB, UploadKind: "lockfile", OriginalFilename: "empty.lock"},
			wantCode: "FETCH_NO_SOURCE",
		},
		{
			name: "an archive in a format nothing validated the guards for",
			broken: projectsource.Upload{UploadID: idB, UploadKind: "source_archive",
				StorageRef: rar, OriginalFilename: "src.rar"},
			wantCode: "FETCH_UNSUPPORTED_ARCHIVE_FORMAT",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fail := asFailure(t, w.materializeUpload(t.Context(), uploadSource(goodUpload, tc.broken), t.TempDir()))
			if fail.code != tc.wantCode {
				t.Errorf("code = %q, want %q", fail.code, tc.wantCode)
			}
			if !strings.Contains(fail.message, tc.broken.OriginalFilename) ||
				!strings.Contains(fail.message, tc.broken.UploadID) {
				t.Errorf("message %q does not name the failing upload %s (%s)",
					fail.message, tc.broken.OriginalFilename, tc.broken.UploadID)
			}
		})
	}
}

// A list of one and the legacy top-level fields are the same source, and must
// produce the same tree as a single upload always has.
func TestMaterializeUploadAListOfOneMatchesTheLegacyFields(t *testing.T) {
	w, store := newUploadWorkerFixture(t)
	key := stage(t, store, "src.zip", buildZipFixture(t, map[string]string{"main.go": "package main\n"}))

	legacy := projectsource.Source{Kind: events.SourceUpload, UploadID: idA,
		UploadKind: "source_archive", StorageRef: key, OriginalFilename: "src.zip"}
	listed := uploadSource(projectsource.Upload{UploadID: idA, UploadKind: "source_archive",
		StorageRef: key, OriginalFilename: "src.zip"})

	legacyDest, listedDest := t.TempDir(), t.TempDir()
	if err := w.materializeUpload(t.Context(), legacy, legacyDest); err != nil {
		t.Fatalf("legacy: %v", err)
	}
	if err := w.materializeUpload(t.Context(), listed, listedDest); err != nil {
		t.Fatalf("listed: %v", err)
	}

	want := map[string]string{"main.go": "package main\n"} // at the ROOT, as before
	assertTree(t, tree(t, legacyDest), want)
	assertTree(t, tree(t, listedDest), want)
}
