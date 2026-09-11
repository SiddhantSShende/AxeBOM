package work

import (
	"strings"
	"testing"

	"github.com/axebom/axebom/libs/go-shared/projectsource"
)

// Upload ids as the project service mints them (UUIDv7): ordered by time.
const (
	idA = "01a06660-0000-7000-8000-00000000000a"
	idB = "01a06660-0000-7000-8000-00000000000b"
	idC = "01a06660-0000-7000-8000-00000000000c"
)

func up(id, kind, name string) projectsource.Upload {
	return projectsource.Upload{UploadID: id, UploadKind: kind, StorageRef: "k/" + id, OriginalFilename: name}
}

func TestPlanUploadLayout(t *testing.T) {
	type place struct {
		id      string
		rel     string
		extract bool
	}
	cases := []struct {
		name    string
		uploads []projectsource.Upload
		want    []place
	}{
		{
			name:    "one archive is extracted at the root, exactly as before",
			uploads: []projectsource.Upload{up(idA, "source_archive", "src.zip")},
			want:    []place{{idA, "", true}},
		},
		{
			name:    "one lockfile is written at the root under its name, exactly as before",
			uploads: []projectsource.Upload{up(idA, "lockfile", "package-lock.json")},
			want:    []place{{idA, "package-lock.json", false}},
		},
		{
			name:    "one unnamed file keeps the legacy fallback name",
			uploads: []projectsource.Upload{up(idA, "manifest", "")},
			want:    []place{{idA, "source", false}},
		},
		{
			name: "an archive and a lockfile each get their own place under uploads/",
			uploads: []projectsource.Upload{
				up(idB, "lockfile", "package-lock.json"),
				up(idA, "source_archive", "src.tar.gz"),
			},
			want: []place{{idA, "uploads/src", true}, {idB, "uploads/package-lock.json", false}},
		},
		{
			name: "two same-named files keep their basename in distinct places",
			uploads: []projectsource.Upload{
				up(idA, "manifest", "package.json"),
				up(idB, "manifest", "package.json"),
			},
			want: []place{
				{idA, "uploads/package.json", false},
				{idB, "uploads/00000000000b/package.json", false},
			},
		},
		{
			name: "two same-named archives get id-suffixed directories",
			uploads: []projectsource.Upload{
				up(idA, "source_archive", "src.zip"),
				up(idB, "source_archive", "src.zip"),
			},
			want: []place{{idA, "uploads/src", true}, {idB, "uploads/src-00000000000b", true}},
		},
		{
			name: "a file named like an archive's directory is not merged into it",
			uploads: []projectsource.Upload{
				up(idA, "source_archive", "src.zip"),
				up(idB, "lockfile", "src"),
			},
			want: []place{{idA, "uploads/src", true}, {idB, "uploads/00000000000b/src", false}},
		},
		{
			name: "names differing only in case collide, as on a case-insensitive filesystem",
			uploads: []projectsource.Upload{
				up(idA, "manifest", "Package.json"),
				up(idB, "manifest", "package.json"),
			},
			want: []place{
				{idA, "uploads/Package.json", false},
				{idB, "uploads/00000000000b/package.json", false},
			},
		},
		{
			name: "hostile filenames become one safe segment each",
			uploads: []projectsource.Upload{
				up(idA, "lockfile", "../../etc/passwd"),
				up(idB, "manifest", ".."),
				up(idC, "sbom", `..\..\bom.json`),
			},
			want: []place{
				{idA, "uploads/passwd", false},
				{idB, "uploads/upload", false},
				{idC, "uploads/bom.json", false},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := planUploadLayout(tc.uploads)
			if len(got) != len(tc.want) {
				t.Fatalf("got %d placements, want %d — an upload was dropped or duplicated", len(got), len(tc.want))
			}
			for i, w := range tc.want {
				g := got[i]
				if g.upload.UploadID != w.id || g.rel != w.rel || g.extract != w.extract {
					t.Errorf("placement %d = {%s %q extract=%v}, want {%s %q extract=%v}",
						i, g.upload.UploadID, g.rel, g.extract, w.id, w.rel, w.extract)
				}
			}

			// ⚠ THE ORDER THE PROJECT SERVICE SENDS MUST NOT MATTER. Reversed
			// input, identical placements — otherwise the same uploads could
			// produce two different archives.
			reversed := make([]projectsource.Upload, len(tc.uploads))
			for i, u := range tc.uploads {
				reversed[len(tc.uploads)-1-i] = u
			}
			again := planUploadLayout(reversed)
			for i := range got {
				if again[i].upload.UploadID != got[i].upload.UploadID || again[i].rel != got[i].rel {
					t.Fatalf("placement depends on input order: %+v vs %+v", again[i], got[i])
				}
			}
		})
	}
}

func TestUploadEntryName(t *testing.T) {
	cases := []struct{ in, want string }{
		{"package-lock.json", "package-lock.json"},
		{"../../etc/passwd", "passwd"},
		{`..\..\win.ini`, "win.ini"},
		{"..", "fallback"},
		{"", "fallback"},
		{".env", "env"},
		{"-rf", "rf"},
		{"--x--", "x--"},
		{"a b$c.txt", "a_b_c.txt"},
		{"naïve.txt", "na_ve.txt"},
		{"trailing.", "trailing"},
		{"CON", "_CON"},
		{"nul.txt", "_nul.txt"},
		{strings.Repeat("a", 300), strings.Repeat("a", maxUploadNameBytes)},
	}
	for _, tc := range cases {
		if got := uploadEntryName(tc.in, "fallback"); got != tc.want {
			t.Errorf("uploadEntryName(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestArchiveStem(t *testing.T) {
	cases := []struct{ in, want string }{
		{"src.zip", "src"},
		{"app.tar.gz", "app"},
		{"x.TGZ", "x"},
		{"a.b.tar", "a.b"},
		{"release.tar.zst", "release"},
		{"zip", "zip"},
		{"notes.txt", "notes.txt"},
	}
	for _, tc := range cases {
		if got := archiveStem(tc.in); got != tc.want {
			t.Errorf("archiveStem(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
