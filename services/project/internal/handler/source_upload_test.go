package handler

import (
	"testing"

	"github.com/axebom/axebom/services/project/internal/store"
)

func TestUploadSourceBodyListsEveryUploadOldestFirst(t *testing.T) {
	older := store.Upload{ID: "01a06660-0000-7000-8000-00000000000a", Kind: "source_archive",
		StorageRef: "uploads/t/p/source_archive/1-src.zip", OriginalFilename: "src.zip"}
	middle := store.Upload{ID: "01a06660-0000-7000-8000-00000000000b", Kind: "lockfile",
		StorageRef: "uploads/t/p/lockfile/2-package-lock.json", OriginalFilename: "package-lock.json"}
	newest := store.Upload{ID: "01a06660-0000-7000-8000-00000000000c", Kind: "manifest",
		StorageRef: "uploads/t/p/manifest/3-package.json", OriginalFilename: "package.json"}

	cases := []struct {
		name        string
		newestFirst []store.Upload // ListUploads' order
		wantIDs     []string       // `uploads`, oldest first
	}{
		{"one upload", []store.Upload{older}, []string{older.ID}},
		{"three uploads", []store.Upload{newest, middle, older}, []string{older.ID, middle.ID, newest.ID}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body := uploadSourceBody(tc.newestFirst)

			if body["kind"] != "upload" {
				t.Fatalf("kind = %v, want upload", body["kind"])
			}
			// The legacy top-level fields still describe the newest upload, so a
			// fetcher that predates `uploads` behaves exactly as it did.
			top := tc.newestFirst[0]
			if body["upload_id"] != top.ID || body["storage_ref"] != top.StorageRef ||
				body["upload_kind"] != top.Kind || body["original_filename"] != top.OriginalFilename {
				t.Fatalf("top-level fields are not the newest upload: %v", body)
			}

			list, ok := body["uploads"].([]map[string]any)
			if !ok {
				t.Fatalf("uploads has type %T, want []map[string]any", body["uploads"])
			}
			if len(list) != len(tc.wantIDs) {
				t.Fatalf("uploads has %d entries, want %d — an upload was dropped", len(list), len(tc.wantIDs))
			}
			for i, id := range tc.wantIDs {
				if list[i]["upload_id"] != id {
					t.Errorf("uploads[%d] = %v, want %s (oldest first)", i, list[i]["upload_id"], id)
				}
				if list[i]["storage_ref"] == "" {
					t.Errorf("uploads[%d] carries no storage_ref", i)
				}
			}
		})
	}
}
