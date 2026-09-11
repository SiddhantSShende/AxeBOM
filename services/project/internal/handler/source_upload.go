package handler

import "github.com/axebom/axebom/services/project/internal/store"

// uploadSourceBody is Source()'s answer for an upload-sourced project.
//
// ⚠ EVERY UPLOAD, NOT THE MOST RECENT ONE. This used to send `uploads[0]` alone
// under the "pick one, document it" convention the connection branch uses — but
// the registration wizard lets a user stage several files, so a project given a
// source archive and then a lockfile was scanned as the lockfile alone, and
// nothing anywhere said the archive had been ignored (CLAUDE.md invariant 12).
//
// `uploads` lists all of them, oldest first. The top-level upload_* fields still
// describe the NEWEST upload exactly as before, so a fetcher that predates the
// list keeps working unchanged. docs/02-CONTRACTS.md §3 is the contract.
//
// uploads must be non-empty and in ListUploads' newest-first order (id DESC;
// ids are UUIDv7, so that is upload order).
func uploadSourceBody(uploads []store.Upload) map[string]any {
	newest := uploads[0]

	list := make([]map[string]any, 0, len(uploads))
	for i := len(uploads) - 1; i >= 0; i-- {
		u := uploads[i]
		list = append(list, map[string]any{
			"upload_id":         u.ID,
			"upload_kind":       u.Kind,
			"storage_ref":       u.StorageRef,
			"original_filename": u.OriginalFilename,
		})
	}

	return map[string]any{
		"kind":              "upload",
		"upload_id":         newest.ID,
		"upload_kind":       newest.Kind,
		"storage_ref":       newest.StorageRef,
		"original_filename": newest.OriginalFilename,
		"uploads":           list,
	}
}
