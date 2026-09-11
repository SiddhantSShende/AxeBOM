package projectsource

// Upload is one stored file of an upload-sourced project.
type Upload struct {
	UploadID         string `json:"upload_id"`
	UploadKind       string `json:"upload_kind"`
	StorageRef       string `json:"storage_ref"`
	OriginalFilename string `json:"original_filename,omitempty"`
}

// UploadList is every upload this source carries, in the order the project
// service sent them.
//
// ⚠ READ THIS, NEVER THE TOP-LEVEL UPLOAD FIELDS. Those describe the newest
// upload only; reading them is exactly how every upload but the last was
// ignored. A project service that predates `uploads` sends only the top-level
// fields — its newest upload, the most it ever sent — so that answer still
// reads as a list of one.
func (s Source) UploadList() []Upload {
	if len(s.Uploads) > 0 {
		return s.Uploads
	}
	if s.StorageRef == "" {
		return nil
	}
	return []Upload{{
		UploadID:         s.UploadID,
		UploadKind:       s.UploadKind,
		StorageRef:       s.StorageRef,
		OriginalFilename: s.OriginalFilename,
	}}
}
