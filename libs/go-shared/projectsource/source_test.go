package projectsource

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestResolveReadsEveryUpload(t *testing.T) {
	cases := []struct {
		name     string
		body     string
		wantRefs []string
		wantErr  error
	}{
		{
			name: "every upload, in the order sent, beside the newest's legacy fields",
			body: `{"kind":"upload","upload_id":"b","upload_kind":"lockfile","storage_ref":"k/b",
				"original_filename":"package-lock.json","uploads":[
				{"upload_id":"a","upload_kind":"source_archive","storage_ref":"k/a","original_filename":"src.zip"},
				{"upload_id":"b","upload_kind":"lockfile","storage_ref":"k/b","original_filename":"package-lock.json"}]}`,
			wantRefs: []string{"k/a", "k/b"},
		},
		{
			name: "a project service that predates the list still reads as one upload",
			body: `{"kind":"upload","upload_id":"a","upload_kind":"source_archive",
				"storage_ref":"k/a","original_filename":"src.zip"}`,
			wantRefs: []string{"k/a"},
		},
		{
			name:     "the list alone is enough",
			body:     `{"kind":"upload","uploads":[{"upload_id":"a","upload_kind":"manifest","storage_ref":"k/a"}]}`,
			wantRefs: []string{"k/a"},
		},
		{
			name:    "an upload project with nothing stored has no source",
			body:    `{"kind":"upload"}`,
			wantErr: ErrNoSource,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = io.WriteString(w, tc.body)
			}))
			defer srv.Close()

			c, err := New(Options{
				BaseURL: srv.URL,
				Token:   func(context.Context) (string, error) { return "tok", nil },
			})
			if err != nil {
				t.Fatalf("new client: %v", err)
			}

			src, err := c.Resolve(t.Context(), "tenant", "project")
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("err = %v, want %v", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("resolve: %v", err)
			}

			var refs []string
			for _, u := range src.UploadList() {
				refs = append(refs, u.StorageRef)
			}
			if len(refs) != len(tc.wantRefs) {
				t.Fatalf("UploadList = %v, want %v", refs, tc.wantRefs)
			}
			for i := range refs {
				if refs[i] != tc.wantRefs[i] {
					t.Errorf("UploadList[%d] = %q, want %q", i, refs[i], tc.wantRefs[i])
				}
			}
		})
	}
}
