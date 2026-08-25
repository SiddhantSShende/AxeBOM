package fetcher

import "testing"

// The orchestrator's default ArtifactPrefix is a URI ("s3://axebom"), and an
// object key is bucket-relative. Passing one through as the other produced
// "Object name contains unsupported characters" from MinIO — an error naming
// neither the key nor the colon — on a RETRYABLE code path, so the fetch job
// redelivered indefinitely and the scan never left `queued`.
func TestObjectKeyPrefixStripsSchemeAndSlashes(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "the real default, which is a URI",
			in:   "s3://axebom/scans/abc/raw/fetcher/job1/",
			want: "scans/abc/raw/fetcher/job1",
		},
		{
			name: "empty ArtifactPrefix leaves a leading slash",
			in:   "/scans/abc/raw/fetcher/job1/",
			want: "scans/abc/raw/fetcher/job1",
		},
		{name: "already a key", in: "scans/abc/raw", want: "scans/abc/raw"},
		{name: "other schemes too", in: "gs://bucket/a/b", want: "a/b"},
		{name: "bucket with no key", in: "s3://axebom", want: ""},
		{name: "empty", in: "", want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := objectKeyPrefix(tt.in); got != tt.want {
				t.Errorf("objectKeyPrefix(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

// A key must never carry a scheme or a leading slash, whatever it was built
// from. Asserted separately because the table above could be satisfied by a
// function that only handled the cases someone thought of.
func TestObjectKeyPrefixNeverYieldsAnInvalidKey(t *testing.T) {
	for _, in := range []string{
		"s3://b/x", "/x", "//x", "s3://b//x/", "x/", "/", "//",
	} {
		got := objectKeyPrefix(in)
		if len(got) > 0 && got[0] == '/' {
			t.Errorf("objectKeyPrefix(%q) = %q, which starts with a slash", in, got)
		}
		for i := range got {
			if got[i] == ':' {
				t.Errorf("objectKeyPrefix(%q) = %q, which still carries a scheme", in, got)
			}
		}
	}
}
