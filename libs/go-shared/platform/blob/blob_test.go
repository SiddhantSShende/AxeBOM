package blob

import "testing"

// TestTrimKeyScheme guards the exact regression this function exists to
// close: a job's Output.Prefix defaults to "s3://axebom/...", and a caller
// that forgets to strip the scheme hands MinIO a key it rejects deep inside
// the SDK with "Object name contains unsupported characters" — on a
// retryable path, so the job redelivers forever. See the doc comment.
func TestTrimKeyScheme(t *testing.T) {
	cases := []struct {
		name string
		key  string
		want string
	}{
		{"already relative", "scans/scan-1/raw/webrecon/job-1/webrecon.json",
			"scans/scan-1/raw/webrecon/job-1/webrecon.json"},
		{"s3 scheme with bucket", "s3://axebom/scans/scan-1/raw/webrecon/job-1/webrecon.json",
			"scans/scan-1/raw/webrecon/job-1/webrecon.json"},
		{"scheme and bucket only, no key", "s3://axebom", ""},
		{"scheme and bucket with trailing slash, no key", "s3://axebom/", ""},
		{"empty", "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := TrimKeyScheme(c.key); got != c.want {
				t.Errorf("TrimKeyScheme(%q) = %q, want %q", c.key, got, c.want)
			}
		})
	}
}
