package toolctl

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Artifact acquisition and verification.
//
// The rule that shapes everything here: a verification failure REFUSES to
// install. An unverified scanner is worse than a missing one, because the
// missing one is visible in Engine Coverage while the unverified one silently
// produces authoritative-looking output. Trivy's distribution channel was
// compromised twice in March 2026; this is not hypothetical.

// httpClient is shared and bounded. No redirects beyond a small limit: a
// release URL that redirects ten times is not a release URL.
var httpClient = &http.Client{
	Timeout: 5 * time.Minute,
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 5 {
			return fmt.Errorf("stopped after 5 redirects")
		}
		return nil
	},
}

// URLStatus is the outcome of probing one URL.
type URLStatus struct {
	URL    string
	Label  string // "binary" | "checksums" | "signature" | "certificate" | "bundle"
	Status int
	Size   int64
	Err    error
}

// OK reports whether the artifact is fetchable.
func (s URLStatus) OK() bool { return s.Err == nil && s.Status >= 200 && s.Status < 300 }

// Probe issues a HEAD request.
//
// GitHub release assets redirect to a CDN; some CDNs reject HEAD, so a 403/405
// falls back to a ranged GET that reads one byte. Reporting a live asset as
// missing because the CDN dislikes HEAD would make the dry run useless.
func Probe(ctx context.Context, url, label string) URLStatus {
	st := URLStatus{URL: url, Label: label}
	if url == "" {
		st.Err = fmt.Errorf("empty url")
		return st
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodHead, url, nil)
	if err != nil {
		st.Err = err
		return st
	}
	req.Header.Set("User-Agent", "encorebom-toolctl")

	resp, err := httpClient.Do(req)
	if err != nil {
		st.Err = err
		return st
	}
	_ = resp.Body.Close()
	st.Status = resp.StatusCode
	st.Size = resp.ContentLength

	if st.Status == http.StatusForbidden || st.Status == http.StatusMethodNotAllowed {
		return probeRanged(ctx, url, label)
	}
	return st
}

func probeRanged(ctx context.Context, url, label string) URLStatus {
	st := URLStatus{URL: url, Label: label}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		st.Err = err
		return st
	}
	req.Header.Set("User-Agent", "encorebom-toolctl")
	req.Header.Set("Range", "bytes=0-0")

	resp, err := httpClient.Do(req)
	if err != nil {
		st.Err = err
		return st
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1))

	st.Status = resp.StatusCode
	if st.Status == http.StatusPartialContent {
		st.Status = http.StatusOK // treat as present
	}
	return st
}

// ProbeResolution probes every URL a resolution depends on.
func ProbeResolution(ctx context.Context, r Resolution) []URLStatus {
	var out []URLStatus
	if r.URL != "" {
		out = append(out, Probe(ctx, r.URL, "binary"))
	}
	if r.ChecksumURL != "" {
		out = append(out, Probe(ctx, r.ChecksumURL, "checksums"))
	}
	if r.SignatureURL != "" {
		out = append(out, Probe(ctx, r.SignatureURL, "signature"))
	}
	if r.CertURL != "" {
		out = append(out, Probe(ctx, r.CertURL, "certificate"))
	}
	if r.BundleURL != "" {
		out = append(out, Probe(ctx, r.BundleURL, "bundle"))
	}
	return out
}

// ChecksumEntry is one line of a goreleaser-style checksums.txt:
//
//	<sha256>  <filename>
type ChecksumEntry struct {
	SHA256 string
	File   string
}

// FetchChecksums downloads and parses a checksum file.
func FetchChecksums(ctx context.Context, url string) (map[string]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "encorebom-toolctl")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch checksums: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch checksums: HTTP %d", resp.StatusCode)
	}

	// 4 MB is far beyond any real checksum file; the cap stops a hostile or
	// misconfigured endpoint from streaming indefinitely.
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, err
	}

	out := map[string]string{}
	for _, line := range strings.Split(string(body), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		// Some tools prefix the filename with '*' (binary mode).
		name := strings.TrimPrefix(fields[len(fields)-1], "*")
		out[name] = fields[0]
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("checksum file at %s parsed to zero entries", url)
	}
	return out, nil
}

// Download fetches a URL to dest, returning the sha256 of what was written.
//
// The hash is computed while streaming so the file is never read twice, and
// the download lands on a temporary path first: a partially-written artifact
// left at the final path would be indistinguishable from a good one on the
// next run.
func Download(ctx context.Context, url, dest string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "encorebom-toolctl")

	resp, err := httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("download %s: %w", url, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("download %s: HTTP %d", url, resp.StatusCode)
	}

	if err := os.MkdirAll(filepath.Dir(dest), 0o750); err != nil {
		return "", err
	}

	tmp := dest + ".partial"
	f, err := os.Create(tmp) // #nosec G304 -- path derived from the manifest
	if err != nil {
		return "", err
	}

	h := sha256.New()
	if _, err := io.Copy(io.MultiWriter(f, h), resp.Body); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return "", fmt.Errorf("write %s: %w", dest, err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return "", err
	}

	sum := hex.EncodeToString(h.Sum(nil))
	if err := os.Rename(tmp, dest); err != nil {
		_ = os.Remove(tmp)
		return "", err
	}
	return sum, nil
}

// ErrChecksumMismatch means a downloaded artifact does not match its published
// checksum. This ALWAYS refuses the install.
type ErrChecksumMismatch struct {
	URL      string
	Expected string
	Actual   string
}

func (e *ErrChecksumMismatch) Error() string {
	return fmt.Sprintf(
		"CHECKSUM MISMATCH for %s\n  expected %s\n  actual   %s\n"+
			"Refusing to install. This means the artifact is not what upstream "+
			"published — a corrupted download, a MITM, or a compromised "+
			"distribution channel (Trivy's was compromised twice in March 2026).",
		e.URL, e.Expected, e.Actual)
}

// VerifyChecksum compares an actual hash against the published set.
func VerifyChecksum(url, actual string, published map[string]string) error {
	name := filepath.Base(url)
	expected, ok := published[name]
	if !ok {
		return fmt.Errorf("no checksum published for %q in the checksum file; "+
			"the asset naming may have changed upstream", name)
	}
	if !strings.EqualFold(expected, actual) {
		return &ErrChecksumMismatch{URL: url, Expected: expected, Actual: actual}
	}
	return nil
}
