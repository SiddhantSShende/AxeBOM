package toolctl

import (
	"errors"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func realManifest(t *testing.T) *Manifest {
	t.Helper()
	m, err := Load(filepath.Join("..", "..", "..", "OSINT", "tools.manifest.yaml"))
	if err != nil {
		t.Fatalf("load manifest: %v", err)
	}
	return m
}

// ---------------------------------------------------------------------------
// The manifest must describe reality
// ---------------------------------------------------------------------------

// Phase 0 wrote every version as a placeholder and every one of them was
// stale by many releases. This asserts the manifest has actually been resolved.
func TestManifestIsResolvedAgainstNetwork(t *testing.T) {
	m := realManifest(t)
	if !m.Meta.ResolvedAgainstNetwork {
		t.Error("manifest.resolved_against_network is false — versions are guesses. " +
			"Run `axebom toolctl dryrun` and pin real values.")
	}
	for _, tool := range m.Tools {
		if strings.Contains(tool.Version, "TBD") {
			t.Errorf("%s: version is still a TBD placeholder", tool.ID)
		}
	}
}

// A tool that declares itself container-only must actually have a container,
// or it silently resolves to `unavailable` and its coverage vanishes.
func TestContainerOnlyToolsHaveImages(t *testing.T) {
	for _, tool := range realManifest(t).Tools {
		if !tool.ContainerOnly || !tool.IsEnabled() {
			continue
		}
		if tool.Container == nil || tool.Container.Image == "" {
			t.Errorf("%s is container_only but declares no image", tool.ID)
		}
		if strings.TrimSpace(tool.ContainerOnlyReason) == "" {
			t.Errorf("%s is container_only without a stated reason", tool.ID)
		}
	}
}

// An unverifiable artifact must be DECLARED, not discovered at install time.
func TestSupplyChainGapsAreDeclared(t *testing.T) {
	m := realManifest(t)
	for _, tool := range m.Tools {
		if tool.Binary == nil || !tool.IsEnabled() {
			continue
		}
		v := tool.EffectiveVerify(m.Defaults)
		if tool.Binary.ChecksumFile == "" && v.Checksum == "required" {
			t.Errorf("%s: checksum is `required` but no checksum_file is declared — "+
				"sync would always fail", tool.ID)
		}
		if tool.Binary.ChecksumFile == "" && !tool.HasSupplyChainGap() {
			t.Errorf("%s: no checksum file and no supply_chain_gap declared. "+
				"An unverifiable artifact must be visible, not silent.", tool.ID)
		}
	}
}

// CLAUDE.md invariant 9. django-bom is GPL-3.0 and would have relicensed
// hbom-worker; this is the mechanical guard against re-adding that class of
// dependency.
func TestNoCopyleftLinkedIntoBinaries(t *testing.T) {
	m := realManifest(t)
	for _, p := range m.LicenseProblems() {
		t.Errorf("%s", p)
	}
	// And the known-bad ones must still be recorded as rejected, so the
	// decision survives someone wondering why they are absent.
	rejected := map[string]bool{}
	for _, r := range m.Rejected {
		rejected[r.ID] = true
	}
	for _, id := range []string{"django-bom", "indabom"} {
		if !rejected[id] {
			t.Errorf("%s should be recorded in `rejected:` with its reason", id)
		}
	}
}

// ---------------------------------------------------------------------------
// URL template expansion
// ---------------------------------------------------------------------------

func TestExpandSyftTemplate(t *testing.T) {
	tool := Tool{
		ID:      "syft",
		Version: "1.51.0",
		Binary: &Binary{
			URLTemplate: "https://github.com/anchore/syft/releases/download/v{version}/syft_{version}_{os}_{arch}.{ext}",
			Ext:         map[string]string{"linux": "tar.gz", "darwin": "tar.gz", "windows": "zip"},
		},
	}
	got := expand(tool.Binary.URLTemplate, tool)

	// Platform-dependent, so assert the invariant parts.
	for _, want := range []string{"/v1.51.0/", "syft_1.51.0_", hostOS(), hostArch()} {
		if !strings.Contains(got, want) {
			t.Errorf("expanded URL %q missing %q", got, want)
		}
	}
	if strings.Contains(got, "{") {
		t.Errorf("unexpanded placeholder remains: %s", got)
	}
	if runtime.GOOS == "windows" && !strings.HasSuffix(got, ".zip") {
		t.Errorf("windows should get .zip, got %s", got)
	}
}

// Trivy's asset naming is inconsistent WITHIN the project: Linux-64bit and
// macOS-64bit are capitalised, windows-64bit is not. Getting this wrong yields
// a 404 that looks like a wrong version.
func TestExpandTrivyTemplateCapitalization(t *testing.T) {
	tool := Tool{
		ID:      "trivy-fs",
		Version: "0.74.0",
		Binary: &Binary{
			URLTemplate: "https://github.com/aquasecurity/trivy/releases/download/v{version}/trivy_{version}_{os_trivy}.{ext}",
			OSTrivy:     map[string]string{"linux": "Linux-64bit", "darwin": "macOS-64bit", "windows": "windows-64bit"},
			Ext:         map[string]string{"linux": "tar.gz", "darwin": "tar.gz", "windows": "zip"},
		},
	}
	got := expand(tool.Binary.URLTemplate, tool)

	want := map[string]string{
		"linux": "Linux-64bit", "darwin": "macOS-64bit", "windows": "windows-64bit",
	}[hostOS()]
	if !strings.Contains(got, want) {
		t.Errorf("expected %q in %q", want, got)
	}
	if strings.Contains(got, "{") {
		t.Errorf("unexpanded placeholder: %s", got)
	}
}

// osv-scanner ships bare binaries: ".exe" on Windows, no suffix elsewhere.
func TestExpandBareBinaryExeSuffix(t *testing.T) {
	tool := Tool{
		ID:      "osv-scanner",
		Version: "2.5.0",
		Binary: &Binary{
			URLTemplate: "https://github.com/google/osv-scanner/releases/download/v{version}/osv-scanner_{os}_{arch}{exe}",
			Exe:         map[string]string{"linux": "", "darwin": "", "windows": ".exe"},
		},
	}
	got := expand(tool.Binary.URLTemplate, tool)

	if runtime.GOOS == "windows" && !strings.HasSuffix(got, ".exe") {
		t.Errorf("windows should get .exe: %s", got)
	}
	if runtime.GOOS != "windows" && strings.HasSuffix(got, ".exe") {
		t.Errorf("non-windows should not get .exe: %s", got)
	}
	if strings.Contains(got, "{") {
		t.Errorf("unexpanded placeholder: %s", got)
	}
}

func TestExpandSignatureReferencesChecksumFile(t *testing.T) {
	tool := Tool{
		Version: "1.51.0",
		Binary: &Binary{
			URLTemplate:  "https://x/{version}/bin",
			ChecksumFile: "https://x/{version}/checksums.txt",
			Signature: &Signature{
				Kind: "cosign-keyless",
				Sig:  "{checksum_file}.sig",
				Cert: "{checksum_file}.pem",
			},
		},
	}
	r := Resolve(tool, Defaults{ModePreference: []string{"binary"}})

	if r.ChecksumURL != "https://x/1.51.0/checksums.txt" {
		t.Fatalf("checksum URL = %q", r.ChecksumURL)
	}
	if r.SignatureURL != r.ChecksumURL+".sig" {
		t.Errorf("signature URL = %q, want %s.sig", r.SignatureURL, r.ChecksumURL)
	}
	if r.CertURL != r.ChecksumURL+".pem" {
		t.Errorf("cert URL = %q", r.CertURL)
	}
}

// ---------------------------------------------------------------------------
// Resolution
// ---------------------------------------------------------------------------

func TestResolvePrefersContainer(t *testing.T) {
	tool := Tool{
		ID: "x", Version: "1.0",
		Container: &Container{Image: "ghcr.io/x/x", ImageTag: "v1.0"},
		Binary:    &Binary{URLTemplate: "https://x/{version}/bin"},
	}
	r := Resolve(tool, Defaults{ModePreference: []string{"container", "binary"}})
	if r.Mode != ModeContainer {
		t.Fatalf("mode = %s, want container", r.Mode)
	}
	if r.ImageRef != "ghcr.io/x/x:v1.0" {
		t.Errorf("image ref = %q", r.ImageRef)
	}
}

// A tag is mutable and can be repointed after pinning. Trivy's channel was
// compromised twice in March 2026, so an unpinned image must warn.
func TestTagPinnedImageWarns(t *testing.T) {
	tagged := Resolve(Tool{ID: "x", Container: &Container{Image: "i", ImageTag: "v1"}},
		Defaults{ModePreference: []string{"container"}})
	if tagged.PinnedByDigest {
		t.Error("tag-only image reported as digest-pinned")
	}
	if len(tagged.Warnings) == 0 {
		t.Error("tag-pinned image must warn")
	}

	digested := Resolve(Tool{ID: "x", Container: &Container{
		Image: "i", ImageTag: "v1", ImageDigest: "sha256:abc"}},
		Defaults{ModePreference: []string{"container"}})
	if !digested.PinnedByDigest {
		t.Error("digest-pinned image not recognised")
	}
	if digested.ImageRef != "i@sha256:abc" {
		t.Errorf("digest ref = %q, want i@sha256:abc", digested.ImageRef)
	}
	if len(digested.Warnings) != 0 {
		t.Errorf("digest-pinned image should not warn: %v", digested.Warnings)
	}
}

// Container-only must hold even when binary mode is forced: there is genuinely
// no binary to fetch, and falling through would produce a 404 that looks like
// a wrong version rather than a category error.
func TestContainerOnlyIgnoresForcedBinaryMode(t *testing.T) {
	tool := Tool{
		ID: "dependency-check", Version: "13.0.0",
		Container:           &Container{Image: "owasp/dependency-check", ImageTag: "13.0.0"},
		ContainerOnly:       true,
		ContainerOnlyReason: "Java 11+ required",
	}
	r := ResolveWithPreference(tool, Defaults{}, []string{"binary"})
	if r.Mode != ModeContainer {
		t.Errorf("mode = %s, want container even under --force-mode binary", r.Mode)
	}
}

// A disabled engine is unavailable WITH ITS REASON — that reason is what the
// report's Engine Coverage section shows the customer.
func TestDisabledToolCarriesReason(t *testing.T) {
	no := false
	r := Resolve(Tool{
		ID:             "sonar-cryptography",
		Enabled:        &no,
		DeferredReason: "SonarQube plugin, not a CLI",
	}, Defaults{})

	if r.Mode != ModeUnavailable {
		t.Fatalf("mode = %s, want unavailable", r.Mode)
	}
	if !strings.Contains(r.Reason, "SonarQube") {
		t.Errorf("reason should explain why: %q", r.Reason)
	}
}

func TestSupplyChainGapSurfacesAsWarning(t *testing.T) {
	r := Resolve(Tool{
		ID: "osv-scanner", Version: "2.5.0",
		Binary:         &Binary{URLTemplate: "https://x/{version}/bin"},
		SupplyChainGap: "publishes no checksum file and no signatures",
	}, Defaults{ModePreference: []string{"binary"}})

	if len(r.Warnings) == 0 {
		t.Fatal("a declared supply-chain gap must surface as a warning")
	}
	if !strings.Contains(strings.Join(r.Warnings, " "), "no checksum") {
		t.Errorf("warning should carry the declared reason: %v", r.Warnings)
	}
}

func TestInternalEnginesNeedNoArtifact(t *testing.T) {
	r := Resolve(Tool{ID: "hbom-csv", Upstream: "internal"}, Defaults{})
	if r.Mode != ModeInternal {
		t.Errorf("mode = %s, want internal", r.Mode)
	}
}

// ---------------------------------------------------------------------------
// Checksum verification
// ---------------------------------------------------------------------------

func TestVerifyChecksumMatch(t *testing.T) {
	published := map[string]string{"syft_1.51.0_linux_amd64.tar.gz": "abc123"}
	if err := VerifyChecksum(
		"https://x/syft_1.51.0_linux_amd64.tar.gz", "ABC123", published); err != nil {
		t.Errorf("case-insensitive match should succeed: %v", err)
	}
}

// A mismatch must REFUSE the install, and say why in terms an operator can act
// on — an unverified scanner is worse than a missing one, because it produces
// authoritative-looking output.
func TestVerifyChecksumMismatchRefuses(t *testing.T) {
	published := map[string]string{"bin.tar.gz": "expected000"}
	err := VerifyChecksum("https://x/bin.tar.gz", "actual999", published)
	if err == nil {
		t.Fatal("mismatch must fail")
	}
	var mm *ErrChecksumMismatch
	if !errors.As(err, &mm) {
		t.Fatalf("want *ErrChecksumMismatch, got %T", err)
	}
	msg := err.Error()
	for _, want := range []string{"expected000", "actual999", "Refusing to install"} {
		if !strings.Contains(msg, want) {
			t.Errorf("message missing %q:\n%s", want, msg)
		}
	}
}

func TestVerifyChecksumMissingEntry(t *testing.T) {
	err := VerifyChecksum("https://x/unlisted.tar.gz", "abc", map[string]string{"other": "def"})
	if err == nil {
		t.Fatal("an asset absent from the checksum file must fail")
	}
	if !strings.Contains(err.Error(), "naming may have changed") {
		t.Errorf("message should hint at upstream renaming: %v", err)
	}
}
