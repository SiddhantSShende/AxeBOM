package compliance

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func profilePath(t *testing.T) string {
	t.Helper()
	return filepath.Join("..", "..", "..", "docs", "reference", "certin-v2.0.yaml")
}

func loadProfile(t *testing.T) *Profile {
	t.Helper()
	p, err := Load(profilePath(t))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	return p
}

// The real profile must lint clean. If this fails, `task verify` is lying.
func TestRealProfileLintsClean(t *testing.T) {
	res := Lint(loadProfile(t))
	for _, p := range res.Problems {
		t.Errorf("%s", p)
	}
	t.Logf("%d fields, %d count assertions matched, %d assumed",
		res.FieldCount, res.CountsOK, res.AssumedCount)
}

// The counts come from the source PDF, read directly. They are transcription
// assertions, so this test is really asking "does the profile still say what
// the guideline says".
func TestProfileCountsMatchSourceDocument(t *testing.T) {
	p := loadProfile(t)
	actual := p.ActualCounts()

	// Transcribed from CERT-In v2.0. Changing a number here means the
	// guideline was revised — which is a documentation change, not a test fix.
	fromPDF := map[string]int{
		"sbom_data_fields":                          21, // §4.2, p.22-24
		"sbom_minimum_element_categories":           3,  // Table 5, p.21 — NOT just the data fields
		"sbom_practices_and_processes_sub_elements": 6,  // Table 5, p.22
		"sbom_levels":                               5,  // §3.1, p.11
		"sbom_classifications":                      6,  // §3.2, p.12-13
		"qbom_elements":                             11, // Table 8, p.44-45
		"crypto_asset_types":                        4,  // Table 9 — type-discriminated
		"crypto_algorithms_fields":                  8,
		"crypto_keys_fields":                        7,
		"crypto_protocols_fields":                   5,
		"crypto_certificates_fields":                10,
		"aibom_elements":                            19, // Table 10, p.54-55
		"hbom_table11_elements":                     20, // Table 11, p.60-61
		"hbom_additional_required_elements":         4,  // §10.4.1.4, p.62 — absent from Table 11
		"vex_statuses":                              4,  // §6, p.35
	}

	for key, want := range fromPDF {
		if got := actual[key]; got != want {
			t.Errorf("%s: profile has %d, source document has %d", key, got, want)
		}
	}
}

// The four crypto asset types must have DIFFERENT field sets. If they were the
// same, type-aware coverage scoring would be pointless — and a certificate
// would be graded against key_size.
func TestCryptoAssetTypesAreDistinct(t *testing.T) {
	p := loadProfile(t)

	sizes := map[string]int{}
	for _, at := range []string{"algorithm", "key", "protocol", "certificate"} {
		fields := p.FieldsForCryptoAssetType(at)
		if len(fields) == 0 {
			t.Fatalf("no fields for crypto asset type %q", at)
		}
		sizes[at] = len(fields)
	}
	t.Logf("field counts by asset type: %v", sizes)

	// A certificate must not be scored against a key's fields.
	certFields := map[string]bool{}
	for _, f := range p.FieldsForCryptoAssetType("certificate") {
		certFields[f.CanonicalPath] = true
	}
	if certFields["crypto_asset.key_size"] {
		t.Error("certificate field set includes key_size — scoring would be wrong")
	}

	keyFields := map[string]bool{}
	for _, f := range p.FieldsForCryptoAssetType("key") {
		keyFields[f.CanonicalPath] = true
	}
	if keyFields["crypto_asset.cert_issuer"] {
		t.Error("key field set includes cert_issuer — scoring would be wrong")
	}
}

// EncoreBOM extensions are our ANALYSIS, not the standard's requirements.
// Scoring them would let our own heuristics move a compliance percentage.
func TestExtensionsAreNotScored(t *testing.T) {
	p := loadProfile(t)
	for _, f := range p.AllFields() {
		if strings.HasPrefix(f.ID, "encorebom.") && f.IsScored() {
			t.Errorf("%s is an EncoreBOM extension but is scored; it would "+
				"inflate or deflate a compliance percentage", f.ID)
		}
	}
}

// ---------------------------------------------------------------------------
// Negative tests: lint must FAIL on a broken profile.
//
// A linter nobody has seen fail is a linter nobody trusts.
// ---------------------------------------------------------------------------

func mutateProfile(t *testing.T, replacements ...[2]string) *Profile {
	t.Helper()
	raw, err := os.ReadFile(profilePath(t))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	s := string(raw)
	for _, r := range replacements {
		if !strings.Contains(s, r[0]) {
			t.Fatalf("mutation target not found: %q", r[0])
		}
		s = strings.Replace(s, r[0], r[1], 1)
	}

	tmp := filepath.Join(t.TempDir(), "mutated.yaml")
	if err := os.WriteFile(tmp, []byte(s), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	p, err := Load(tmp)
	if err != nil {
		t.Fatalf("load mutated: %v", err)
	}
	return p
}

func assertLintFails(t *testing.T, p *Profile, wantCheck string) {
	t.Helper()
	res := Lint(p)
	if res.OK() {
		t.Fatalf("lint passed on a deliberately broken profile (expected a %q problem)", wantCheck)
	}
	for _, pr := range res.Problems {
		if pr.Check == wantCheck {
			t.Logf("correctly rejected: %s", pr)
			return
		}
	}
	t.Errorf("expected a %q problem, got: %v", wantCheck, res.Problems)
}

func TestLintRejectsWrongCount(t *testing.T) {
	// Claim 22 SBOM data fields when the profile contains 21.
	assertLintFails(t, mutateProfile(t,
		[2]string{"sbom_data_fields: 21", "sbom_data_fields: 22"}), "counts")
}

func TestLintRejectsDuplicateID(t *testing.T) {
	// Give field 2 the same id as field 1.
	assertLintFails(t, mutateProfile(t,
		[2]string{"id: certin.sbom.02.component_version", "id: certin.sbom.01.component_name"}),
		"unique-ids")
}

func TestLintRejectsMissingStatus(t *testing.T) {
	assertLintFails(t, mutateProfile(t,
		[2]string{
			"      source_page: 22\n      status: verified",
			"      source_page: 22",
		}), "status")
}

func TestLintRejectsAssumedWithoutNote(t *testing.T) {
	p := mutateProfile(t, [2]string{
		"      source_page: 22\n      status: verified",
		"      source_page: 22\n      status: assumed",
	})
	assertLintFails(t, p, "status")
}

func TestLintRejectsSourcePageBeyondDocument(t *testing.T) {
	// The source document has 66 pages.
	assertLintFails(t, mutateProfile(t,
		[2]string{"source_page: 22\n      status: verified", "source_page: 999\n      status: verified"}),
		"source-page")
}

func TestLintRejectsInconsistentAllVerified(t *testing.T) {
	// Claim everything is verified while marking an entry assumed.
	p := mutateProfile(t,
		[2]string{
			"      source_page: 22\n      status: verified",
			"      source_page: 22\n      status: assumed\n      note: deliberately inconsistent",
		})
	assertLintFails(t, p, "meta")
}

func TestLintRejectsUnknownCanonicalEntity(t *testing.T) {
	assertLintFails(t, mutateProfile(t,
		[2]string{"canonical_path: component.name", "canonical_path: widget.name"}),
		"canonical-path")
}
