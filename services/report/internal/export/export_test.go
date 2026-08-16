package export

import (
	"encoding/json"
	"strings"
	"testing"
)

// fixture is a small BOM exercising the mappings that are easy to get wrong:
// a scoped npm package, a Maven artifact with mixed case, declared and
// concluded licences that DISAGREE, hashes, a CPE, and the CERT-In identifier.
func fixture() Document {
	return Document{
		GeneratedAt: "2026-08-17T00:00:00Z",
		DocumentID:  "urn:encorebom:scan:fixture",
		ProjectName: "fixture-project",
		ToolName:    "EncoreBOM",
		ToolVersion: "0.1.0",
		Roots:       []string{"purl:pkg:npm/fixture-project@1.0.0"},
		Components: []Component{
			{
				Key:              "purl:pkg:npm/fixture-project@1.0.0",
				Name:             "fixture-project",
				VersionRaw:       "1.0.0",
				Purl:             "pkg:npm/fixture-project@1.0.0",
				Ecosystem:        "npm",
				LicenseDeclared:  "MIT",
				CertInIdentifier: "pkg:supplier/Example/FixtureProject@1.0.0",
			},
			{
				Key:        "purl:pkg:npm/lodash@4.17.21",
				Name:       "lodash",
				VersionRaw: "4.17.21",
				Purl:       "pkg:npm/lodash@4.17.21",
				Ecosystem:  "npm",
				// ⚠ These DISAGREE on purpose. The manifest says MIT; reading
				// the LICENSE file concluded Apache-2.0. That discrepancy is a
				// finding a reviewer wants, not a conflict to resolve.
				LicenseDeclared:  "MIT",
				LicenseConcluded: "Apache-2.0",
				Supplier:         "Example Corp",
				Hashes: []Hash{
					{Algorithm: "SHA-256", Value: strings.Repeat("a", 64)},
					{Algorithm: "SHA-1", Value: strings.Repeat("b", 40)},
				},
				CPEs:      []string{"cpe:2.3:a:lodash:lodash:4.17.21:*:*:*:*:*:*:*"},
				Locations: []string{"package-lock.json"},
			},
			{
				Key:        "purl:pkg:maven/org.apache.commons/commons-lang3@3.12.0",
				Name:       "commons-lang3",
				VersionRaw: "3.12.0",
				Purl:       "pkg:maven/org.apache.commons/commons-lang3@3.12.0",
				Ecosystem:  "maven",
			},
		},
		Dependencies: []Dependency{
			{From: "purl:pkg:npm/fixture-project@1.0.0", To: "purl:pkg:npm/lodash@4.17.21"},
			{
				From: "purl:pkg:npm/fixture-project@1.0.0",
				To:   "purl:pkg:maven/org.apache.commons/commons-lang3@3.12.0",
			},
		},
	}
}

func TestBothFormatsSerialize(t *testing.T) {
	for _, format := range []Format{SPDX23JSON, CycloneDX16JSON} {
		t.Run(string(format), func(t *testing.T) {
			data, err := Serialize(fixture(), format)
			if err != nil {
				t.Fatalf("serialize: %v", err)
			}
			if len(data) == 0 {
				t.Fatal("empty document")
			}

			var doc map[string]any
			if err := json.Unmarshal(data, &doc); err != nil {
				t.Fatalf("output is not valid JSON: %v", err)
			}
		})
	}
}

// TestSerializationIsDeterministic is the property the golden files rest on.
//
// ⚠ Two runs over the same canonical model must produce identical bytes. A
// serializer that emits maps in random order makes every golden diff flap, and
// flapping tests get ignored — worse than not having them.
func TestSerializationIsDeterministic(t *testing.T) {
	for _, format := range []Format{SPDX23JSON, CycloneDX16JSON} {
		t.Run(string(format), func(t *testing.T) {
			first, err := Serialize(fixture(), format)
			if err != nil {
				t.Fatal(err)
			}
			second, err := Serialize(fixture(), format)
			if err != nil {
				t.Fatal(err)
			}
			if string(first) != string(second) {
				t.Error("two runs produced different bytes")
			}
		})
	}
}

// TestComponentOrderDoesNotAffectOutput — the canonical model's component order
// is an implementation detail; the document must not depend on it.
func TestComponentOrderDoesNotAffectOutput(t *testing.T) {
	forward := fixture()
	reversed := fixture()
	for i, j := 0, len(reversed.Components)-1; i < j; i, j = i+1, j-1 {
		reversed.Components[i], reversed.Components[j] =
			reversed.Components[j], reversed.Components[i]
	}

	a, err := Serialize(forward, CycloneDX16JSON)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Serialize(reversed, CycloneDX16JSON)
	if err != nil {
		t.Fatal(err)
	}
	if string(a) != string(b) {
		t.Error("output depends on the order components were supplied in")
	}
}

// TestSpdxKeepsDeclaredAndConcludedApart is the mapping decision most likely to
// be quietly wrong.
//
// ⚠ SPDX has distinct fields for a reason: "the manifest says MIT but the
// LICENSE file is Apache-2.0" is a finding. Writing the concluded value into
// both fields asserts they agreed.
func TestSpdxKeepsDeclaredAndConcludedApart(t *testing.T) {
	data, err := Serialize(fixture(), SPDX23JSON)
	if err != nil {
		t.Fatal(err)
	}

	var doc struct {
		Packages []struct {
			Name             string `json:"name"`
			LicenseDeclared  string `json:"licenseDeclared"`
			LicenseConcluded string `json:"licenseConcluded"`
		} `json:"packages"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}

	found := false
	for _, p := range doc.Packages {
		if p.Name != "lodash" {
			continue
		}
		found = true
		if p.LicenseDeclared != "MIT" {
			t.Errorf("declared licence was not preserved: %q", p.LicenseDeclared)
		}
		if p.LicenseConcluded != "Apache-2.0" {
			t.Errorf("concluded licence was not preserved: %q", p.LicenseConcluded)
		}
		if p.LicenseDeclared == p.LicenseConcluded {
			t.Error("declared and concluded were collapsed into one value")
		}
	}
	if !found {
		t.Fatal("lodash is missing from the SPDX document")
	}
}

// TestTheCertInIdentifierIsNotAPurl guards a mapping mistake that would break
// every downstream consumer.
//
// ⚠ `pkg:supplier/Org/Name@1.0` is CERT-In's own form. It is not a resolvable
// PURL, no tool will resolve it, and putting it where a PURL belongs would make
// consumers dedup on it or fail to fetch it.
func TestTheCertInIdentifierIsNotAPurl(t *testing.T) {
	data, err := Serialize(fixture(), CycloneDX16JSON)
	if err != nil {
		t.Fatal(err)
	}

	var doc struct {
		Components []struct {
			Name string `json:"name"`
			Purl string `json:"purl"`
		} `json:"components"`
		Metadata struct {
			Component struct {
				Purl string `json:"purl"`
			} `json:"component"`
		} `json:"metadata"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}

	for _, c := range doc.Components {
		if strings.HasPrefix(c.Purl, "pkg:supplier/") {
			t.Errorf("%s: the CERT-In identifier was emitted as a PURL: %q", c.Name, c.Purl)
		}
	}
	// …but it must still be present somewhere in the document.
	if !strings.Contains(string(data), "pkg:supplier/Example/FixtureProject@1.0.0") {
		t.Error("the CERT-In identifier is missing from the document entirely")
	}
}

func TestEcosystemPurlsSurviveVerbatim(t *testing.T) {
	data, err := Serialize(fixture(), CycloneDX16JSON)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"pkg:npm/lodash@4.17.21",
		"pkg:maven/org.apache.commons/commons-lang3@3.12.0",
	} {
		if !strings.Contains(string(data), want) {
			t.Errorf("PURL missing from the document: %s", want)
		}
	}
}

// TestUnknownHashAlgorithmsAreDroppedNotGuessed — a digest under the wrong
// label is worse than no digest, because a verifier reports a mismatch on a
// file that is fine.
func TestUnknownHashAlgorithmsAreDroppedNotGuessed(t *testing.T) {
	if _, ok := hashAlgorithm("blake3"); ok {
		t.Error("an unknown algorithm was mapped to something")
	}
	for _, known := range []string{"SHA-256", "sha256", "SHA1", "md5"} {
		if _, ok := hashAlgorithm(known); !ok {
			t.Errorf("known algorithm %q was not mapped", known)
		}
	}
}

func TestRootsAreDeclaredExplicitly(t *testing.T) {
	doc := fixture()
	bom, err := toProtobom(doc)
	if err != nil {
		t.Fatal(err)
	}
	if len(bom.NodeList.RootElements) != 1 {
		t.Fatalf("expected 1 declared root, got %d", len(bom.NodeList.RootElements))
	}
}

// TestAMonorepoKeepsAllItsRoots — one root per repository would make every
// workspace package look like a dependency of one imaginary parent.
func TestAMonorepoKeepsAllItsRoots(t *testing.T) {
	doc := fixture()
	doc.Roots = []string{
		"purl:pkg:npm/api@1.0.0",
		"purl:pkg:pypi/worker@1.0.0",
		"purl:pkg:golang/shared@v1.0.0",
	}
	bom, err := toProtobom(doc)
	if err != nil {
		t.Fatal(err)
	}
	if len(bom.NodeList.RootElements) != 3 {
		t.Errorf("a monorepo lost roots: %v", bom.NodeList.RootElements)
	}
}

func TestAnUnsupportedFormatIsRefused(t *testing.T) {
	if _, err := Serialize(fixture(), Format("spdx-1.0-tag-value")); err == nil {
		t.Error("an unsupported format was accepted")
	}
}

func TestAComponentWithNoKeyIsRefused(t *testing.T) {
	doc := fixture()
	doc.Components = append(doc.Components, Component{Name: "keyless"})
	if _, err := Serialize(doc, CycloneDX16JSON); err == nil {
		t.Error("a component with no key was serialized")
	}
}

// TestGeneratedAtComesFromTheRecord — a clock read here would make the same
// canonical model serialize differently on every run, breaking replay.
func TestGeneratedAtComesFromTheRecord(t *testing.T) {
	doc := fixture()
	doc.GeneratedAt = "2020-01-02T03:04:05Z"

	data, err := Serialize(doc, SPDX23JSON)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "2020-01-02") {
		t.Error("the supplied timestamp did not reach the document")
	}
}

func TestMediaTypesAreCorrect(t *testing.T) {
	if got := SPDX23JSON.MediaType(); got != "application/spdx+json" {
		t.Errorf("SPDX media type: %s", got)
	}
	if got := CycloneDX16JSON.MediaType(); !strings.Contains(got, "cyclonedx") {
		t.Errorf("CycloneDX media type: %s", got)
	}
}

// TestDeterminismHoldsAcrossManyRuns — map-iteration order is random per run,
// so two comparisons can agree by luck. protobom shuffled `components` between
// runs and a two-run check caught it only intermittently.
func TestDeterminismHoldsAcrossManyRuns(t *testing.T) {
	for _, format := range []Format{SPDX23JSON, CycloneDX16JSON} {
		t.Run(string(format), func(t *testing.T) {
			want, err := Serialize(fixture(), format)
			if err != nil {
				t.Fatal(err)
			}
			for i := 0; i < 40; i++ {
				got, err := Serialize(fixture(), format)
				if err != nil {
					t.Fatal(err)
				}
				if string(got) != string(want) {
					t.Fatalf("run %d differed from the first", i)
				}
			}
		})
	}
}

// TestTheSpdxTimestampIsTheScansNotTheRenders.
//
// ⚠ protobom stamps `creationInfo.created` with time.Now(). Left alone, a
// re-render of a 2024 scan produces a document claiming to describe today —
// and a signature over it never verifies twice.
func TestTheSpdxTimestampIsTheScansNotTheRenders(t *testing.T) {
	doc := fixture()
	doc.GeneratedAt = "2020-01-02T03:04:05Z"

	data, err := Serialize(doc, SPDX23JSON)
	if err != nil {
		t.Fatal(err)
	}

	var out struct {
		CreationInfo struct {
			Created string `json:"created"`
		} `json:"creationInfo"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatal(err)
	}
	if out.CreationInfo.Created != "2020-01-02T03:04:05Z" {
		t.Errorf("created is %q, not the scan's time — protobom's clock read won",
			out.CreationInfo.Created)
	}
}

// TestSortingDoesNotLoseAnything — stabilizing must reorder, never drop.
func TestSortingDoesNotLoseAnything(t *testing.T) {
	data, err := Serialize(fixture(), CycloneDX16JSON)
	if err != nil {
		t.Fatal(err)
	}
	var out struct {
		Components []struct {
			Name string `json:"name"`
		} `json:"components"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatal(err)
	}

	names := map[string]bool{}
	for _, c := range out.Components {
		names[c.Name] = true
	}
	for _, want := range []string{"lodash", "commons-lang3"} {
		if !names[want] {
			t.Errorf("%s was lost during stabilization", want)
		}
	}
}
