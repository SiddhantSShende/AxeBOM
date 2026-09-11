package render

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/axebom/axebom/libs/go-shared/model"
)

// evidenceSample is cbomSample shaped like a migration-0020 row: the algorithm
// has an asset key, three evidence entries — two of them one line seen by two
// engines — and two engines.
func evidenceSample() BOM {
	b := cbomSample()
	line := 12
	b.CryptoAssets[0].AssetKey = "algorithm:rsa;size=2048"
	b.CryptoAssets[0].Evidence = []CryptoEvidence{
		{Path: "src/Main.java", Line: &line, Engine: "cbomkit-action"},
		{Path: "src/Main.java", Line: &line, Engine: "cdxgen-cbom"},
		{Path: "lib/crypto.js", Engine: "cdxgen-cbom"},
	}
	b.CryptoAssets[0].Engines = []string{"cbomkit-action", "cdxgen-cbom"}
	return b
}

// withCommittedKey flags evidenceSample's key as private key material read out
// of two committed files.
func withCommittedKey(b BOM) BOM {
	b.CryptoAssets[1].AssetKey = "key:fp:sha256:00ff"
	b.CryptoAssets[1].Attributes = map[string]any{"material_type": "private-key", "private_key_in_source": true}
	b.CryptoAssets[1].Evidence = []CryptoEvidence{
		{Path: "keys/server.key", Engine: "cbomkit-theia"},
		{Path: "deploy/old.pem", Engine: "cbomkit-theia"},
	}
	b.CryptoAssets[1].Engines = []string{"cbomkit-theia"}
	return b
}

// TestEachInventoryNamesWhereAndWhoSawIt — Location is the first evidence
// location and how many more; one line seen by two engines is one location.
func TestEachInventoryNamesWhereAndWhoSawIt(t *testing.T) {
	sheets := CBOMSheets(evidenceSample())
	algos := findSheet(t, sheets, "Crypto - Algorithms")
	row := rowsOf(t, algos)[0]
	for column, want := range map[string]string{
		"Location":  "lib/crypto.js (+1 more)",
		"Engines":   "cbomkit-action, cdxgen-cbom",
		"Asset Key": "algorithm:rsa;size=2048",
	} {
		if got := row[columnIndex(t, algos, column)]; got != want {
			t.Errorf("%s = %q, want %q", column, got, want)
		}
	}

	// No evidence is stated, not left blank.
	keys := findSheet(t, sheets, "Crypto - Keys")
	for _, column := range []string{"Location", "Engines", "Asset Key"} {
		if got := rowsOf(t, keys)[0][columnIndex(t, keys, column)]; got != model.NotProvided {
			t.Errorf("an asset with no %s renders %q, want %q", column, got, model.NotProvided)
		}
	}

	// Every type's sheet carries the columns: they apply to every type alike.
	for _, name := range []string{"Crypto - Algorithms", "Crypto - Keys", "Crypto - Protocols", "Crypto - Certificates"} {
		s := findSheet(t, sheets, name)
		columnIndex(t, s, "Location")
		columnIndex(t, s, "Engines")
	}
}

// TestAHostileEvidencePathIsEscapedInTheWorkbook — invariant 8. A path and an
// engine list come from the customer's repository and the scan, and the
// escaping lives in cell(); this proves the new columns and the private-key
// sheet inherit it rather than assuming so.
func TestAHostileEvidencePathIsEscapedInTheWorkbook(t *testing.T) {
	b := withCommittedKey(evidenceSample())
	b.CryptoAssets[1].Evidence = []CryptoEvidence{{Path: `=cmd|'/c calc'!A1`, Engine: "cbomkit-theia"}}
	b.CryptoAssets[1].Engines = []string{"@SUM(1+9)"}
	b.CryptoAssets[1].AssetKey = "-2+3"

	sheets, err := Sheets(b)
	if err != nil {
		t.Fatal(err)
	}
	var stats cellStats
	checked := 0
	for _, s := range sheets {
		if s.Name != "Crypto - Keys" && s.Name != "Private Keys in Source" {
			continue
		}
		checked++
		for _, row := range rowsOf(t, s) {
			for _, value := range row {
				escaped := cell(value, &stats)
				if escaped == "" {
					continue
				}
				switch escaped[0] {
				case '=', '+', '-', '@', '\t', '\r':
					t.Errorf("%s: cell %q was not escaped", s.Name, value)
				}
			}
		}
	}
	if checked != 2 {
		t.Fatalf("checked %d sheets, want the key inventory and the private-key sheet", checked)
	}
	if stats.escaped == 0 {
		t.Fatal("no cell was escaped, so this test proves nothing")
	}
}

// TestThePrivateKeyBlockIsAFindingAndAbsentWhenNone.
func TestThePrivateKeyBlockIsAFindingAndAbsentWhenNone(t *testing.T) {
	clean := evidenceSample()
	sheets, err := Sheets(clean)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range sheets {
		if s.Name == "Private Keys in Source" {
			t.Fatal("the private-key sheet renders for a BOM with nothing flagged")
		}
	}
	if PrivateKeysInSourceFinding(clean) != "" || PrivateKeysInSourceStatement(clean) != "" {
		t.Error("a finding exists for a BOM with nothing flagged")
	}
	raw, err := WriteJSON(clean, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "private_keys_in_source") {
		t.Error("the JSON bundle carries a private-key block with nothing flagged")
	}

	b := withCommittedKey(evidenceSample())
	finding := PrivateKeysInSourceFinding(b)
	for _, want := range []string{PrivateKeysInSourceTitle, "1 asset(s)", "never read or stored by AxeBOM", "rotate it", "history"} {
		if !strings.Contains(finding, want) {
			t.Errorf("the finding %q does not say %q", finding, want)
		}
	}
	if strings.Contains(strings.ToLower(finding), "compliant") {
		t.Errorf("the finding is phrased as a pass: %q", finding)
	}

	sheets, err = Sheets(b)
	if err != nil {
		t.Fatal(err)
	}
	if sheets[2].Name != "Private Keys in Source" {
		t.Errorf("sheet 3 is %q; the finding belongs right after Summary and Engine Coverage", sheets[2].Name)
	}
	rows := rowsOf(t, sheets[2])
	if len(rows) != 3 || rows[0][0] != "Finding" {
		t.Fatalf("private-key sheet rows = %v, want the finding then one row per location", rows)
	}
	if rows[1][2] != "deploy/old.pem" || rows[2][2] != "keys/server.key" {
		t.Errorf("locations = %q, %q — want every one, sorted", rows[1][2], rows[2][2])
	}
	if !strings.Contains(flatten(rowsOf(t, findSheet(t, sheets, "Summary"))), PrivateKeysInSourceTitle) {
		t.Error("the Summary sheet does not state the finding")
	}

	raw, err = WriteJSON(b, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	var bundle struct {
		PrivateKeys *BundlePrivateKeys `json:"private_keys_in_source"`
	}
	if err := json.Unmarshal(raw, &bundle); err != nil {
		t.Fatal(err)
	}
	if bundle.PrivateKeys == nil || len(bundle.PrivateKeys.Assets) != 1 {
		t.Fatalf("the JSON bundle's private-key block = %+v", bundle.PrivateKeys)
	}
	if got := strings.Join(bundle.PrivateKeys.Assets[0].Locations, ","); got != "deploy/old.pem,keys/server.key" {
		t.Errorf("JSON locations = %q", got)
	}
	if bundle.PrivateKeys.Finding != finding {
		t.Errorf("the JSON finding differs from every other format's: %q", bundle.PrivateKeys.Finding)
	}

	// ⚠ ONLY A JSON `true` FLAGS A KEY. Anything else is not the normalizer's
	// statement, and a false accusation of a committed key is its own harm.
	b.CryptoAssets[1].Attributes = map[string]any{"private_key_in_source": "true"}
	if len(PrivateKeysInSource(b)) != 0 {
		t.Error("a non-boolean flag was read as a committed private key")
	}
}

// TestTheJSONBundleCarriesIdentityAndEvidence — the bundle is the one format
// with every location, so a null line must stay null and every key be there.
func TestTheJSONBundleCarriesIdentityAndEvidence(t *testing.T) {
	raw, err := WriteJSON(evidenceSample(), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	var generic map[string]any
	if err := json.Unmarshal(raw, &generic); err != nil {
		t.Fatal(err)
	}
	first := generic["canonical"].(map[string]any)["crypto_assets"].([]any)[0].(map[string]any)
	for _, key := range []string{"asset_key", "evidence", "engines"} {
		if _, ok := first[key]; !ok {
			t.Errorf("the bundle's crypto asset has no %q: %v", key, first)
		}
	}
	evidence := first["evidence"].([]any)
	last := evidence[len(evidence)-1].(map[string]any)
	if line, ok := last["line"]; !ok || line != nil {
		t.Errorf("a missing line reached the bundle as %v (present=%v), want null", line, ok)
	}
}
