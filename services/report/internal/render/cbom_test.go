package render

import (
	"strings"
	"testing"

	"github.com/axebom/axebom/libs/go-shared/model"
)

func cryptoAssets() []CryptoAsset {
	size := 2048
	return []CryptoAsset{
		{
			AssetType: "algorithm", Name: "RSA-2048", Primitive: "RSA", Mode: "PKCS1",
			ClassicalSecurityLevel: intPtr(112), QuantumVulnerable: true,
			PQCRecommendation: "lattice-based", DeprecationStatus: "current",
			QuantumFamily: "RSA", QuantumRationale: "Shor's algorithm breaks RSA",
			QuantumReadinessGroup: "vulnerable",
		},
		{
			AssetType: "key", Name: "signing-key-01", KeyID: "kid-01", KeyState: "active",
			KeySize: &size, QuantumVulnerable: false, QuantumFamily: "unknown",
			QuantumReadinessGroup: "unassessed",
		},
		{
			AssetType: "protocol", Name: "TLS 1.3", ProtocolVersion: "1.3",
			CipherSuites: []string{"TLS_AES_256_GCM_SHA384"}, QuantumFamily: "ML-KEM",
			QuantumReadinessGroup: "post_quantum",
		},
		{
			AssetType: "certificate", Name: "leaf-cert", CertSubject: "CN=example.com",
			CertIssuer: "CN=Example CA", SignatureAlgoRef: "SHA256withRSA",
			GroverNote:            "AES-128 effective strength halves under Grover",
			QuantumReadinessGroup: "grover_note",
		},
	}
}

func intPtr(n int) *int { return &n }

func cbomSample() BOM {
	return BOM{
		ReportID: "0199-cbom", ProjectName: "acme-crypto", BOMType: model.BOMTypeCBOM,
		GeneratedAt: "2026-08-17T09:14:03Z", ToolName: "AxeBOM", ToolVersion: "0.1.0",
		Coverage: Coverage{
			CompletenessPct: 40, DeclarationPct: 80,
			Formula: "sum(weight × substantive) / sum(weight × entities)",
			Fields: []FieldCoverage{
				{FieldID: model.FieldCertinCryptoCertName, Present: 1, Declared: 1, Total: 1},
				{FieldID: model.FieldCertinCryptoCertSubjectName, Present: 1, Declared: 1, Total: 1},
			},
		},
		CryptoAssets: cryptoAssets(),
	}
}

// TestACertificateNeverShowsAKeySizeField pins CLAUDE.md invariant 5 at the
// literal case its own docstring warns about.
//
// ⚠ THE FAILURE THIS TEST CATCHES: a single merged crypto table would give a
// certificate a blank `key_size` cell, and a reader cannot tell "this type
// was never asked for a key size" from "the scan found nothing". The
// Certificates sheet must not have the column AT ALL.
func TestACertificateNeverShowsAKeySizeField(t *testing.T) {
	sheets := CBOMSheets(cbomSample())
	certs := findSheet(t, sheets, "Crypto - Certificates")

	for _, h := range certs.Header {
		if strings.Contains(strings.ToLower(h), "size") {
			t.Fatalf("the Certificates sheet has a %q column; a certificate has no key size", h)
		}
	}

	keys := findSheet(t, sheets, "Crypto - Keys")
	sizeCol := columnIndex(t, keys, "size")
	rows := rowsOf(t, keys)
	if rows[0][sizeCol] != "2048" {
		t.Errorf("the key's own size is %q, want 2048", rows[0][sizeCol])
	}
}

// TestEveryInventorySheetShowsOnlyItsOwnType — the four sheets are disjoint,
// and each asset appears exactly once, on its own type's sheet.
func TestEveryInventorySheetShowsOnlyItsOwnType(t *testing.T) {
	b := cbomSample()
	sheets := CBOMSheets(b)

	want := map[string]int{
		"Crypto - Algorithms":   1,
		"Crypto - Keys":         1,
		"Crypto - Protocols":    1,
		"Crypto - Certificates": 1,
	}
	for name, n := range want {
		rows := rowsOf(t, findSheet(t, sheets, name))
		if len(rows) != n {
			t.Errorf("%s has %d rows, want %d", name, len(rows), n)
		}
	}
}

// TestCryptoFieldCoverageIsGroupedByType — the replacement for the generic
// Field Coverage sheet must still cite present/declared/total, per type.
func TestCryptoFieldCoverageIsGroupedByType(t *testing.T) {
	sheets := CBOMSheets(cbomSample())
	sheet := findSheet(t, sheets, "Crypto Field Coverage")
	rows := rowsOf(t, sheet)

	wantRows := 0
	for _, at := range cryptoAssetTypeOrder {
		wantRows += len(model.CryptoFieldsByAssetType[at])
	}
	if len(rows) != wantRows {
		t.Fatalf("the crypto field coverage sheet has %d rows, want %d (one per "+
			"field across all four asset types)", len(rows), wantRows)
	}

	joined := flatten(rows)
	if !strings.Contains(joined, "Certificates") || !strings.Contains(joined, "Algorithms") {
		t.Error("the sheet does not label rows by asset type")
	}
	if !strings.Contains(joined, "1") {
		t.Error("the coverage counts from b.Coverage.Fields did not reach the sheet")
	}
}

// TestSheetsUsesCBOMSheetsInsteadOfTheGenericPair — Sheets() must skip
// componentSheet/fieldCoverageSheet entirely for a CBOM, not run them
// alongside CBOMSheets.
func TestSheetsUsesCBOMSheetsInsteadOfTheGenericPair(t *testing.T) {
	sheets, err := Sheets(cbomSample())
	if err != nil {
		t.Fatalf("a CBOM report was refused: %v", err)
	}

	names := map[string]bool{}
	for _, s := range sheets {
		names[s.Name] = true
	}

	for _, forbidden := range []string{"Components", "Field Coverage"} {
		if names[forbidden] {
			t.Errorf("a CBOM report carries the generic %q sheet; it should have "+
				"been replaced by the crypto-specific sheets", forbidden)
		}
	}
	for _, want := range []string{"Crypto Field Coverage", "Crypto - Algorithms", "Crypto - Certificates"} {
		if !names[want] {
			t.Errorf("a CBOM report is missing %q", want)
		}
	}

	if last := sheets[len(sheets)-1].Name; last != "Notes" {
		t.Errorf("the last sheet is %q, want Notes", last)
	}
	joined := flatten(collect(t, findSheet(t, sheets, "Notes")))
	if !strings.Contains(joined, "CERT-In Table 9 defines four different") {
		t.Error("the CBOM type-discrimination note is missing from the Notes sheet")
	}
}

// TestCBOMSheetsNeverCallFieldsFor — a behavioural echo of the doc comment:
// building the sheets must succeed even though FieldsFor(CBOM) itself still
// errors (that reasoning did not change; only what callers do with it did).
func TestCBOMSheetsNeverCallFieldsFor(t *testing.T) {
	if _, err := FieldsFor(model.BOMTypeCBOM); err == nil {
		t.Fatal("FieldsFor(CBOM) unexpectedly succeeded; the type-discrimination " +
			"reasoning should still hold")
	}
	if _, err := Sheets(cbomSample()); err != nil {
		t.Fatalf("Sheets(CBOM) failed even though it must not call FieldsFor: %v", err)
	}
}
