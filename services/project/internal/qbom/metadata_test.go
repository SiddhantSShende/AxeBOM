package qbom_test

import (
	"strings"
	"testing"

	"github.com/axebom/axebom/libs/go-shared/model"
	"github.com/axebom/axebom/services/project/internal/qbom"
)

func TestFormFieldsIsGeneratedFromTheProfile(t *testing.T) {
	fields := qbom.FormFields()
	if len(fields) != len(model.QBOMFields) {
		t.Fatalf("FormFields() len = %d, want %d (len(model.QBOMFields)) — "+
			"never hand-count these (CLAUDE.md invariant 2)", len(fields), len(model.QBOMFields))
	}

	var sawDerived int
	for _, f := range fields {
		if f.FieldID == "" || f.Name == "" || f.CanonicalPath == "" {
			t.Errorf("field %+v missing required metadata", f)
		}
		if f.Derived {
			sawDerived++
		}
	}
	if sawDerived != 2 {
		t.Errorf("derived field count = %d, want 2 (crypto_assets, findings)", sawDerived)
	}
}

func TestFormFieldsMarksExactlyCryptoAssetsAndFindingsAsDerived(t *testing.T) {
	want := map[string]bool{
		model.FieldCertinQbom05CryptographicAsset: true,
		model.FieldCertinQbom10Vulnerabilities:    true,
	}
	for _, f := range qbom.FormFields() {
		if f.Derived != want[f.FieldID] {
			t.Errorf("field %s: derived = %v, want %v", f.FieldID, f.Derived, want[f.FieldID])
		}
	}
}

func TestFormDisclosureIsNonEmptyAndHonest(t *testing.T) {
	if qbom.FormDisclosure == "" {
		t.Fatal("FormDisclosure must not be empty — it is a product commitment, not decoration")
	}
	if !strings.Contains(qbom.FormDisclosure, "no open-source scanner") {
		t.Errorf("FormDisclosure = %q, want it to state plainly that there is no scanner", qbom.FormDisclosure)
	}
}

func TestNormalizeDeviceRecordsEveryCapturedFieldOrMarksItNotProvided(t *testing.T) {
	values := qbom.DeviceValues{
		ModelName:             "IBM Q System One",
		Version:               "",
		VendorOrigin:          "IBM, US",
		LicenseInfo:           "not-provided",
		CommunicationProtocol: "REST over TLS",
		Hardware:              "",
		SoftwareDependencies:  nil,
		EnvironmentalImpact:   "  ",
		AttestationSignature:  "sig:abc123",
	}

	device, gaps := qbom.NormalizeDevice(values, nil, nil)

	if device.ModelName != "IBM Q System One" {
		t.Errorf("model_name = %q, want passthrough of a substantive value", device.ModelName)
	}
	if device.Version != qbom.NotProvided {
		t.Errorf("version = %q, want %q for an absent value", device.Version, qbom.NotProvided)
	}
	if device.LicenseInfo != qbom.NotProvided {
		t.Errorf("license_info = %q, want %q — a user typing the literal sentinel still counts as a gap",
			device.LicenseInfo, qbom.NotProvided)
	}
	if device.EnvironmentalImpact != qbom.NotProvided {
		t.Errorf("environmental_impact = %q, want %q for a whitespace-only value",
			device.EnvironmentalImpact, qbom.NotProvided)
	}
	if len(device.SoftwareDependencies) != 0 {
		t.Errorf("software_dependencies = %v, want an explicit empty list, not nil", device.SoftwareDependencies)
	}
	if device.AttestationSignature != "sig:abc123" {
		t.Errorf("attestation_signature = %q, want passthrough", device.AttestationSignature)
	}

	// field_status must cover all eleven elements, not just the nine captured
	// ones — the two derived fields are absent here too (nil refs) and must
	// still be reported.
	if len(device.FieldStatus) != len(model.QBOMFields) {
		t.Fatalf("field_status has %d entries, want %d (one per QBOM field)",
			len(device.FieldStatus), len(model.QBOMFields))
	}
	if device.FieldStatus[model.FieldCertinQbom05CryptographicAsset] != qbom.NotProvided {
		t.Errorf("crypto asset field_status = %q, want %q when no refs were supplied",
			device.FieldStatus[model.FieldCertinQbom05CryptographicAsset], qbom.NotProvided)
	}

	// Every not-provided field must appear in gaps exactly once.
	gapIDs := map[string]bool{}
	for _, g := range gaps {
		if gapIDs[g.FieldID] {
			t.Errorf("field %s reported as a gap twice", g.FieldID)
		}
		gapIDs[g.FieldID] = true
	}
	for fieldID, status := range device.FieldStatus {
		if status == qbom.NotProvided && !gapIDs[fieldID] {
			t.Errorf("field %s is not-provided but missing from gaps", fieldID)
		}
		if status == "provided" && gapIDs[fieldID] {
			t.Errorf("field %s is provided but incorrectly listed as a gap", fieldID)
		}
	}
}

func TestNormalizeDeviceDerivedFieldsComeFromResolvedRefsNotUserValues(t *testing.T) {
	cryptoRefs := []string{"asset-1", "asset-2"}
	device, gaps := qbom.NormalizeDevice(qbom.DeviceValues{ModelName: "X"}, cryptoRefs, nil)

	if len(device.CryptoAssetRefs) != 2 {
		t.Fatalf("crypto asset refs = %v, want the two resolved refs", device.CryptoAssetRefs)
	}
	if device.FieldStatus[model.FieldCertinQbom05CryptographicAsset] != "provided" {
		t.Errorf("crypto asset status = %q, want provided when refs are non-empty",
			device.FieldStatus[model.FieldCertinQbom05CryptographicAsset])
	}
	if device.FieldStatus[model.FieldCertinQbom10Vulnerabilities] != qbom.NotProvided {
		t.Errorf("findings status = %q, want %q — no finding-to-crypto-asset matching exists yet",
			device.FieldStatus[model.FieldCertinQbom10Vulnerabilities], qbom.NotProvided)
	}

	for _, g := range gaps {
		if g.FieldID == model.FieldCertinQbom05CryptographicAsset {
			t.Errorf("crypto asset field must not be a gap when refs were resolved: %+v", g)
		}
	}
}

func TestNormalizeDeviceEmptyDerivedListIsNotProvidedNotProvided(t *testing.T) {
	// An empty (non-nil) slice must be treated identically to nil — a CBOM
	// that ran and found zero crypto assets is still "nothing to reference".
	device, gaps := qbom.NormalizeDevice(qbom.DeviceValues{}, []string{}, []string{})

	if device.FieldStatus[model.FieldCertinQbom05CryptographicAsset] != qbom.NotProvided {
		t.Errorf("empty (non-nil) crypto refs must still be not-provided, got %q",
			device.FieldStatus[model.FieldCertinQbom05CryptographicAsset])
	}
	var found bool
	for _, g := range gaps {
		if g.FieldID == model.FieldCertinQbom05CryptographicAsset {
			found = true
		}
	}
	if !found {
		t.Error("expected a gap for the crypto asset field when refs are empty")
	}
}
