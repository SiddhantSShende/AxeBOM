package service

import (
	"strings"
	"testing"

	"github.com/axebom/axebom/libs/go-shared/platform/errs"
	"github.com/axebom/axebom/services/report/internal/level"
)

// TestAnUnimplementedLevelIsRefusedWithTheRightAnswer.
//
// ⚠ TWO DIFFERENT REFUSALS, BECAUSE THEY MEAN DIFFERENT THINGS TO THE CALLER.
// `delivery` is a real CERT-In §3.1 level this build does not produce;
// `top-lvl` is a typo. Collapsing them would have somebody spend an afternoon
// checking the spelling of a level that does not exist here at all.
func TestAnUnimplementedLevelIsRefusedWithTheRightAnswer(t *testing.T) {
	for _, known := range []string{"n_level", "delivery", "transitive"} {
		_, err := parseLevel(known)
		if err == nil {
			t.Errorf("level %q was accepted; this build does not produce it", known)
			continue
		}
		if !strings.Contains(err.Error(), "CERT-In") {
			t.Errorf("the refusal for %q does not say it is a real level: %v", known, err)
		}
	}

	_, err := parseLevel("top-lvl")
	if err == nil {
		t.Fatal("a nonsense level was accepted")
	}
	if strings.Contains(err.Error(), "CERT-In §3.1") {
		t.Errorf("a typo was reported as an unimplemented CERT-In level: %v", err)
	}
}

// TestTheDefaultLevelIsTopLevel — and it must be a spelling the database
// accepts, which is what level.TopLevel guarantees.
func TestTheDefaultLevelIsTopLevel(t *testing.T) {
	got, err := parseLevel("")
	if err != nil {
		t.Fatalf("an omitted level was refused: %v", err)
	}
	if got != level.TopLevel {
		t.Errorf("default level = %q, want %q", got, level.TopLevel)
	}
	if !level.Known(got) {
		t.Errorf("the default level %q is not in the compliance profile, so the "+
			"INSERT would fail a CHECK constraint", got)
	}
}

// TestAStandardThatContradictsTheFormatIsRefused.
//
// ⚠ REFUSED, NOT CORRECTED. `{format: spdx, standard: CycloneDX}` is a caller
// that believes something false about what it will receive, and quietly fixing
// it hands them a document they will mis-parse.
func TestAStandardThatContradictsTheFormatIsRefused(t *testing.T) {
	if _, err := parseStandard("CycloneDX", "spdx"); err == nil {
		t.Error("a CycloneDX standard was accepted for an SPDX format")
	}
	if _, err := parseStandard("SPDX", "cyclonedx"); err == nil {
		t.Error("an SPDX standard was accepted for a CycloneDX format")
	}
	if _, err := parseStandard("Whatever", "pdf"); err == nil {
		t.Error("an unknown standard was accepted")
	}
}

// TestTheStandardIsDerivedWhenTheFormatImpliesIt.
func TestTheStandardIsDerivedWhenTheFormatImpliesIt(t *testing.T) {
	tests := map[string]string{
		"spdx":      "SPDX",
		"cyclonedx": "CycloneDX",
		"pdf":       "native",
		"xlsx":      "native",
		"json":      "native",
	}
	for format, want := range tests {
		got, err := parseStandard("", format)
		if err != nil {
			t.Errorf("parseStandard(\"\", %q): %v", format, err)
			continue
		}
		if got != want {
			t.Errorf("format %q derived standard %q, want %q", format, got, want)
		}
	}
}

// TestAnUnknownFormatIsRefused — a queued report that can never render is worse
// than a rejected request: the customer sees `queued`, the UI spins, and the
// reason arrives minutes later as an error code on a row nobody is watching.
func TestAnUnknownFormatIsRefused(t *testing.T) {
	for _, bad := range []string{"", "csv", "PDF", "html", "doc"} {
		if _, err := parseFormat(bad); err == nil {
			t.Errorf("format %q was accepted", bad)
		}
	}
	for _, good := range []string{"pdf", "docx", "xlsx", "json", "spdx", "cyclonedx"} {
		if _, err := parseFormat(good); err != nil {
			t.Errorf("format %q was refused: %v", good, err)
		}
	}
}

// TestTheStorageKeyIsTenantPrefixedAndDerived.
//
// ⚠ NEVER SUPPLIED BY A REQUEST. A caller-named key would be a read primitive
// over the whole bucket — the same class of bug the Vault path derivation
// avoids. The tenant prefix also means a bucket listing is already segmented.
func TestTheStorageKeyIsTenantPrefixedAndDerived(t *testing.T) {
	key := StorageKey("0199-tenant", "0199-report", "pdf")

	if !strings.HasPrefix(key, "reports/0199-tenant/") {
		t.Fatalf("key %q is not tenant-prefixed", key)
	}
	if !strings.Contains(key, "0199-report") {
		t.Errorf("key %q does not identify the report", key)
	}

	// A different tenant must never produce the same key, even for the same
	// report id — that would be a cross-tenant overwrite.
	if StorageKey("other-tenant", "0199-report", "pdf") == key {
		t.Fatal("two tenants produced the same storage key")
	}

	// The standard formats get their conventional double extension, so a
	// downloaded file opens in the right tool.
	for format, want := range map[string]string{
		"spdx":      ".spdx.json",
		"cyclonedx": ".cdx.json",
		"xlsx":      ".xlsx",
		"json":      ".json",
		"docx":      ".docx",
	} {
		if got := StorageKey("t", "r", format); !strings.HasSuffix(got, want) {
			t.Errorf("format %q produced key %q, want suffix %q", format, got, want)
		}
	}
}

// TestErrorCodesAreTheTaxonomy — a bare string tells the UI nothing it can act
// on and ends up rendered at the customer verbatim.
func TestErrorCodesAreTheTaxonomy(t *testing.T) {
	_, err := parseFormat("html")
	if !errs.Is(err, errs.ValidationFieldInvalid) {
		t.Errorf("format refusal carries %v, want %v",
			errs.From(err).Code, errs.ValidationFieldInvalid)
	}

	_, err = parseLevel("delivery")
	if !errs.Is(err, errs.ValidationFieldInvalid) {
		t.Errorf("level refusal carries %v, want %v",
			errs.From(err).Code, errs.ValidationFieldInvalid)
	}
}
