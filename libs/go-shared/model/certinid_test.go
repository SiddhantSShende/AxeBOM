package model

import "testing"

// The golden test: EVERY worked example from CERT-In Table 6 (PDF p.26).
//
// These strings come from the guideline itself, so they are the closest thing
// to an authoritative conformance check that exists. If this test fails,
// EncoreBOM's field 21 does not match what the standard's own examples show.
func TestDeriveCERTInIdentifier_Table6(t *testing.T) {
	tests := []struct {
		name string
		in   CERTInIdentifierInput
		want string
	}{
		{
			name: "Apache Tomcat — the fully worked example",
			in: CERTInIdentifierInput{
				Supplier:   "Apache Software Foundation",
				Name:       "Apache Tomcat",
				VersionRaw: "9.0.71",
				Qualifiers: map[string]string{"arch": "x86_64", "os": "linux"},
				Subpath:    "server/webapps",
			},
			want: "pkg:supplier/ApacheSoftwareFoundation/ApacheTomcat@9.0.71?arch=x86_64&os=linux#server/webapps",
		},
		{
			// The interesting one: internal capitalisation must survive.
			// Naive Title-casing yields "Postgresql" and stops matching the
			// guideline's own example.
			name: "PostgreSQL — internal capitals preserved",
			in: CERTInIdentifierInput{
				Supplier:   "PostgreSQL Global Development Group",
				Name:       "PostgreSQL",
				VersionRaw: "13.5",
				Qualifiers: map[string]string{"arch": "x86_64", "os": "linux"},
			},
			want: "pkg:supplier/PostgreSQLGlobalDevelopmentGroup/PostgreSQL@13.5?arch=x86_64&os=linux",
		},
		{
			name: "Postfix",
			in: CERTInIdentifierInput{
				Supplier:   "Postfix Foundation",
				Name:       "Postfix",
				VersionRaw: "3.6.2",
				Qualifiers: map[string]string{"arch": "x86_64", "os": "linux"},
			},
			want: "pkg:supplier/PostfixFoundation/Postfix@3.6.2?arch=x86_64&os=linux",
		},
		{
			// Table 6 renders this one WITHOUT the `pkg:` prefix —
			// "supplier/TwilioInc/TwilioSDK@1.20.0?..." — which contradicts
			// both the field-21 syntax on p.24 and every other row in the
			// same table. We treat that as a typo in the source document and
			// emit the prefix consistently. Recorded here so the decision is
			// visible rather than looking like a mismatch nobody noticed.
			name: "Twilio SDK — trailing punctuation dropped from 'Inc.'",
			in: CERTInIdentifierInput{
				Supplier:   "Twilio Inc.",
				Name:       "Twilio SDK",
				VersionRaw: "1.20.0",
				Qualifiers: map[string]string{"arch": "x86_64", "os": "linux"},
			},
			want: "pkg:supplier/TwilioInc/TwilioSDK@1.20.0?arch=x86_64&os=linux",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := DeriveCERTInIdentifier(tt.in)
			if !ok {
				t.Fatalf("derivation reported failure for %+v", tt.in)
			}
			if got != tt.want {
				t.Errorf("identifier mismatch\n  got:  %s\n  want: %s", got, tt.want)
			}
		})
	}
}

// An unknown supplier must NOT be papered over. A fabricated organisation name
// in a compliance artifact is worse than an honest gap.
func TestDeriveCERTInIdentifier_RefusesUnknownSupplier(t *testing.T) {
	for _, in := range []CERTInIdentifierInput{
		{Supplier: "", Name: "lodash", VersionRaw: "4.17.21"},
		{Supplier: "   ", Name: "lodash", VersionRaw: "4.17.21"},
		{Supplier: "Acme", Name: "", VersionRaw: "1.0"},
		{Supplier: "...", Name: "lodash"}, // punctuation-only reduces to empty
	} {
		if got, ok := DeriveCERTInIdentifier(in); ok {
			t.Errorf("expected refusal for %+v, got %q", in, got)
		}
	}
}

// Qualifier order must be deterministic, or the same component produces
// different identifiers across runs and two reports of one scan disagree.
func TestDeriveCERTInIdentifier_QualifiersSorted(t *testing.T) {
	in := CERTInIdentifierInput{
		Supplier:   "Acme",
		Name:       "Widget",
		VersionRaw: "1.0",
		Qualifiers: map[string]string{
			"os": "linux", "arch": "x86_64", "distro": "debian", "epoch": "1",
		},
	}
	want := "pkg:supplier/Acme/Widget@1.0?arch=x86_64&distro=debian&epoch=1&os=linux"

	// Repeat: Go randomizes map iteration, so a single pass could pass by luck.
	for i := 0; i < 50; i++ {
		got, ok := DeriveCERTInIdentifier(in)
		if !ok || got != want {
			t.Fatalf("iteration %d: got %q, want %q", i, got, want)
		}
	}
}

func TestDeriveCERTInIdentifier_EmptyQualifiersOmitted(t *testing.T) {
	got, _ := DeriveCERTInIdentifier(CERTInIdentifierInput{
		Supplier:   "Acme",
		Name:       "Widget",
		VersionRaw: "1.0",
		Qualifiers: map[string]string{"arch": ""}, // present but empty
	})
	if got != "pkg:supplier/Acme/Widget@1.0" {
		t.Errorf("empty qualifier should be omitted, got %q", got)
	}
}

func TestPascalCompact(t *testing.T) {
	tests := []struct{ in, want string }{
		{"Apache Software Foundation", "ApacheSoftwareFoundation"},
		{"PostgreSQL Global Development Group", "PostgreSQLGlobalDevelopmentGroup"},
		{"Twilio Inc.", "TwilioInc"},
		{"Apache Tomcat", "ApacheTomcat"},
		{"the-linux-foundation", "TheLinuxFoundation"},
		{"Red_Hat, Inc.", "RedHatInc"},
		{"IBM", "IBM"}, // already compact, all caps preserved
		{"eclipse foundation", "EclipseFoundation"},
		{"  spaced   out  ", "SpacedOut"},
		{"", ""},
		{"...", ""},
		{"3M Company", "3MCompany"}, // leading digit survives
	}
	for _, tt := range tests {
		if got := PascalCompact(tt.in); got != tt.want {
			t.Errorf("PascalCompact(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

// Only identity-bearing qualifiers belong in the identifier. A download_url in
// there would make the same component in two mirrors look like two components.
func TestFilterIdentityQualifiers(t *testing.T) {
	in := map[string]string{
		"arch":           "x86_64",
		"os":             "linux",
		"distro":         "debian-12",
		"epoch":          "1",
		"classifier":     "sources",
		"repository_url": "https://repo1.maven.org/maven2",
		"download_url":   "https://example.com/x.jar",
		"checksum":       "sha256:abc",
		"file_name":      "x.jar",
		"vcs_url":        "git+https://github.com/x/y",
		"empty":          "",
	}
	got := FilterIdentityQualifiers(in)

	for _, k := range []string{"arch", "os", "distro", "epoch", "classifier"} {
		if _, ok := got[k]; !ok {
			t.Errorf("identity qualifier %q was dropped", k)
		}
	}
	for _, k := range []string{"repository_url", "download_url", "checksum", "file_name", "vcs_url", "empty"} {
		if _, ok := got[k]; ok {
			t.Errorf("non-identity qualifier %q was kept", k)
		}
	}
}

// The CERT-In identifier and the ecosystem PURL are DIFFERENT STRINGS for the
// same component. This test exists to make that concrete: if someone ever
// "simplifies" by using one for the other, dedup silently changes behaviour.
func TestCERTInIdentifierIsNotAPURL(t *testing.T) {
	certin, ok := DeriveCERTInIdentifier(CERTInIdentifierInput{
		Supplier:   "Apache Software Foundation",
		Name:       "Apache Tomcat",
		VersionRaw: "9.0.71",
	})
	if !ok {
		t.Fatal("derivation failed")
	}
	const ecosystemPURL = "pkg:maven/org.apache.tomcat/tomcat@9.0.71"

	if certin == ecosystemPURL {
		t.Fatal("the CERT-In identifier must not equal the ecosystem PURL")
	}
	if want := "pkg:supplier/ApacheSoftwareFoundation/ApacheTomcat@9.0.71"; certin != want {
		t.Errorf("got %q, want %q", certin, want)
	}
}
