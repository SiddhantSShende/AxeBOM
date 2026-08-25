// Package compliance loads and validates a compliance profile.
//
// A compliance standard is DATA here, not code (ADR-0007). One YAML file is
// the source of truth; Go structs, Python models, report field tables and the
// coverage checker all generate from or validate against it.
//
// The rule this exists to enforce: NEVER HARDCODE A FIELD COUNT. Not 21, not
// "the 21 data fields", anywhere. A hardcoded count is how a product ships a
// false compliance claim — the guideline revises to 23 fields, the profile is
// updated, and the UI still reads "21 of 21 covered ✓" because nobody grepped
// for the literal.
package compliance

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Profile is a parsed compliance profile.
type Profile struct {
	Meta               Meta               `yaml:"profile"`
	SBOM               SBOMSection        `yaml:"sbom"`
	QBOM               ElementSection     `yaml:"qbom"`
	CryptoAsset        CryptoAssetSection `yaml:"crypto_asset"`
	AIBOM              ElementSection     `yaml:"aibom"`
	HBOM               HBOMSection        `yaml:"hbom"`
	VEX                VEXSection         `yaml:"vex"`
	CSAF               CSAFSection        `yaml:"csaf"`
	SecureDistribution SecureDistSection  `yaml:"secure_distribution"`
	ExpectedCounts     map[string]int     `yaml:"expected_counts"`
}

type Meta struct {
	ID                 string `yaml:"id"`
	Name               string `yaml:"name"`
	Version            string `yaml:"version"`
	Published          string `yaml:"published"`
	Authority          string `yaml:"authority"`
	SourceDocument     string `yaml:"source_document"`
	SourcePages        int    `yaml:"source_pages"`
	Revision           int    `yaml:"revision"`
	AllEntriesVerified bool   `yaml:"all_entries_verified"`
}

// Field is one required element.
type Field struct {
	ID            string   `yaml:"id"`
	Ordinal       int      `yaml:"ordinal"`
	Name          string   `yaml:"name"`
	Description   string   `yaml:"description"`
	CanonicalPath string   `yaml:"canonical_path"`
	CycloneDXPath string   `yaml:"cyclonedx_path"`
	SPDXPath      string   `yaml:"spdx_path"`
	Type          string   `yaml:"type"`
	Weight        int      `yaml:"weight"`
	Required      bool     `yaml:"required"`
	SourcePage    int      `yaml:"source_page"`
	Status        string   `yaml:"status"`
	Note          string   `yaml:"note"`
	Values        []string `yaml:"values"`
	Scope         string   `yaml:"scope"`
	Scored        *bool    `yaml:"scored"`
	// Binding for per-project settings rather than per-component fields.
	AxeBOMBinding string `yaml:"axebom_binding"`
}

// IsScored reports whether the field counts toward coverage. AxeBOM
// extensions (quantum_vulnerable, risk_score) are analysis, not CERT-In
// elements, and must not inflate or deflate a compliance percentage.
func (f Field) IsScored() bool { return f.Scored == nil || *f.Scored }

type SBOMSection struct {
	MinimumElementCategories []Category `yaml:"minimum_element_categories"`
	DataFields               []Field    `yaml:"data_fields"`
	Levels                   []Level    `yaml:"levels"`
	Classifications          []Level    `yaml:"classifications"`
}

type Category struct {
	ID             string   `yaml:"id"`
	Name           string   `yaml:"name"`
	SourcePage     int      `yaml:"source_page"`
	Overview       string   `yaml:"overview"`
	Kind           string   `yaml:"kind"`
	FieldsRef      string   `yaml:"fields_ref"`
	RequiredValues []string `yaml:"required_values"`
	SubElements    []Field  `yaml:"sub_elements"`
}

type Level struct {
	ID          string `yaml:"id"`
	Name        string `yaml:"name"`
	SourcePage  int    `yaml:"source_page"`
	Description string `yaml:"description"`
	UIExposed   bool   `yaml:"ui_exposed"`
}

type ElementSection struct {
	SourceTable      string  `yaml:"source_table"`
	SourcePages      []int   `yaml:"source_pages"`
	Elements         []Field `yaml:"elements"`
	AxeBOMExtensions []Field `yaml:"axebom_extensions"`
}

// CryptoAssetSection is TYPE-DISCRIMINATED — CERT-In Table 9 defines four
// asset types with DIFFERENT field sets.
//
// Coverage must be scored against the field set for the row's asset_type.
// Scoring a certificate against key_size would report every CBOM at roughly
// 30% coverage, falsely, in a document shown to a regulator.
type CryptoAssetSection struct {
	SourceTable      string                `yaml:"source_table"`
	SourcePages      []int                 `yaml:"source_pages"`
	Discriminator    string                `yaml:"discriminator"`
	Types            map[string]CryptoType `yaml:"types"`
	AxeBOMExtensions []Field               `yaml:"axebom_extensions"`
}

type CryptoType struct {
	AssetTypeValue string  `yaml:"asset_type_value"`
	Fields         []Field `yaml:"fields"`
}

type HBOMSection struct {
	SourceTable                string          `yaml:"source_table"`
	SourcePages                []int           `yaml:"source_pages"`
	Recursive                  bool            `yaml:"recursive"`
	Elements                   []Field         `yaml:"elements"`
	AdditionalRequiredElements AdditionalElems `yaml:"additional_required_elements"`
}

// AdditionalElems are mandated by prose rather than by the table — CERT-In
// §10.4.1.4 (p.62) requires four HBOM fields that appear nowhere in Table 11.
type AdditionalElems struct {
	SourceSection string  `yaml:"source_section"`
	SourcePage    int     `yaml:"source_page"`
	SourceQuote   string  `yaml:"source_quote"`
	Elements      []Field `yaml:"elements"`
}

type VEXSection struct {
	SourcePages      []int     `yaml:"source_pages"`
	Iterative        bool      `yaml:"iterative"`
	Statuses         []VEXStat `yaml:"statuses"`
	AdditionalFields []Field   `yaml:"additional_fields"`
}

type VEXStat struct {
	ID          string `yaml:"id"`
	Name        string `yaml:"name"`
	CSAFValue   string `yaml:"csaf_value"`
	SourcePage  int    `yaml:"source_page"`
	Status      string `yaml:"status"`
	Description string `yaml:"description"`
}

type CSAFSection struct {
	SourcePage      int      `yaml:"source_page"`
	Sequence        []string `yaml:"sequence"`
	RequiredContent []Field  `yaml:"required_content"`
}

type SecureDistSection struct {
	SourcePages []int   `yaml:"source_pages"`
	Controls    []Field `yaml:"controls"`
}

// Load reads and parses a profile.
func Load(path string) (*Profile, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- operator-supplied path to a repo file
	if err != nil {
		return nil, fmt.Errorf("read profile: %w", err)
	}
	var p Profile
	if err := yaml.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("parse profile: %w", err)
	}
	return &p, nil
}

// AllFields returns every field in the profile, in a stable order.
func (p *Profile) AllFields() []Field {
	var out []Field
	for _, c := range p.SBOM.MinimumElementCategories {
		out = append(out, c.SubElements...)
	}
	out = append(out, p.SBOM.DataFields...)
	out = append(out, p.QBOM.Elements...)
	out = append(out, p.QBOM.AxeBOMExtensions...)

	// Map iteration is random; sort the crypto type names so generated output
	// is byte-stable. Unstable codegen produces spurious diffs, and spurious
	// diffs are how a real one gets missed.
	for _, name := range p.cryptoTypeNames() {
		out = append(out, p.CryptoAsset.Types[name].Fields...)
	}
	out = append(out, p.CryptoAsset.AxeBOMExtensions...)

	out = append(out, p.AIBOM.Elements...)
	out = append(out, p.AIBOM.AxeBOMExtensions...)
	out = append(out, p.HBOM.Elements...)
	out = append(out, p.HBOM.AdditionalRequiredElements.Elements...)
	out = append(out, p.VEX.AdditionalFields...)
	out = append(out, p.CSAF.RequiredContent...)
	out = append(out, p.SecureDistribution.Controls...)
	return out
}

func (p *Profile) cryptoTypeNames() []string {
	names := make([]string, 0, len(p.CryptoAsset.Types))
	for n := range p.CryptoAsset.Types {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// ActualCounts computes what the profile actually contains, for comparison
// against the declared expected_counts.
func (p *Profile) ActualCounts() map[string]int {
	counts := map[string]int{
		"sbom_minimum_element_categories":   len(p.SBOM.MinimumElementCategories),
		"sbom_data_fields":                  len(p.SBOM.DataFields),
		"sbom_levels":                       len(p.SBOM.Levels),
		"sbom_classifications":              len(p.SBOM.Classifications),
		"qbom_elements":                     len(p.QBOM.Elements),
		"crypto_asset_types":                len(p.CryptoAsset.Types),
		"aibom_elements":                    len(p.AIBOM.Elements),
		"hbom_table11_elements":             len(p.HBOM.Elements),
		"hbom_additional_required_elements": len(p.HBOM.AdditionalRequiredElements.Elements),
		"hbom_total_elements": len(p.HBOM.Elements) +
			len(p.HBOM.AdditionalRequiredElements.Elements),
		"vex_statuses":                 len(p.VEX.Statuses),
		"secure_distribution_controls": len(p.SecureDistribution.Controls),
	}

	for _, c := range p.SBOM.MinimumElementCategories {
		if c.Kind == "per_project_settings" {
			counts["sbom_practices_and_processes_sub_elements"] = len(c.SubElements)
		}
	}
	for name, t := range p.CryptoAsset.Types {
		counts["crypto_"+name+"_fields"] = len(t.Fields)
	}
	return counts
}

// FieldsForBOMType returns the scored required fields for a BOM type.
func (p *Profile) FieldsForBOMType(bomType string) []Field {
	var src []Field
	switch strings.ToUpper(bomType) {
	case "SBOM":
		src = p.SBOM.DataFields
	case "QBOM":
		src = p.QBOM.Elements
	case "AIBOM":
		src = p.AIBOM.Elements
	case "HBOM":
		src = append(append([]Field{}, p.HBOM.Elements...),
			p.HBOM.AdditionalRequiredElements.Elements...)
	default:
		return nil
	}
	out := make([]Field, 0, len(src))
	for _, f := range src {
		if f.IsScored() {
			out = append(out, f)
		}
	}
	return out
}

// FieldsForCryptoAssetType returns the scored fields for ONE crypto asset type.
//
// This is the type-aware scoring that keeps CBOM coverage honest.
func (p *Profile) FieldsForCryptoAssetType(assetType string) []Field {
	for _, t := range p.CryptoAsset.Types {
		if t.AssetTypeValue == assetType {
			out := make([]Field, 0, len(t.Fields))
			for _, f := range t.Fields {
				if f.IsScored() {
					out = append(out, f)
				}
			}
			return out
		}
	}
	return nil
}
