package render

import (
	"fmt"

	"github.com/axebom/axebom/libs/go-shared/model"
)

// ─── AIBOM ──────────────────────────────────────────────────────────────────
//
// ⚠ AN AI MODEL IS NOT A Component. CERT-In Table 10 has no PURL, no
// dependency depth, no ecosystem — componentSheet/componentPages' identity
// columns describe SBOM concepts that do not apply here, the same reason
// CBOM's crypto assets get their own sheets rather than the generic ones
// (CBOMSheets' doc comment). Unlike CBOM, Table 10 IS one flat field list —
// FieldsFor succeeds for AIBOM — so fieldCoverageSheet still runs (Sheets);
// only the per-row inventory is replaced.

// AIDataset is one normalize.ai_datasets row.
type AIDataset struct {
	Name        string
	Version     string
	Format      string
	Limitations string
	License     string
	Source      string
}

// AIModel is one normalize.ai_models row, plus its datasets and dependencies.
//
// ⚠ risk_score AND owasp_llm_top10 ARE AXEBOM EXTENSIONS FROM TRUSERA
// ai-bom — NOT CERT-In Table 10 fields, excluded from Fields and from both
// coverage numbers (workers/aibom/normalize/ai.py's module docstring).
// Rendered on their own, clearly labelled, never folded into a CERT-In
// column.
type AIModel struct {
	Name          string
	Datasets      []AIDataset
	Dependencies  []string
	RiskScore     *float64
	OwaspLLMTop10 []string

	// Fields holds the 19 Table 10 profile-field values keyed by
	// model.ProfileField.ID — same convention as Component.Fields, so a
	// CERT-In revision changes the profile, never this struct.
	Fields map[string]string
}

// AIBOMExtensionsNote lands on the Notes sheet alongside every other
// methodology caveat — the same place QBOMFormDisclosure and
// CBOMTypeDiscriminationNote surface their own type-specific honesty label.
const AIBOMExtensionsNote = "Risk Score and OWASP LLM Top-10 are AxeBOM " +
	"extensions derived from Trusera ai-bom's own heuristics, not CERT-In " +
	"Table 10 elements — they are excluded from both coverage numbers, " +
	"because letting a third party's heuristic move a customer's compliance " +
	"percentage would tie that percentage to a rule this product does not own."

// AIBOMSheets are the AIBOM-specific sheets, appended in place of the
// generic componentSheet Sheets() builds for every other type.
func AIBOMSheets(b BOM, fields []model.ProfileField) []Sheet {
	return []Sheet{
		aiModelInventorySheet(b.AIModels, fields),
		aiDatasetSheet(b.AIModels),
		aiDependencySheet(b.AIModels),
	}
}

func aiModelInventorySheet(models []AIModel, fields []model.ProfileField) Sheet {
	header := []string{"Model"}
	for _, f := range fields {
		header = append(header, f.Name)
	}
	header = append(header, "Risk Score (AxeBOM extension)", "OWASP LLM Top-10 (AxeBOM extension)")

	rows := RowSource(func(emit func([]string) error) error {
		for _, m := range models {
			row := []string{orNotProvided(m.Name)}
			for _, f := range fields {
				// ⚠ EXPLICIT, NEVER BLANK — same reasoning as componentSheet's
				// identical line: a blank cell reads as "we did not look".
				row = append(row, orNotProvided(m.Fields[f.ID]))
			}
			row = append(row, riskScoreText(m.RiskScore), joinList(m.OwaspLLMTop10))
			if err := emit(row); err != nil {
				return err
			}
		}
		return nil
	})

	return Sheet{Name: "AI Models", Header: header, Rows: rows, Width: 22}
}

func riskScoreText(v *float64) string {
	if v == nil {
		return model.NotProvided
	}
	return fmt.Sprintf("%.1f", *v)
}

func aiDatasetSheet(models []AIModel) Sheet {
	header := []string{"Model", "Dataset", "Version", "Format", "Limitations", "License", "Source"}
	rows := RowSource(func(emit func([]string) error) error {
		for _, m := range models {
			for _, d := range m.Datasets {
				if err := emit([]string{
					orNotProvided(m.Name), orNotProvided(d.Name), orNotProvided(d.Version),
					orNotProvided(d.Format), orNotProvided(d.Limitations),
					orNotProvided(d.License), orNotProvided(d.Source),
				}); err != nil {
					return err
				}
			}
		}
		return nil
	})
	return Sheet{Name: "AI Model Datasets", Header: header, Rows: rows, Width: 22}
}

// aiDependencySheet lists each model's SBOM component references.
//
// ⚠ COMPONENT KEY ONLY, NOT A JOIN. normalize.ai_model_dependencies
// .component_key is a plain text column, not a foreign key — the referenced
// SBOM component usually lives in a different bom_document_id than this
// AIBOM (see docs/01-DATA-MODEL.md's ai_model_dependencies entry) — so there
// is nothing to join against here; a reader cross-references the SBOM's own
// export by this key.
func aiDependencySheet(models []AIModel) Sheet {
	header := []string{"Model", "Component Key"}
	rows := RowSource(func(emit func([]string) error) error {
		for _, m := range models {
			for _, dep := range m.Dependencies {
				if err := emit([]string{orNotProvided(m.Name), orNotProvided(dep)}); err != nil {
					return err
				}
			}
		}
		return nil
	})
	return Sheet{Name: "AI Model Dependencies", Header: header, Rows: rows, Width: 30}
}

// ─── PDF (minimum-bar treatment — see cbom.go for the shared scope decision) ─

// aibomInventoryPage replaces the generic componentPages() for an AIBOM —
// name, developer, licence and dataset count only, to fit the page budget.
// The full 19-column inventory is in the XLSX and JSON exports, which are
// not page-capped.
func (r *pdfRender) aibomInventoryPage() {
	r.doc.AddPage()
	r.heading("AI Models")
	r.note("Name, developer, licence and dataset count only, to fit the " +
		"page budget. The full Table 10 field set is in the XLSX and JSON exports.")
	r.doc.Ln(2)

	widths := []float64{50, 40, 30, 30}
	r.tableHeader([]string{"Model", "Developer", "Licence", "Datasets"}, widths)
	for i, m := range r.bom.AIModels {
		if r.overCap() {
			r.markTruncated("AI models", i, len(r.bom.AIModels))
			return
		}
		r.tableRow([]string{
			orNotProvided(m.Name),
			orNotProvided(m.Fields[model.FieldCertinAibom04ModelDeveloper]),
			orNotProvided(m.Fields[model.FieldCertinAibom05Licensing]),
			fmt.Sprintf("%d", len(m.Datasets)),
		}, widths)
	}
}
