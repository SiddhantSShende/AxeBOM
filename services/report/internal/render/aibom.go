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

	// ModelKey is the identity ladder's merge key — `purl:pkg:huggingface/…`,
	// `api:openai/gpt-4o`. Stable across normalizations, which a row id is not,
	// so it is what the ML-BOM's bom-refs and every cross-document reference are
	// built from.
	ModelKey string

	// FoundBy names every AIBOM engine that reported this model, from
	// normalize.ai_model_provenance.
	//
	// ⚠ ONE ENGINE OR THREE IS THE MOST USEFUL SINGLE FACT ON THE ROW, and it
	// was invisible before AxeBOM ran more than one AI discovery engine. Three
	// engines agreeing on `meta-llama/Llama-3-8B` and one engine alone reporting
	// `sentence-transformers/all-MiniLM-L6-v2` are different degrees of evidence,
	// and a reviewer weighing a Table 10 row is entitled to see which they have.
	FoundBy []string

	// Evidence is where the model was referenced, as `path:line`. Empty when no
	// engine reported a position — never a guessed one.
	Evidence []string

	// Verified is true only when an engine confirmed the model resolves
	// upstream.
	//
	// ⚠ IT NEVER DEFAULTS TO TRUE, and the report has to say which it is. A
	// model nobody could confirm is not a model somebody confirmed, and a Table
	// 10 inventory that renders both identically hides the difference that
	// matters most to a reviewer.
	Verified bool

	// IdentityRule and IdentityConfidence are which rung of the identity ladder
	// fired and what that is worth (03-NORMALIZER-SPEC §1.5). A `purl:` key at
	// high confidence and a `name:` key at low confidence are different degrees
	// of evidence for the same-looking row.
	IdentityRule       string
	IdentityConfidence string

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

// AIAsset is one AI component that is NOT a model and NOT a software
// dependency — a prompt, a vector store, a RAG pipeline, an inference endpoint.
//
// ⚠ IT HAS ITS OWN SHEET BECAUSE IT HAS NO HOME IN TABLE 10. CERT-In Table 10
// asks about MODELS; none of its 19 elements is a prompt or a vector store. That
// is a limit of the guideline, not of the scan — `airom` and `cdxgen-ai` find
// these with file:line evidence, and a report that stored them and rendered
// nothing would be the silence invariant 12 exists to prevent. They are
// inventory and evidence, and they are deliberately NOT scored into either
// coverage number: see normalize/pipeline.py.
type AIAsset struct {
	// Type is one of normalize.ai_assets' closed set — prompt, vector_store,
	// rag_pipeline, embedding, agent, tool, mcp_server, endpoint, dataset.
	Type string
	// Key is the merge key the normalizer minted — `prompt:src/app.py:9`. It is
	// what a bom-ref is built from in the ML-BOM export: a ref derived from a
	// display name would not survive two prompts sharing one.
	Key         string
	Name        string
	Provider    string
	Evidence    []string
	ServesModel string
	FoundBy     []string
}

// AIBOMSheets are the AIBOM-specific sheets, appended in place of the
// generic componentSheet Sheets() builds for every other type.
func AIBOMSheets(b BOM, fields []model.ProfileField) []Sheet {
	return []Sheet{
		aiModelInventorySheet(b.AIModels, fields),
		aiDatasetSheet(b.AIModels),
		aiDependencySheet(b.AIModels),
		aiAssetSheet(b.AIAssets),
	}
}

// aiAssetSheet lists the prompts, vector stores, RAG pipelines and inference
// endpoints the AI engines found.
//
// ⚠ AN EMPTY SHEET IS STILL RENDERED, DELIBERATELY. A reader who sees no sheet
// cannot tell "this repository has no prompts" from "this product does not look
// for prompts". The sheet with a header and no rows says the first.
func aiAssetSheet(assets []AIAsset) Sheet {
	header := []string{"Type", "Name", "Provider", "Serves Model", "Evidence", "Found By"}
	rows := RowSource(func(emit func([]string) error) error {
		for _, a := range assets {
			if err := emit([]string{
				orNotProvided(a.Type), orNotProvided(a.Name), orNotProvided(a.Provider),
				orNotProvided(a.ServesModel), joinList(a.Evidence), joinList(a.FoundBy),
			}); err != nil {
				return err
			}
		}
		return nil
	})
	return Sheet{Name: "AI Assets", Header: header, Rows: rows, Width: 26}
}

func aiModelInventorySheet(models []AIModel, fields []model.ProfileField) Sheet {
	header := []string{"Model"}
	for _, f := range fields {
		header = append(header, f.Name)
	}
	header = append(header,
		// ⚠ NOT A TABLE 10 ELEMENT, AND NOT AN AxeBOM HEURISTIC EITHER — it is
		// a plain record of which engines reported this row. Three engines
		// agreeing and one engine alone are different degrees of evidence.
		"Found By (engines)",
		"Evidence",
		"Identity",
		"Verified upstream",
		"Risk Score (AxeBOM extension)", "OWASP LLM Top-10 (AxeBOM extension)")

	rows := RowSource(func(emit func([]string) error) error {
		for _, m := range models {
			row := []string{orNotProvided(m.Name)}
			for _, f := range fields {
				// ⚠ EXPLICIT, NEVER BLANK — same reasoning as componentSheet's
				// identical line: a blank cell reads as "we did not look".
				row = append(row, orNotProvided(m.Fields[f.ID]))
			}
			row = append(row,
				joinList(m.FoundBy), joinList(m.Evidence),
				identityText(m),
				// ⚠ RENDERED AS "no", NOT LEFT BLANK. An unverified model and a
				// verified one must not look the same, and a blank cell reads as
				// a rendering gap rather than as an answer.
				boolText(m.Verified),
				riskScoreText(m.RiskScore), joinList(m.OwaspLLMTop10))
			if err := emit(row); err != nil {
				return err
			}
		}
		return nil
	})

	return Sheet{Name: "AI Models", Header: header, Rows: rows, Width: 22}
}

// identityText says which rung of the ladder produced this row's key.
func identityText(m AIModel) string {
	switch {
	case m.IdentityRule == "" && m.IdentityConfidence == "":
		return model.NotProvided
	case m.IdentityConfidence == "":
		return m.IdentityRule
	default:
		return m.IdentityRule + " (" + m.IdentityConfidence + " confidence)"
	}
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
