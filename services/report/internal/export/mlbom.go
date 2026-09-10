package export

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

// ---------------------------------------------------------------------------
// CycloneDX ML-BOM — the AIBOM's real machine-readable form.
//
// ⚠ AIBOM ALREADY EXPORTED, AND WHAT IT EXPORTED WAS NOT AN ML-BOM.
//
// `toExportDocument` mapped every AI model onto a generic protobom component
// with `certin:aibom:*` properties. That produces a valid CycloneDX 1.6
// document — and a consumer looking for `modelCard` finds nothing, because
// protobom v0.5.8's `sbom.Node` has no ML fields at all (checked: the string
// `ModelCard` does not appear anywhere in the module). Every ML-aware tool
// therefore read our AIBOM as a list of unremarkable components.
//
// ⚠ AND THIS IS STILL NOT HAND-ROLLED JSON. `export.go`'s header says we do not
// hand-roll either format, and that reasoning does not stop being true for a
// third one: a writer that passes our tests and fails the customer's validator
// is worthless. `CycloneDX/cyclonedx-go` is the format's own Go library, it was
// already in the module graph as protobom's dependency, and it models the whole
// ML shape — `MLModelCard`, `MLModelParameters`, `ComponentData`. What this file
// owns is the MAPPING, which is the part where a wrong decision produces a
// document that validates cleanly and says something false.
//
// ⚠ `modelCard` IS OPTIONAL IN CycloneDX 1.5, 1.6 AND 1.7. A document with zero
// ML content validates as a perfect ML-BOM. Schema conformance is therefore NOT
// evidence of content, and the tests assert content — see
// `TestTheMLBOMCarriesAPopulatedModelCard`.
// ---------------------------------------------------------------------------

// MLDataset is one training dataset named on a model's card.
type MLDataset struct {
	Name    string
	Version string
	License string
	Source  string
	Format  string
}

// MLAsset is one AI component that is NOT a model — a prompt, a vector store, a
// RAG pipeline, an inference endpoint.
//
// ⚠ NO CERT-In TABLE 10 ELEMENT COVERS ANY OF THESE, and CycloneDX has no
// component type for most of them either. They are emitted with the closest
// honest type and their real kind on a namespaced property, never squeezed into
// a standard type that would misdescribe them.
type MLAsset struct {
	Type        string
	Key         string
	Name        string
	Provider    string
	ServesModel string
	Evidence    []string
}

// MLModel is one AI model, as the ML-BOM sees it.
type MLModel struct {
	Key      string
	Name     string
	Version  string
	Purl     string
	Task     string
	Licenses string
	Author   string

	Architectures []string
	Inputs        string
	Outputs       string
	Datasets      []MLDataset
	Dependencies  []string

	// The honesty fields. An ML-BOM that says what a model IS without saying how
	// well we know it is the half of the document a reviewer cannot check.
	Evidence           []string
	FoundBy            []string
	Verified           bool
	IdentityRule       string
	IdentityConfidence string

	// Considerations — the Table 10 elements no tool reports, which map onto
	// CycloneDX's own `considerations` block rather than onto properties.
	IntendedUsage        string
	OutOfScopeUsage      string
	SecurityRequirements string
	EnvironmentalImpact  string

	// Fields is the full Table 10 set keyed by profile-field id, emitted as
	// namespaced properties so nothing is lost in the mapping above.
	Fields map[string]string

	// AxeBOM extensions, namespaced apart because they are explicitly not
	// CERT-In elements and are excluded from both coverage numbers.
	RiskScore     *float64
	OwaspLLMTop10 []string
}

// MLDocument is everything the ML-BOM serializer needs.
type MLDocument struct {
	// ⚠ NOT READ FROM A CLOCK. Passed in from the scan record so the same
	// canonical model always serializes to the same bytes (ADR-0003).
	GeneratedAt string
	DocumentID  string
	ProjectName string
	ToolName    string
	ToolVersion string

	Models []MLModel
	Assets []MLAsset
}

// MLBOMFormat is the format name this serializer answers to.
const MLBOMFormat Format = "cyclonedx-mlbom-1.6-json"

// SerializeMLBOM writes a CycloneDX 1.6 ML-BOM.
//
// ⚠ REFUSES AN EMPTY DOCUMENT RATHER THAN EMITTING A VALID ONE. An ML-BOM with
// no models validates against the schema and asserts that a project contains no
// AI — the exact failure the generic AIBOM export already made once, where six
// downloadable artifacts said nothing. A caller with no models has nothing to
// serialize and should say so, not hand a customer a conformant empty file.
func SerializeMLBOM(doc MLDocument) ([]byte, error) {
	if len(doc.Models) == 0 && len(doc.Assets) == 0 {
		return nil, fmt.Errorf(
			"refusing to serialize an ML-BOM with no models and no AI assets: the " +
				"document would validate and assert that this project contains no AI")
	}

	bom := cdx.NewBOM()
	bom.SpecVersion = cdx.SpecVersion1_6
	// ⚠ ONLY WHEN IT IS ACTUALLY A UUID, AND THE OFFICIAL SCHEMA IS WHAT CAUGHT
	// THIS. CycloneDX pins `serialNumber` to an RFC-4122 URN; this emitted
	// `urn:uuid:` + whatever the document id was, so any non-UUID id produced a
	// document the spec's own validator rejects. A report id is a UUIDv7 in
	// production, which is exactly why the defect would have shipped: it would
	// have been correct on every real report and wrong on the first one that was
	// not. The field is optional, so omitting it is legal — emitting a malformed
	// one is not.
	if isUUID(doc.DocumentID) {
		bom.SerialNumber = "urn:uuid:" + strings.ToLower(doc.DocumentID)
	}
	bom.Metadata = &cdx.Metadata{
		Timestamp: doc.GeneratedAt,
		Tools: &cdx.ToolsChoice{
			Components: &[]cdx.Component{{
				Type:    cdx.ComponentTypeApplication,
				Name:    doc.ToolName,
				Version: doc.ToolVersion,
			}},
		},
		Component: &cdx.Component{
			BOMRef: "axebom:project",
			Type:   cdx.ComponentTypeApplication,
			Name:   orUnnamed(doc.ProjectName),
		},
	}

	components := make([]cdx.Component, 0, len(doc.Models)+len(doc.Assets))
	services := make([]cdx.Service, 0)
	deps := map[string]map[string]bool{}
	link := func(from, to string) {
		if deps[from] == nil {
			deps[from] = map[string]bool{}
		}
		deps[from][to] = true
	}

	for _, m := range doc.Models {
		ref := "axebom:model:" + m.Key
		components = append(components, mlModelComponent(ref, m))
		link("axebom:project", ref)

		for _, d := range m.Datasets {
			dref := ref + ":dataset:" + d.Name
			components = append(components, mlDatasetComponent(dref, d))
			// ⚠ CONTAINED BY THE MODEL, NOT DEPENDED ON. A training dataset is
			// part of what the model IS; a runtime dependency is something it
			// needs to run. CycloneDX has one edge kind, so the distinction has
			// to live in the containment direction.
			link(ref, dref)
		}
		// The SBOM component keys this model rests on. Emitted as dependency
		// edges to refs this document does not define, which is legal and is the
		// honest shape: the component is catalogued in the project's SBOM, not
		// here, and inventing a component entry for it would duplicate an
		// inventory that already exists.
		for _, key := range m.Dependencies {
			link(ref, key)
		}
	}

	for _, a := range doc.Assets {
		// ⚠ AN INFERENCE ENDPOINT IS A SERVICE, NOT A COMPONENT, and CycloneDX
		// has a `services` array for exactly this. `cdxgen -t ai` emits them
		// there too, so a consumer that reads one AI BOM reads both.
		if a.Type == "endpoint" {
			services = append(services, cdx.Service{
				BOMRef:   "axebom:service:" + a.Key,
				Name:     orUnnamed(a.Name),
				Provider: &cdx.OrganizationalEntity{Name: a.Provider},
				Properties: mlProperties(map[string]string{
					"axebom:aibom:asset_type":   a.Type,
					"axebom:aibom:serves_model": a.ServesModel,
					"axebom:aibom:evidence":     strings.Join(a.Evidence, ", "),
				}),
			})
			continue
		}
		aref := "axebom:asset:" + a.Key
		components = append(components, cdx.Component{
			BOMRef: aref,
			Type:   mlAssetType(a.Type),
			Name:   orUnnamed(a.Name),
			Properties: mlProperties(map[string]string{
				// ⚠ THE REAL KIND, ON A PROPERTY, BECAUSE THE STANDARD HAS NO
				// TYPE FOR IT. CycloneDX 1.6 has no `prompt` or `vector-store`
				// component type; emitting one of these as `data` and saying
				// nothing more would lose what it actually is.
				"axebom:aibom:asset_type": a.Type,
				"axebom:aibom:provider":   a.Provider,
				"axebom:aibom:evidence":   strings.Join(a.Evidence, ", "),
			}),
		})
		link("axebom:project", aref)
	}

	bom.Components = &components
	if len(services) > 0 {
		bom.Services = &services
	}
	bom.Dependencies = mlDependencies(deps)

	// ⚠ ENCODED WITH INDENTATION AND A STABLE ORDER, because a report is
	// downloaded, diffed and attached to tickets. `SetPretty` is the library's
	// own switch; the ordering is ours, above.
	var buf bytes.Buffer
	enc := cdx.NewBOMEncoder(&buf, cdx.BOMFileFormatJSON)
	enc.SetPretty(true)
	if err := enc.EncodeVersion(bom, cdx.SpecVersion1_6); err != nil {
		return nil, fmt.Errorf("encode ML-BOM: %w", err)
	}
	return buf.Bytes(), nil
}

func mlModelComponent(ref string, m MLModel) cdx.Component {
	c := cdx.Component{
		BOMRef:  ref,
		Type:    cdx.ComponentTypeMachineLearningModel,
		Name:    orUnnamed(m.Name),
		Version: substantive(m.Version),
		PackageURL: func() string {
			// ⚠ ONLY A REAL ONE. `model_key` carries a `purl:` prefix on its
			// top tier and something else on every other; emitting a
			// non-purl key here would put an unresolvable identifier in the
			// field a consumer resolves.
			if strings.HasPrefix(m.Purl, "pkg:") {
				return m.Purl
			}
			return ""
		}(),
	}
	// ⚠ FILTERED HERE TOO, NOT ONLY AT THE MAPPING LAYER. `toMLDocument` already
	// drops the sentinel, and this is the serializer every future caller reaches
	// through — a second caller that forgot would export `not-provided` as a
	// model's licence to every tool that reads the file.
	if author := substantive(m.Author); author != "" {
		c.Authors = &[]cdx.OrganizationalContact{{Name: author}}
	}
	if m.Licenses = substantive(m.Licenses); m.Licenses != "" {
		// ⚠ `Name`, NOT `ID`. A licence read off a model card is free text —
		// `llama3`, `apache-2.0`, `other` — and CycloneDX's `id` field means an
		// SPDX identifier. Putting an unvalidated string there would assert SPDX
		// membership we never checked.
		c.Licenses = &cdx.Licenses{{License: &cdx.License{Name: m.Licenses}}}
	}

	card := &cdx.MLModelCard{BOMRef: ref + ":card"}
	// ⚠ FILTERED HERE TOO, for the reason the licence above records: this is the
	// serializer every future caller reaches through, and one that forgot would
	// export `not-provided` as a model's task.
	params := &cdx.MLModelParameters{
		Task:              substantive(m.Task),
		ModelArchitecture: substantive(strings.Join(m.Architectures, ", ")),
	}
	if v := substantive(m.Inputs); v != "" {
		params.Inputs = &[]cdx.MLInputOutputParameters{{Format: v}}
	}
	if v := substantive(m.Outputs); v != "" {
		params.Outputs = &[]cdx.MLInputOutputParameters{{Format: v}}
	}
	if len(m.Datasets) > 0 {
		choices := make([]cdx.MLDatasetChoice, 0, len(m.Datasets))
		for _, d := range m.Datasets {
			// Referenced, not inlined: the dataset is a real component in this
			// document, and inlining it would state the same fact twice with
			// nothing keeping the two copies in step.
			choices = append(choices, cdx.MLDatasetChoice{Ref: ref + ":dataset:" + d.Name})
		}
		params.Datasets = &choices
	}
	// ⚠ OMITTED WHEN IT SAYS NOTHING. An empty `modelParameters: {}` is
	// schema-valid and is pure noise — and worse, it reads as a block somebody
	// filled in and left blank rather than as a fact nobody established.
	if params.Task != "" || params.ModelArchitecture != "" ||
		params.Inputs != nil || params.Outputs != nil || params.Datasets != nil {
		card.ModelParameters = params
	}

	// ⚠ THE OPERATOR'S ANSWERS BELONG IN `considerations`, NOT IN PROPERTIES.
	// CycloneDX models exactly this — what a model is for, what it must not be
	// used for, its limitations — and burying them in namespaced properties
	// would hide them from every tool that reads an ML-BOM properly.
	cons := &cdx.MLModelCardConsiderations{}
	if v := substantive(m.IntendedUsage); v != "" {
		cons.UseCases = &[]string{v}
	}
	limitations := []string{}
	if v := substantive(m.OutOfScopeUsage); v != "" {
		limitations = append(limitations, "Out of scope: "+v)
	}
	if v := substantive(m.SecurityRequirements); v != "" {
		limitations = append(limitations, "Security requirements: "+v)
	}
	if len(limitations) > 0 {
		cons.TechnicalLimitations = &limitations
	}
	if v := substantive(m.EnvironmentalImpact); v != "" {
		cons.EnvironmentalConsiderations = &cdx.MLModelCardEnvironmentalConsiderations{
			Properties: mlProperties(map[string]string{
				"certin:aibom:environmental_impact": v,
			}),
		}
	}
	if cons.UseCases != nil || cons.TechnicalLimitations != nil ||
		cons.EnvironmentalConsiderations != nil {
		card.Considerations = cons
	}
	c.ModelCard = card

	props := map[string]string{
		// ⚠ THE HONESTY HALF OF THE DOCUMENT. An ML-BOM that says what a model
		// IS without saying how well we know it leaves a reviewer nothing to
		// check. `verified` is emitted even when false — especially when false.
		"axebom:aibom:model_key":           m.Key,
		"axebom:aibom:identity_rule":       m.IdentityRule,
		"axebom:aibom:identity_confidence": m.IdentityConfidence,
		"axebom:aibom:verified":            strconv.FormatBool(m.Verified),
		"axebom:aibom:found_by":            strings.Join(m.FoundBy, ", "),
		"axebom:aibom:evidence":            strings.Join(m.Evidence, ", "),
	}
	// ⚠ THE PROFILE FIELD ID VERBATIM, NOT A SECOND PREFIX. The ids already read
	// `certin.aibom.01.model_name`; prefixing them again produced
	// `certin:aibom:certin.aibom.01.model_name`, which is a property name a
	// consumer has to know to strip. The id is globally unique and
	// self-describing on its own — that is what invariant 2's "render it from
	// the profile" buys.
	for id, v := range m.Fields {
		props[id] = v
	}
	if m.RiskScore != nil {
		props["axebom:aibom:risk_score"] = strconv.FormatFloat(*m.RiskScore, 'f', 2, 64)
	}
	if len(m.OwaspLLMTop10) > 0 {
		props["axebom:aibom:owasp_llm_top10"] = strings.Join(m.OwaspLLMTop10, ", ")
	}
	c.Properties = mlProperties(props)
	return c
}

func mlDatasetComponent(ref string, d MLDataset) cdx.Component {
	c := cdx.Component{
		BOMRef:  ref,
		Type:    cdx.ComponentTypeData,
		Name:    orUnnamed(d.Name),
		Version: d.Version,
	}
	if d.License != "" {
		c.Licenses = &cdx.Licenses{{License: &cdx.License{Name: d.License}}}
	}
	data := cdx.ComponentData{
		BOMRef: ref + ":data",
		Type:   cdx.ComponentDataType("dataset"),
		Name:   orUnnamed(d.Name),
	}
	if d.Source != "" {
		data.Contents = &cdx.ComponentDataContents{URL: d.Source}
	}
	c.Data = &[]cdx.ComponentData{data}
	return c
}

// mlAssetType maps an AxeBOM asset kind onto the closest honest CycloneDX type.
//
// ⚠ CycloneDX 1.6 HAS NO TYPE FOR MOST OF THESE, and inventing one is not an
// option — an unknown `type` fails the schema. A prompt is a piece of data; a
// vector store and a RAG pipeline are things that run. The real kind always
// travels on `axebom:aibom:asset_type` beside it, so the approximation here
// never loses information.
func mlAssetType(kind string) cdx.ComponentType {
	switch kind {
	case "prompt", "dataset":
		return cdx.ComponentTypeData
	case "vector_store", "rag_pipeline", "agent", "mcp_server":
		return cdx.ComponentTypeApplication
	case "tool":
		return cdx.ComponentTypeLibrary
	default:
		return cdx.ComponentTypeData
	}
}

// mlDependencies renders the edge set in a stable order.
//
// ⚠ SORTED, BECAUSE A REPORT IS DIFFED. Map iteration order is randomised in
// Go, so an unsorted graph makes two exports of one document differ — which
// destroys the replayability ADR-0003 rests on and makes every re-render look
// like a change.
func mlDependencies(deps map[string]map[string]bool) *[]cdx.Dependency {
	if len(deps) == 0 {
		return nil
	}
	froms := make([]string, 0, len(deps))
	for from := range deps {
		froms = append(froms, from)
	}
	sort.Strings(froms)

	out := make([]cdx.Dependency, 0, len(froms))
	for _, from := range froms {
		tos := make([]string, 0, len(deps[from]))
		for to := range deps[from] {
			tos = append(tos, to)
		}
		sort.Strings(tos)
		out = append(out, cdx.Dependency{Ref: from, Dependencies: &tos})
	}
	return &out
}

// mlProperties renders a property map in a stable order, dropping empties.
func mlProperties(m map[string]string) *[]cdx.Property {
	names := make([]string, 0, len(m))
	for name, value := range m {
		if strings.TrimSpace(value) != "" {
			names = append(names, name)
		}
	}
	if len(names) == 0 {
		return nil
	}
	sort.Strings(names)
	out := make([]cdx.Property, 0, len(names))
	for _, name := range names {
		out = append(out, cdx.Property{Name: name, Value: m[name]})
	}
	return &out
}

// substantive drops the explicit `not-provided` sentinel.
//
// ⚠ IT IS STORED AND IT IS NOT EXPORTED AS A VALUE. Invariant 3 requires the
// gap to be visible in OUR document; emitting the literal string
// "not-provided" as a model's intended use in a CycloneDX file would assert
// that as the answer to any tool reading it. Absence is how the standard says
// "not stated".
func substantive(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "", "not-provided", "noassertion", "unknown", "n/a", "none":
		return ""
	}
	return v
}

// isUUID reports whether v is an RFC-4122 UUID in canonical text form.
//
// Hand-rolled rather than pulling a parser in: the check is exactly the pattern
// CycloneDX's own schema applies, and matching the schema's rule is the point.
func isUUID(v string) bool {
	const groups = "8-4-4-4-12"
	v = strings.ToLower(v)
	want := []int{8, 4, 4, 4, 12}
	parts := strings.Split(v, "-")
	if len(parts) != len(want) {
		return false
	}
	for i, p := range parts {
		if len(p) != want[i] {
			return false
		}
		for _, r := range p {
			if !strings.ContainsRune("0123456789abcdef", r) {
				return false
			}
		}
	}
	_ = groups
	return true
}

func orUnnamed(v string) string {
	if strings.TrimSpace(v) == "" {
		// CycloneDX requires a component name. An empty one fails validation,
		// and a blank string in a report reads as a rendering bug rather than as
		// missing data.
		return "unnamed"
	}
	return v
}

// mlbomIsValidJSON is a cheap self-check used by the tests; kept here so the
// encoder and the check cannot drift apart.
func mlbomIsValidJSON(b []byte) bool {
	var v any
	return json.Unmarshal(b, &v) == nil
}
