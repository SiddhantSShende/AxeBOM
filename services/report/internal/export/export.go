// Package export serializes the canonical BOM to SPDX and CycloneDX.
//
// ⚠ protobom IS THE SERIALIZATION LAYER. WE DO NOT HAND-ROLL EITHER FORMAT.
//
// Both specs are large, both have version-specific quirks, and both are
// validated by tools we do not control. A hand-rolled writer passes our own
// tests and fails the customer's validator — and a compliance artifact that a
// standard validator rejects is worthless regardless of how correct its
// contents are.
//
// What this package owns is the MAPPING: canonical model -> protobom node
// graph. That is the part where a wrong decision produces a document that
// validates cleanly and says something false.
//
// ⚠ THE MAPPING NEVER INVENTS A VALUE.
//
// Where the canonical model has nothing, the field is left empty rather than
// defaulted to something plausible. `NOASSERTION` is emitted where SPDX
// requires a value and we have none — that is the format's own way of saying
// "not asserted", and it is different from claiming a licence we did not find.
//
// See docs/phases/PHASE-09-reports.md and docs/03-NORMALIZER-SPEC.md §6.
package export

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/protobom/protobom/pkg/formats"
	"github.com/protobom/protobom/pkg/sbom"
	"github.com/protobom/protobom/pkg/writer"
)

// Format is a serialization target.
type Format string

const (
	// SPDX23JSON is SPDX 2.3 in JSON. The format most compliance reviewers ask
	// for by name.
	SPDX23JSON Format = "spdx-2.3-json"
	// CycloneDX16JSON is CycloneDX 1.6 in JSON — the format CERT-In's
	// Automation Support element names alongside SPDX.
	CycloneDX16JSON Format = "cyclonedx-1.6-json"
)

// protobomFormat maps our name onto protobom's media-type constant.
func (f Format) protobomFormat() (formats.Format, error) {
	switch f {
	case SPDX23JSON:
		return formats.SPDX23JSON, nil
	case CycloneDX16JSON:
		return formats.CDX16JSON, nil
	default:
		return "", fmt.Errorf("unsupported export format %q", f)
	}
}

// MediaType is what the HTTP response and the artifact record carry.
func (f Format) MediaType() string {
	switch f {
	case SPDX23JSON:
		return "application/spdx+json"
	case CycloneDX16JSON:
		return "application/vnd.cyclonedx+json; version=1.6"
	default:
		return "application/json"
	}
}

// Component is the canonical model's component, reduced to what a standard
// document can carry.
type Component struct {
	Key         string
	Name        string
	VersionRaw  string
	Purl        string
	Ecosystem   string
	Supplier    string
	Description string

	// ⚠ Kept separate all the way to the writer. SPDX has distinct fields for
	// declared and concluded, and collapsing them here would throw away exactly
	// the distinction a compliance reviewer asks about.
	LicenseDeclared  string
	LicenseConcluded string

	Hashes    []Hash
	Locations []string
	CPEs      []string

	// ⚠ NOT a merge key and NOT an identifier any tool will resolve. Rendered
	// as a property so the CERT-In form is present in the document without
	// being mistaken for a PURL.
	CertInIdentifier string
}

// Hash is one digest of a component.
type Hash struct {
	Algorithm string
	Value     string
}

// Document is everything an export needs from the canonical model.
type Document struct {
	// ⚠ NOT read from a clock. Passed in from the scan record so the same
	// canonical model always serializes to the same bytes (ADR-0003).
	GeneratedAt string
	DocumentID  string
	ProjectName string

	Components []Component
	// From -> To, both component keys.
	Dependencies []Dependency
	// Component keys that are dependency roots. A monorepo has several.
	Roots []string

	ToolName    string
	ToolVersion string
}

// Dependency is one edge of the graph.
type Dependency struct {
	From string
	To   string
}

// Serialize renders the document in the requested format.
func Serialize(doc Document, format Format) ([]byte, error) {
	pbFormat, err := format.protobomFormat()
	if err != nil {
		return nil, err
	}

	bom, err := toProtobom(doc)
	if err != nil {
		return nil, fmt.Errorf("building the node graph: %w", err)
	}

	var buf bytes.Buffer
	w := writer.New()
	if err := w.WriteStreamWithOptions(bom, &buf, &writer.Options{Format: pbFormat}); err != nil {
		return nil, fmt.Errorf("serializing to %s: %w", format, err)
	}

	out, err := stabilize(buf.Bytes(), format, doc.GeneratedAt)
	if err != nil {
		return nil, err
	}

	return out, nil
}

// stabilize makes the serialized document byte-reproducible.
//
// ⚠ protobom's OUTPUT IS NOT DETERMINISTIC, AND WE REQUIRE THAT IT IS.
//
// Two independent causes, both measured against v0.5.8:
//
//  1. The SPDX serializer stamps `creationInfo.created` from `time.Now().UTC()`
//     (serializer_spdx23.go:171) with no option to supply it.
//  2. The CycloneDX serializer emits `components` in Go map order, so the array
//     is shuffled between runs.
//
// Neither matters for an ordinary tool. Both break the property this product
// rests on (ADR-0003): rendering is a deterministic function of stored inputs,
// so a report can be regenerated later and shown to be the same document. A
// signature over a shuffled document also fails verification for no reason.
//
// Array order carries no meaning in either format — `components`, `packages`
// and `relationships` are sets — so sorting them changes nothing a validator or
// a consumer can observe. The timestamp is different: it is corrected to the
// SCAN's time rather than the render's, because dating a re-render "now" would
// have the document claim to describe today.
func stabilize(data []byte, format Format, generatedAt string) ([]byte, error) {
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("re-reading the %s document to stabilize it: %w", format, err)
	}

	if format == SPDX23JSON {
		if info, ok := doc["creationInfo"].(map[string]any); ok && generatedAt != "" {
			if _, err := parseTimestamp(generatedAt); err == nil {
				info["created"] = generatedAt
			}
		}
	}

	sortDeep(doc)

	// encoding/json sorts map keys, so the round trip also removes any
	// key-order instability the library had.
	return json.Marshal(doc)
}

// sortDeep recursively sorts every array in the document.
//
// ⚠ TARGETED SORTING IS NOT ENOUGH, because the randomness is NESTED.
//
// protobom's `Node` stores identifiers and hashes as `map[int32]string`, so the
// shuffling appears inside each component — SPDX `externalRefs` alternates
// between purl-first and cpe-first, CycloneDX `hashes` between SHA-256-first and
// SHA-1-first. Sorting only the top-level `components` and `packages` arrays
// left both, and a two-run comparison agreed by luck often enough to look
// green. A 40-run check found it on the first iteration.
//
// ⚠ WHY SORTING EVERY ARRAY IS SAFE HERE, and where it would not be.
//
// In SPDX 2.3 and CycloneDX 1.6 JSON, the arrays are unordered collections:
// packages, files, relationships, components, dependencies, hashes,
// externalRefs, licenses, properties. None carries meaning in its ordering, so
// sorting changes nothing a validator or a consumer can observe.
//
// This would be WRONG for a format where array position is semantic — an
// ordered changelog, a layered filesystem, a sequence of operations. If a
// future format is added here, check that before reusing this.
func sortDeep(value any) {
	switch v := value.(type) {
	case map[string]any:
		for _, child := range v {
			sortDeep(child)
		}
	case []any:
		for _, child := range v {
			sortDeep(child)
		}
		// Sorted by canonical JSON so the key covers the whole element rather
		// than a field guessed in advance — which is how the nested arrays were
		// missed the first time.
		sort.SliceStable(v, func(i, j int) bool {
			return canonicalKey(v[i]) < canonicalKey(v[j])
		})
	}
}

// canonicalKey renders a value to a stable string for comparison.
//
// The children are already sorted when this runs, so marshalling is stable;
// encoding/json sorts map keys for us.
func canonicalKey(value any) string {
	data, err := json.Marshal(value)
	if err != nil {
		// Unmarshalled JSON always re-marshals, so this is unreachable in
		// practice. Returning a constant keeps the sort stable rather than
		// panicking inside a report render.
		return ""
	}
	return string(data)
}

// toProtobom maps the canonical model onto a protobom document.
//
// ⚠ DETERMINISTIC. Components and edges are sorted, and every map is emitted in
// sorted key order, so the same canonical model produces byte-identical output
// on every run and on every OS. Without that the golden tests flap, and a
// flapping test is one that gets ignored.
func toProtobom(doc Document) (*sbom.Document, error) {
	components := make([]Component, len(doc.Components))
	copy(components, doc.Components)
	sort.Slice(components, func(i, j int) bool { return components[i].Key < components[j].Key })

	bom := sbom.NewDocument()
	bom.Metadata.Id = doc.DocumentID
	bom.Metadata.Name = doc.ProjectName
	bom.Metadata.Date = nil // set below only if parseable
	bom.Metadata.Tools = []*sbom.Tool{{
		Name:    doc.ToolName,
		Version: doc.ToolVersion,
	}}

	if ts, err := parseTimestamp(doc.GeneratedAt); err == nil {
		bom.Metadata.Date = ts
	}

	for _, c := range components {
		node, err := toNode(c)
		if err != nil {
			return nil, err
		}
		bom.NodeList.AddNode(node)
	}

	// ⚠ Roots are declared explicitly, not inferred. A monorepo has N of them,
	// and letting the serializer guess would make every workspace package look
	// like a dependency of one imaginary parent.
	roots := append([]string(nil), doc.Roots...)
	sort.Strings(roots)
	bom.NodeList.RootElements = roots

	edges := append([]Dependency(nil), doc.Dependencies...)
	sort.Slice(edges, func(i, j int) bool {
		if edges[i].From != edges[j].From {
			return edges[i].From < edges[j].From
		}
		return edges[i].To < edges[j].To
	})

	byFrom := map[string][]string{}
	order := []string{}
	for _, e := range edges {
		if _, seen := byFrom[e.From]; !seen {
			order = append(order, e.From)
		}
		byFrom[e.From] = append(byFrom[e.From], e.To)
	}
	for _, from := range order {
		bom.NodeList.Edges = append(bom.NodeList.Edges, &sbom.Edge{
			Type: sbom.Edge_dependsOn,
			From: from,
			To:   byFrom[from],
		})
	}

	return bom, nil
}

func toNode(c Component) (*sbom.Node, error) {
	if c.Key == "" {
		return nil, fmt.Errorf("component %q has no key", c.Name)
	}

	node := &sbom.Node{
		Id:          c.Key,
		Type:        sbom.Node_PACKAGE,
		Name:        c.Name,
		Version:     c.VersionRaw,
		Description: c.Description,
	}

	// ⚠ SPDX distinguishes declared from concluded, so both survive.
	//
	// `Licenses` is the DECLARED list; `LicenseConcluded` is separate. Writing
	// the concluded value into both would assert that the manifest said what
	// the LICENSE file said, which is precisely the discrepancy a reviewer is
	// looking for.
	if c.LicenseDeclared != "" {
		node.Licenses = []string{c.LicenseDeclared}
	}
	node.LicenseConcluded = c.LicenseConcluded

	if c.Supplier != "" {
		node.Suppliers = []*sbom.Person{{Name: c.Supplier}}
	}

	node.Identifiers = map[int32]string{}
	if c.Purl != "" {
		node.Identifiers[int32(sbom.SoftwareIdentifierType_PURL)] = c.Purl
	}
	if len(c.CPEs) > 0 {
		cpes := append([]string(nil), c.CPEs...)
		sort.Strings(cpes)
		// Only one CPE fits the identifier map, so the rest become properties
		// rather than being dropped — a CPE we found and did not report is a
		// match a downstream tool cannot make.
		node.Identifiers[int32(sbom.SoftwareIdentifierType_CPE23)] = cpes[0]
		for _, extra := range cpes[1:] {
			node.Properties = append(node.Properties, &sbom.Property{
				Name: "axebom:cpe", Data: extra,
			})
		}
	}

	if len(c.Hashes) > 0 {
		node.Hashes = map[int32]string{}
		hashes := append([]Hash(nil), c.Hashes...)
		sort.Slice(hashes, func(i, j int) bool {
			if hashes[i].Algorithm != hashes[j].Algorithm {
				return hashes[i].Algorithm < hashes[j].Algorithm
			}
			return hashes[i].Value < hashes[j].Value
		})
		for _, h := range hashes {
			if alg, ok := hashAlgorithm(h.Algorithm); ok {
				node.Hashes[int32(alg)] = h.Value
			}
		}
	}

	// ⚠ THE CERT-In IDENTIFIER IS A PROPERTY, NEVER AN IDENTIFIER.
	//
	// `pkg:supplier/Org/Name@1.0` is not a resolvable PURL and no tool will
	// treat it as one. Putting it in the identifier map would make downstream
	// consumers try to resolve it and fail, or worse, dedup on it.
	if c.CertInIdentifier != "" {
		node.Properties = append(node.Properties, &sbom.Property{
			Name: "certin:unique_identifier",
			Data: c.CertInIdentifier,
		})
	}

	locations := append([]string(nil), c.Locations...)
	sort.Strings(locations)
	for _, loc := range locations {
		node.Properties = append(node.Properties, &sbom.Property{
			Name: "axebom:location", Data: loc,
		})
	}

	sort.Slice(node.Properties, func(i, j int) bool {
		if node.Properties[i].Name != node.Properties[j].Name {
			return node.Properties[i].Name < node.Properties[j].Name
		}
		return node.Properties[i].Data < node.Properties[j].Data
	})

	return node, nil
}

// hashAlgorithm maps our algorithm names onto protobom's enum.
//
// Unknown algorithms are DROPPED rather than guessed at. A hash under the wrong
// algorithm label is worse than no hash: a verifier will compute the wrong
// digest and report a mismatch on a file that is fine.
func hashAlgorithm(name string) (sbom.HashAlgorithm, bool) {
	switch strings.ToLower(strings.ReplaceAll(name, "-", "")) {
	case "sha1":
		return sbom.HashAlgorithm_SHA1, true
	case "sha256":
		return sbom.HashAlgorithm_SHA256, true
	case "sha512":
		return sbom.HashAlgorithm_SHA512, true
	case "md5":
		return sbom.HashAlgorithm_MD5, true
	default:
		return sbom.HashAlgorithm_UNKNOWN, false
	}
}
