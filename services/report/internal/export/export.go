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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/protobom/protobom/pkg/formats"
	"github.com/protobom/protobom/pkg/mod"
	"github.com/protobom/protobom/pkg/native"
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

	// PrimaryPurpose is what KIND of thing this is, in the standards' own
	// vocabulary: "" for ordinary software, "device" for a hardware component,
	// "firmware" for firmware.
	//
	// ⚠ THIS IS WHAT MAKES A HARDWARE BOM A HARDWARE BOM RATHER THAN A LIST OF
	// LIBRARIES. It becomes CycloneDX `type: device` and SPDX
	// `primaryPackagePurpose: DEVICE`. Without it a consumer reads a gateway's
	// parts list as software dependencies — the document would validate and
	// mean something false.
	PrimaryPurpose string

	// Manufacturer is who MADE the part, kept separate from Supplier, who SOLD
	// it. SPDX and CycloneDX both distinguish them (originator vs supplier),
	// and CERT-In Table 11 lists both because supply-chain provenance is the
	// point of §10.2.1. Collapsing them would assert that a distributor
	// manufactured a microcontroller.
	Manufacturer string

	// Properties carry facts the standards have no field for.
	//
	// ⚠ NAMESPACED, AND NEVER IDENTIFIERS. Reference designators, DNP flags,
	// lifecycle status and prices are real and belong in the document, but a
	// consumer must not mistake any of them for something resolvable. Same
	// treatment `certin:unique_identifier` already gets.
	Properties []Property
}

// Property is one namespaced name/value pair on a component.
type Property struct {
	Name  string
	Value string
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
	// Kind is the relationship. Empty means "depends on", which is every
	// software edge.
	//
	// ⚠ "contains" IS NOT A SYNONYM FOR "depends on". A board CONTAINS a
	// capacitor: remove it and you have a different physical object. A program
	// DEPENDS ON a library: remove it and the program stops working.
	//
	// ⚠ AND ONLY SPDX ACTUALLY CARRIES THE DISTINCTION. Verified against real
	// output, not assumed:
	//
	//   SPDX 2.3   emits a genuine `relationshipType: CONTAINS`.
	//   CycloneDX  flattens it to `dependencies[].dependsOn`. protobom's CDX
	//              serializer ignores Edge.Type entirely (buildDependencies in
	//              serializer_cdx.go, v0.5.8), and CycloneDX 1.6's dependency
	//              graph has no containment relationship to map onto anyway —
	//              the spec expresses assembly through NESTED components[],
	//              which a flat protobom NodeList cannot produce.
	//
	// So the CycloneDX form says "dependsOn" where it means "contains". Rather
	// than leave a reader to guess, the caller emits an explicit
	// `axebom:hbom:parent` property alongside; see worker.hardwareProperties.
	// This is recorded here rather than fixed because fixing it means either
	// post-processing serialized JSON (which would break the byte-reproducibility
	// ADR-0003 requires) or replacing protobom.
	Kind string
}

// KindContains marks an assembly relationship rather than a dependency.
const KindContains = "contains"

// Serialize renders the document in the requested format.
func Serialize(doc Document, format Format) ([]byte, error) {
	pbFormat, err := format.protobomFormat()
	if err != nil {
		return nil, err
	}

	bom, err := toProtobom(doc, format)
	if err != nil {
		return nil, fmt.Errorf("building the node graph: %w", err)
	}

	// ⚠ MULTIROOT_HEADLESS IS NOT A WORKAROUND, IT IS THE HONEST DOCUMENT.
	//
	// A component-only scan with no resolved dependency graph (no lockfile —
	// see the Roots doc comment on render.BOM) has no single subject to put in
	// CycloneDX's metadata.component: every component is independently a root.
	// Without this mod, protobom's CDX writer refuses a document with more
	// than one root outright. With it, protobom drops metadata.component and
	// emits every root as its own top-level component — a standard, valid
	// "headless" CycloneDX BOM, not an invented hierarchy. It is a documented
	// no-op whenever there is exactly one root (the ordinary case, and SPDX's
	// serializer ignores it entirely), so enabling it unconditionally changes
	// nothing for the common path.
	serializeOpts := &native.SerializeOptions{
		Mods: map[mod.Mod]struct{}{mod.CYCLONEDX_MULTIROOT_HEADLESS: {}},
	}

	var buf bytes.Buffer
	w := writer.New()
	if err := w.WriteStreamWithOptions(bom, &buf, &writer.Options{
		Format:           pbFormat,
		SerializeOptions: serializeOpts,
	}); err != nil {
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
func toProtobom(doc Document, format Format) (*sbom.Document, error) {
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
		node, err := toNode(c, idFor(format, c.Key))
		if err != nil {
			return nil, err
		}
		bom.NodeList.AddNode(node)
	}

	// ⚠ Roots are declared explicitly, not inferred. A monorepo has N of them,
	// and letting the serializer guess would make every workspace package look
	// like a dependency of one imaginary parent.
	roots := make([]string, len(doc.Roots))
	for i, r := range doc.Roots {
		roots[i] = idFor(format, r)
	}
	sort.Strings(roots)
	bom.NodeList.RootElements = roots

	edges := append([]Dependency(nil), doc.Dependencies...)
	for i := range edges {
		edges[i].From = idFor(format, edges[i].From)
		edges[i].To = idFor(format, edges[i].To)
	}
	sort.Slice(edges, func(i, j int) bool {
		if edges[i].From != edges[j].From {
			return edges[i].From < edges[j].From
		}
		if edges[i].Kind != edges[j].Kind {
			return edges[i].Kind < edges[j].Kind
		}
		return edges[i].To < edges[j].To
	})

	// ⚠ GROUPED BY (from, KIND), NOT BY from ALONE. protobom's Edge carries one
	// type for its whole `To` list, so a component that both contains parts and
	// depends on libraries needs two edges. Grouping on `from` only would file
	// every target under whichever kind was seen first and quietly restate the
	// relationship for the rest.
	type edgeKey struct{ from, kind string }
	byFrom := map[edgeKey][]string{}
	order := []edgeKey{}
	for _, e := range edges {
		key := edgeKey{from: e.From, kind: e.Kind}
		if _, seen := byFrom[key]; !seen {
			order = append(order, key)
		}
		byFrom[key] = append(byFrom[key], e.To)
	}
	for _, key := range order {
		edgeType := sbom.Edge_dependsOn
		if key.kind == KindContains {
			edgeType = sbom.Edge_contains
		}
		bom.NodeList.Edges = append(bom.NodeList.Edges, &sbom.Edge{
			Type: edgeType,
			From: key.from,
			To:   byFrom[key],
		})
	}

	return bom, nil
}

// idFor derives the node/edge-reference identifier for a component key in
// the given format.
//
// ⚠ SPDXID GRAMMAR IS NOT PURL GRAMMAR.
//
// CycloneDX's bom-ref has no character restriction, so it keeps using the
// component key unchanged — that already validates. SPDX 2.3 permits only
// letters, digits, '.' and '-' in an SPDXID (spdx/tools-golang's ElementID
// does zero sanitization — it just prefixes "SPDXRef-" onto whatever string
// it is given), and a PURL-shaped component key (colons, slashes, '@', '?')
// violates that on every real component. SPDX gets a derived identifier
// instead; the PURL itself is untouched and keeps living correctly in
// node.Identifiers[PURL] regardless of format.
func idFor(format Format, key string) string {
	if format == SPDX23JSON {
		return spdxSafeID(key)
	}
	return key
}

// spdxSafeID derives an SPDX-2.3-grammar-legal identifier from a component
// key: a sanitized slug for readability, plus a short hash suffix of the
// full original key for collision-safety (two components that sanitize to
// the same slug must not collide). Deterministic — never a random UUID — so
// the same canonical model always serializes to the same SPDXID (ADR-0003
// replayability).
func spdxSafeID(key string) string {
	var b strings.Builder
	dash := false
	for _, r := range key {
		switch {
		case (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '.' || r == '-':
			b.WriteRune(r)
			dash = false
		case !dash:
			b.WriteByte('-')
			dash = true
		}
	}
	slug := strings.Trim(b.String(), "-")
	if len(slug) > 96 {
		slug = strings.Trim(slug[:96], "-")
	}
	sum := sha256.Sum256([]byte(key))
	suffix := hex.EncodeToString(sum[:6])
	if slug == "" {
		return suffix
	}
	return slug + "-" + suffix
}

func toNode(c Component, nodeID string) (*sbom.Node, error) {
	if c.Key == "" {
		return nil, fmt.Errorf("component %q has no key", c.Name)
	}

	node := &sbom.Node{
		Id:          nodeID,
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

	// ⚠ IsOrg, BECAUSE Yageo IS NOT A PERSON. protobom's SPDX serializer writes
	// `Person: <name>` for a Person and `Organization: <name>` for an org, and
	// a compliance document that files STMicroelectronics as a person is
	// wrong in a way a reader will notice and an auditor may question.
	if c.Supplier != "" {
		node.Suppliers = []*sbom.Person{{Name: c.Supplier, IsOrg: true}}
	}
	// ⚠ Originators, NOT a second Suppliers entry. SPDX calls the maker the
	// originator and the seller the supplier, and Table 11 lists both because
	// supply-chain provenance is the entire point of §10.2.1.
	//
	// ⚠ THIS SURVIVES INTO SPDX AND IS DROPPED BY CycloneDX. protobom's CDX
	// serializer reads Suppliers and never reads Originators (verified in
	// serializer_cdx.go at v0.5.8), so the manufacturer would silently vanish
	// from the CycloneDX form of a hardware BOM — the single most important
	// supply-chain field in it. The caller therefore ALSO emits it as a
	// namespaced property; see worker.hardwareProperties. Belt and braces on
	// purpose: the property is not a substitute for the structured field where
	// the structured field works.
	if c.Manufacturer != "" {
		node.Originators = []*sbom.Person{{Name: c.Manufacturer, IsOrg: true}}
	}
	if purpose, ok := purposeFor(c.PrimaryPurpose); ok {
		node.PrimaryPurpose = []sbom.Purpose{purpose}
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

	for _, p := range c.Properties {
		if p.Name == "" || p.Value == "" {
			continue
		}
		node.Properties = append(node.Properties, &sbom.Property{Name: p.Name, Data: p.Value})
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

// purposeFor maps our vocabulary onto protobom's Purpose enum.
//
// ⚠ AN UNKNOWN PURPOSE IS DROPPED, NEVER GUESSED. protobom's serializers turn
// a Purpose into a CycloneDX component `type` and an SPDX
// `primaryPackagePurpose`; a wrong one is a machine-readable assertion about
// what kind of thing a component IS, which is worse than saying nothing.
func purposeFor(name string) (sbom.Purpose, bool) {
	switch name {
	case "device":
		return sbom.Purpose_DEVICE, true
	case "firmware":
		return sbom.Purpose_FIRMWARE, true
	case "application":
		// The component a CBOM or AIBOM DESCRIBES — the project itself. See
		// worker.subjectKey for why one has to be declared.
		return sbom.Purpose_APPLICATION, true
	case "machine-learning-model":
		// CycloneDX `machine-learning-model`; SPDX has no equivalent purpose,
		// so an SPDX package carries the Table 10 elements as properties and
		// nothing else claims to type it.
		return sbom.Purpose_MACHINE_LEARNING_MODEL, true
	case "data":
		// A training or evaluation dataset. Distinct from the model itself, and
		// CycloneDX has the type for it.
		return sbom.Purpose_DATA, true
	case "cryptographic-asset":
		// ⚠ THE CLOSEST HONEST ANSWER, NOT THE RIGHT ONE, AND THE DIFFERENCE IS
		// RECORDED RATHER THAN HIDDEN.
		//
		// CycloneDX 1.6 has a `cryptographic-asset` component type and it is
		// exactly what a CBOM contains. protobom v0.5.8's Purpose enum has no
		// member for it and its writer's switch has no branch that emits it, so
		// there is no way to ask for one.
		//
		// Leaving the purpose unset is worse than choosing: protobom then falls
		// back to `application`, publishing that an RSA key is a runnable
		// program. Purpose_OTHER serializes as CycloneDX `data`, which is at
		// least true of a key or a certificate and is not an assertion about
		// executability. The real type always travels as
		// `certin:crypto:asset_type`, and docs/LIMITATIONS.md records the gap.
		return sbom.Purpose_OTHER, true
	case "":
		return sbom.Purpose_UNKNOWN_PURPOSE, false
	default:
		return sbom.Purpose_UNKNOWN_PURPOSE, false
	}
}
