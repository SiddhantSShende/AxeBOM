// Package policy resolves which engines run for a scan, and refuses
// combinations that cannot work.
//
// ⚠ THE POINT OF THIS PACKAGE IS TO FAIL AT CREATE TIME.
//
// Discovering at worker time that cbomkit-theia cannot process an `image`
// source — twenty minutes into a scan, after a fetch and a container start — is
// a design failure. Every combination is checked when the scan is created, and
// a bad one is a 422 listing EVERY offending pair, not the first one found.
//
// Listing every pair matters: a user who fixes the one error they were shown,
// resubmits, and hits the next one has been made to do the work twice.
package policy

import (
	"fmt"
	"sort"
	"strings"

	"github.com/axebom/axebom/libs/go-shared/events"
	"github.com/axebom/axebom/libs/go-shared/platform/errs"
)

// Engine describes one scanner as a unit of work.
//
// ⚠ THE UNIT IS (TOOL, MODE), NOT TOOL.
//
// `trivy fs` and `trivy image` have different capabilities and different output
// parsers, so they are DIFFERENT ENGINES with different ids. Treating them as
// one tool with a flag makes the registry lie about what can scan what.
type Engine struct {
	ID       string          `json:"engine_id"`
	Families []events.Family `json:"families"`
	// SourceKinds is what this engine can actually read. The source of most
	// invalid combinations.
	SourceKinds []events.SourceKind `json:"source_kinds"`
	Ecosystems  []string            `json:"ecosystems"`
	Produces    []string            `json:"produces"`

	NativeFormat string   `json:"native_format"`
	Requires     []string `json:"requires,omitempty"`

	// Mode is how this engine actually runs: "container" (the sandbox, per
	// CLAUDE.md invariant #7), "pip" (installed into the worker's own Python
	// environment — unsandboxed, and only ever a discovery/enrichment step
	// that never touches customer code with network access), or "internal"
	// (no OSINT tool at all — hbom-csv and qbom-derive are AxeBOM's own
	// import/derivation logic, not a third party engine). Mirrors
	// OSINT/tools.manifest.yaml's per-tool `mode`, kept here as data (like
	// RequiresImport/Derived below) so the UI's Engine Coverage panel never
	// has to guess or hardcode it.
	Mode string `json:"mode"`

	// DBBacked engines need a vulnerability database, which means they need
	// either a pre-warmed volume or egress. It is also why they must report
	// engine_db_version — a finding that cannot be dated is not defensible.
	DBBacked bool `json:"db_backed"`

	// DefaultWeight is this engine's share of the scan's progress percentage.
	// dependency-check taking 40 minutes and syft taking 20 seconds should not
	// contribute equally to a progress bar.
	DefaultWeight int `json:"default_weight"`

	// GraphTrust ranks this engine's dependency graph per ecosystem; higher
	// wins. Consumed by the normalizer (03-NORMALIZER-SPEC), which REPLACES an
	// ecosystem's subgraph rather than unioning — unioning invents phantom
	// transitive edges.
	GraphTrust map[string]int `json:"graph_trust,omitempty"`

	// Honest labels, carried as data so the UI cannot imply otherwise.
	//
	// RequiresImport: there is no HBOM scanner. It is a CSV/form import.
	RequiresImport bool `json:"requires_import,omitempty"`

	// Scaffold marks an engine that exists to exercise the machinery, not to
	// scan anything. It is NEVER part of a family's default engine set.
	//
	// ⚠ `mock-engine` WAS IN THE DEFAULT SBOM SET AND RAN ON EVERY CUSTOMER
	// SCAN. It is the Phase 6 fake — `workers/_mock/main.go` — and it is not
	// deployed, so it left a permanent `skipped` row in the Engine Coverage
	// section of every SBOM report: 20 of them in the dev database. That
	// section exists to tell a customer what could not be seen (invariant 12),
	// and a row naming a scanner that does not exist is the opposite of that.
	//
	// Get() still returns it, so a test that names it explicitly — or a tenant
	// override — still resolves. Only ForFamily skips it, which is what makes
	// it invisible to a real scan while staying usable by the tests that prove
	// idempotency and status derivation against the same code path.
	Scaffold bool `json:"-"`

	// OperatorAction is what a PERSON has to do for this engine to have
	// anything to read. Empty for every engine that just runs.
	//
	// ⚠ IT EXISTS BECAUSE THE INSTRUCTION REACHED NOBODY. `hbom-cdxgen-host`
	// and `hbom-host-report` parse a file the customer produces on the device
	// they want documented — and the only place that was written down was
	// OSINT/tools.manifest.yaml (which no browser reads) and an adapter's
	// ENGINE_INPUT_MISSING hint, which appears AFTER a scan has already run and
	// found nothing. A customer had no way to learn the feature existed, let
	// alone how to use it.
	//
	// Deliberately not a general `notes` field: a free-form notes column
	// becomes a dumping ground and then nothing renders it. This one answers a
	// single question — "what do I do?" — so the UI can show it as an
	// instruction next to the engine it belongs to.
	OperatorAction string `json:"operator_action,omitempty"`
	// Derived: QBOM crypto assets come from CBOM discovery with
	// quantum-vulnerability rules applied. There is no quantum-hardware
	// scanner.
	Derived bool `json:"derived,omitempty"`

	// ConsumesOutputOf names an engine whose output this one reads.
	//
	// ⚠ DISTINCT FROM Requires, WHICH IS A CAPABILITY ("vuln_db"). This is an
	// ORDERING constraint between two jobs in the same scan, and it changes
	// when the job may be published rather than whether the engine can run.
	//
	// grype is the case: it matches against OUR syft SBOM rather than
	// cataloguing the tree itself, because re-scanning would produce a second,
	// subtly different component inventory to reconcile — exactly the work the
	// normalizer exists to avoid.
	//
	// Without this the fan-out published all six jobs at once and grype
	// routinely ran BEFORE syft, reporting `skipped` on every real scan for an
	// input that was still being produced.
	ConsumesOutputOf string `json:"consumes_output_of,omitempty"`

	// ConsumesNativeSBOM marks an engine whose job needs
	// ScanJobV1.Workspace.NativeSBOMRef populated — a native document a
	// PRODUCER (the fetcher or services/webrecon) staged, not another
	// engine's job output, so this is orthogonal to ConsumesOutputOf and
	// needs no ordering wait: the producer phase is always complete before
	// FanOut runs at all.
	//
	// Two engines set this today: github-dependency-graph-sbom (fed by the
	// fetcher) and webrecon-fingerprint (fed by services/webrecon). A second
	// bool rather than overloading RequiresImport, because the two answer
	// different questions — RequiresImport is the honest-label claim "there
	// is no scanner here, this is an import" (true for hbom-csv too, which is
	// never dispatched at all, and for github-dependency-graph-sbom; NOT true
	// for webrecon-fingerprint, which performs real discovery, just not
	// inside a sandboxed container job of its own); this is the dispatch-time
	// instruction "wire this specific artifact into this specific job."
	ConsumesNativeSBOM bool `json:"consumes_native_sbom,omitempty"`
}

// Supports reports whether this engine can read a source kind.
func (e Engine) Supports(kind events.SourceKind) bool {
	for _, k := range e.SourceKinds {
		if k == kind {
			return true
		}
	}
	return false
}

// InFamily reports whether this engine belongs to a family.
func (e Engine) InFamily(f events.Family) bool {
	for _, x := range e.Families {
		if x == f {
			return true
		}
	}
	return false
}

// Registry is the set of known engines.
//
// Built-in defaults live here as DATA; per-tenant overrides come from the
// scan.engine_policy table, so changing which engines run for a family is a
// data change rather than a deploy.
type Registry struct {
	engines map[string]Engine
}

// DefaultRegistry returns the built-in engine set from
// docs/02-CONTRACTS.md §7.
func DefaultRegistry() *Registry {
	list := []Engine{
		{
			ID:          "syft",
			Mode:        "container",
			Families:    []events.Family{events.FamilySBOM},
			SourceKinds: []events.SourceKind{events.SourceGit, events.SourceUpload, events.SourceImage},
			Ecosystems:  []string{"npm", "pypi", "maven", "golang", "gem", "cargo", "nuget", "deb", "rpm", "apk", "conan", "swift"},
			Produces:    []string{"components", "licenses"},
			// ⚠ CycloneDX, NOT SPDX. This said "spdx-json-2.3" while
			// SyftAdapter.build_argv asks for CycloneDX on stdout and the
			// manifest records `native_format: cyclonedx-json-1.6` with
			// `also_emits: [spdx-json-2.3]`. The Engine Coverage panel renders
			// this field, so it told the reader the wrong thing about which
			// document syft actually produced. The SPDX pass is syft-spdx,
			// directly below.
			NativeFormat:  "cyclonedx-json-1.6",
			DefaultWeight: 3,
			GraphTrust:    map[string]int{"npm": 2, "pypi": 2, "golang": 3, "maven": 2},
		},
		{
			// ⚠ SYFT'S SECOND PASS, AND IT WAS IMPLEMENTED AND UNREACHABLE.
			//
			// SyftSPDXAdapter, its entry in workers/sbom/runner.py's ADAPTERS,
			// the SPDX branch of normalize/ingest.py and a smoke fixture all
			// existed — but the engine was in neither the manifest nor this
			// registry. Resolve() only ever selects registry engines, so it
			// could never be dispatched; EnginePolicyUpsert rejected it as
			// "not valid for family"; and it could never appear in an Engine
			// Coverage section. CERT-In's Automation Support minimum element
			// asks for BOTH formats.
			//
			// It is a separate engine rather than a second flag on syft
			// because syft writes ONE format to stdout, and every sandbox
			// mount is read-only by design, so there is no second file to
			// collect. The cost is one extra pass over the already-fetched
			// tree, no network, on an image that is already pulled for syft —
			// which is why its weight is 1 and not 3.
			ID:            "syft-spdx",
			Mode:          "container",
			Families:      []events.Family{events.FamilySBOM},
			SourceKinds:   []events.SourceKind{events.SourceGit, events.SourceUpload, events.SourceImage},
			Ecosystems:    []string{"npm", "pypi", "maven", "golang", "gem", "cargo", "nuget", "deb", "rpm", "apk", "conan", "swift"},
			Produces:      []string{"components", "licenses"},
			NativeFormat:  "spdx-json-2.3",
			DefaultWeight: 1,
		},
		{
			ID:           "grype",
			Mode:         "container",
			Families:     []events.Family{events.FamilySBOM},
			SourceKinds:  []events.SourceKind{events.SourceGit, events.SourceUpload, events.SourceImage},
			Ecosystems:   []string{"npm", "pypi", "maven", "golang", "gem", "cargo", "nuget", "deb", "rpm", "apk"},
			Produces:     []string{"vulnerabilities"},
			NativeFormat: "cyclonedx-json-1.6",
			Requires:     []string{"vuln_db"},
			// grype matches against OUR SBOM, never a re-scan. Its job is held
			// back until syft reports.
			ConsumesOutputOf: "syft",
			DBBacked:         true,
			DefaultWeight:    3,
		},
		{
			// trivy-fs and trivy-image are SEPARATE engines: different
			// invocation, different parser, different source kinds.
			ID:            "trivy-fs",
			Mode:          "container",
			Families:      []events.Family{events.FamilySBOM},
			SourceKinds:   []events.SourceKind{events.SourceGit, events.SourceUpload},
			Ecosystems:    []string{"npm", "pypi", "maven", "golang", "gem", "cargo", "nuget", "deb", "rpm", "apk"},
			Produces:      []string{"components", "vulnerabilities", "licenses", "secrets"},
			NativeFormat:  "cyclonedx-json-1.6",
			Requires:      []string{"vuln_db"},
			DBBacked:      true,
			DefaultWeight: 3,
			GraphTrust:    map[string]int{"npm": 2, "pypi": 2, "maven": 1},
		},
		{
			ID:            "trivy-image",
			Mode:          "container",
			Families:      []events.Family{events.FamilySBOM},
			SourceKinds:   []events.SourceKind{events.SourceImage},
			Ecosystems:    []string{"deb", "rpm", "apk", "npm", "pypi", "golang"},
			Produces:      []string{"components", "vulnerabilities", "licenses"},
			NativeFormat:  "cyclonedx-json-1.6",
			Requires:      []string{"vuln_db"},
			DBBacked:      true,
			DefaultWeight: 3,
		},
		{
			ID:            "osv-scanner",
			Mode:          "container",
			Families:      []events.Family{events.FamilySBOM},
			SourceKinds:   []events.SourceKind{events.SourceGit, events.SourceUpload},
			Ecosystems:    []string{"npm", "pypi", "maven", "golang", "gem", "cargo", "nuget"},
			Produces:      []string{"vulnerabilities"},
			NativeFormat:  "osv-json",
			Requires:      []string{"vuln_db"},
			DBBacked:      true,
			DefaultWeight: 2,
		},
		{
			ID:           "dependency-check",
			Mode:         "container",
			Families:     []events.Family{events.FamilySBOM},
			SourceKinds:  []events.SourceKind{events.SourceGit, events.SourceUpload},
			Ecosystems:   []string{"maven", "npm", "nuget", "pypi", "golang"},
			Produces:     []string{"vulnerabilities"},
			NativeFormat: "dependency-check-json",
			Requires:     []string{"vuln_db", "nvd_api_key"},
			DBBacked:     true,
			// Lower weight despite being slow: its identification is CPE-based
			// and lower confidence, so it contributes less to a merged result.
			DefaultWeight: 1,
		},
		{
			// HONEST LABEL: not discovery. A GitHub repository's own
			// CI-published Dependency Graph SBOM, imported and cross-checked
			// against every other engine's independent inventory — never
			// authoritative on its own. See docs/04-OSINT-INTEGRATION.md.
			//
			// Mode "internal" like hbom-csv/qbom-derive, but UNLIKE them this
			// engine is genuinely dispatched: its family (sbom) has other,
			// real scanners, so ValidateCombination never rejects it as
			// SCAN_FAMILY_NOT_DIRECTLY_SCANNABLE, and its job runs the normal
			// FanOut path — workers/sbom/adapters/github_dependency_graph.py
			// does local artifact I/O only, no sandbox, no network of its own.
			ID:                 "github-dependency-graph-sbom",
			Mode:               "internal",
			Families:           []events.Family{events.FamilySBOM},
			SourceKinds:        []events.SourceKind{events.SourceGit},
			Ecosystems:         []string{"generic"},
			Produces:           []string{"components"},
			NativeFormat:       "spdx-json-2.3",
			DefaultWeight:      1,
			RequiresImport:     true,
			ConsumesNativeSBOM: true,
		},
		{
			// The ONLY sbom engine offered for a url source (see
			// docs/04-OSINT-INTEGRATION.md's webrecon roster row). Its job
			// carries no source archive — a url source has none — only
			// Workspace.NativeSBOMRef, populated from services/webrecon's own
			// discovery + JS-fingerprint document. Mode "internal": there is no
			// sandboxed container run of its own; the network-touching work
			// already happened in services/webrecon, itself sandboxed
			// (subfinder) or SafeHTTPClient-guarded (the page/script fetches),
			// and this engine only parses the JSON that produced. Not
			// RequiresImport — unlike github-dependency-graph-sbom this is real
			// discovery, not a foreign document AxeBOM never generated.
			ID:                 "webrecon-fingerprint",
			Mode:               "internal",
			Families:           []events.Family{events.FamilySBOM},
			SourceKinds:        []events.SourceKind{events.SourceURL},
			Ecosystems:         []string{"npm"},
			Produces:           []string{"components"},
			NativeFormat:       "axebom-webrecon-json-1",
			DefaultWeight:      1,
			ConsumesNativeSBOM: true,
		},
		{
			// A second independent generator alongside syft, Apache-2.0 and
			// actively maintained. Its ecosystem coverage genuinely exceeds
			// syft's in several languages, and the normalizer is built to
			// reconcile two inventories of the same tree rather than trust one
			// — which is the whole reason more than one generator is useful.
			//
			// GraphTrust is deliberately BELOW syft's everywhere the two
			// overlap: the normalizer REPLACES an ecosystem's subgraph by
			// trust rank rather than unioning (03-NORMALIZER-SPEC), and syft
			// is the engine this codebase has actually run against real
			// projects. cdxgen ranks above it in nothing until it has.
			ID:            "cdxgen",
			Mode:          "container",
			Families:      []events.Family{events.FamilySBOM},
			SourceKinds:   []events.SourceKind{events.SourceGit, events.SourceUpload},
			Ecosystems:    []string{"npm", "pypi", "maven", "golang", "gem", "cargo", "nuget", "swift", "dart", "elixir", "php", "ruby"},
			Produces:      []string{"components", "licenses"},
			NativeFormat:  "cyclonedx-json-1.6",
			DefaultWeight: 3,
			GraphTrust:    map[string]int{"npm": 1, "pypi": 1, "maven": 1, "golang": 1},
		},
		{
			ID:            "cbomkit-theia",
			Mode:          "container",
			Families:      []events.Family{events.FamilyCBOM},
			SourceKinds:   []events.SourceKind{events.SourceGit, events.SourceUpload, events.SourceImage},
			Ecosystems:    []string{"generic"},
			Produces:      []string{"crypto_assets"},
			NativeFormat:  "cyclonedx-json-1.6",
			DefaultWeight: 3,
		},
		{
			ID:            "cbomkit",
			Mode:          "container",
			Families:      []events.Family{events.FamilyCBOM},
			SourceKinds:   []events.SourceKind{events.SourceGit},
			Ecosystems:    []string{"java", "python"},
			Produces:      []string{"crypto_assets"},
			NativeFormat:  "cyclonedx-json-1.6",
			DefaultWeight: 2,
		},
		{
			ID:            "aibom-generator",
			Mode:          "pip",
			Families:      []events.Family{events.FamilyAIBOM},
			SourceKinds:   []events.SourceKind{events.SourceGit, events.SourceUpload},
			Ecosystems:    []string{"huggingface", "pypi"},
			Produces:      []string{"ai_models"},
			NativeFormat:  "cyclonedx-json-1.6",
			DefaultWeight: 3,
		},
		{
			// ⚠ "container", NOT "pip", AND THE REGISTRY WAS THE ONE THAT WAS
			// WRONG. Upstream publishes ai-bom only as a pip package, so this
			// field was set from that fact — but AxeBOM does not consume it
			// that way: deploy/docker/engines/Dockerfile.ai-bom wraps it into a
			// locally-built image, AIBomAdapter is a SandboxedAdapter, and the
			// manifest and docs/04-OSINT-INTEGRATION.md both say container.
			//
			// This field feeds the UI's Engine Coverage panel, so the
			// disagreement rendered as a claim that a sandboxed engine runs
			// unsandboxed in the worker's own Python environment — the opposite
			// of the truth, on the panel whose whole job is being precise.
			ID:            "ai-bom",
			Mode:          "container",
			Families:      []events.Family{events.FamilyAIBOM},
			SourceKinds:   []events.SourceKind{events.SourceGit, events.SourceUpload},
			Ecosystems:    []string{"pypi"},
			Produces:      []string{"ai_models"},
			NativeFormat:  "cyclonedx-json-1.6",
			DefaultWeight: 2,
		},
		{
			// HONEST LABEL: not a scanner. A structured CSV/form import plus a
			// data model. The UI must never imply discovery.
			//
			// ⚠ SourceKinds IS DELIBERATELY EMPTY, AND THAT IS WHAT KEEPS IT
			// OUT OF FAN-OUT.
			//
			// This engine id names the interactive REST path — POST
			// /v1/hbom/preview then /v1/hbom/{projectId}/import — not a job.
			// It used to declare `upload`, which was harmless only because the
			// whole hbom family was refused at scan-create time. `hbom-ecad`
			// makes the family scannable, and Resolve() filters candidates on
			// Supports(kind) ALONE — it does not look at RequiresImport — so a
			// declared source kind would have started publishing real
			// scan.job.hbom jobs for an engine no worker implements, putting a
			// permanent `skipped`/ENGINE_NOT_IMPLEMENTED row in the Engine
			// Coverage section of every HBOM scan. That section is the one
			// place invariant 12 promises is precise.
			//
			// Filtering RequiresImport inside Resolve() would have been the
			// wrong fix: github-dependency-graph-sbom carries that same flag
			// and IS dispatched on every git SBOM scan. The flag is an honest
			// label about where data came from, not a statement about
			// dispatch. An empty SourceKinds says the dispatch thing exactly.
			//
			// Resolve() still records it in SkippedForSource, so it stays
			// visible rather than vanishing — and hbom-ecad reports
			// `hardware` as COVERED, which is what stops that record turning
			// into a false "no engine for this ecosystem" line (see
			// Store.CoverageGaps).
			ID: "hbom-csv",
			// Found by TestEveryHBOMEngineTellsTheCustomerWhatToProduce at the
			// same time as hbom-ecad's: this engine is reached from the
			// Hardware tab rather than from a scan, but the Engine Coverage
			// section still names it, and a reader who sees it there needs to
			// know it is a thing they DO rather than a scanner that failed.
			OperatorAction: "Import your parts list from the project's Hardware tab — " +
				"a CSV, TSV or Excel export from your PLM, ERP or spreadsheet. " +
				"This is an import you perform, not a scan: AxeBOM reads the file " +
				"you provide and never examines a physical device.",
			Mode:           "internal",
			Families:       []events.Family{events.FamilyHBOM},
			SourceKinds:    nil,
			Ecosystems:     []string{"hardware"},
			Produces:       []string{"hardware_components"},
			NativeFormat:   "csv",
			DefaultWeight:  1,
			RequiresImport: true,
		},
		{
			// ⚠ NOT DISCOVERY OF A DEVICE. NOTHING HERE LOOKS AT HARDWARE.
			//
			// This parses the customer's OWN hardware DESIGN files — KiCad
			// schematics and netlists, EAGLE schematics, and BOM exports from
			// KiCad, Altium and OrCAD — out of an upload or a connected
			// repository. It is the
			// exact analogue of parsing package-lock.json for an SBOM: a
			// design artifact the customer wrote, read as data.
			//
			// It is the first HBOM engine that is neither an import of a
			// foreign document nor a derivation, which is precisely what makes
			// the hbom family scannable at all: rejectNonScannableFamilies
			// refuses a family only when EVERY engine in it is metadata-only,
			// so this entry flips HBOM without that function being touched.
			//
			// Mode "internal" like webrecon-fingerprint: native parsing, no
			// container, no manifest-pinned third-party tool.
			//
			// ⚠ Ecosystems MUST INCLUDE "hardware" AND THE ADAPTER MUST REPORT
			// IT COVERED. hbom-csv above is recorded as unavailable for
			// `hardware` at create time; CoverageGaps only neutralises that
			// with a matching available=true row, which comes from this
			// engine's GenerateResult.ecosystems_covered.
			ID:   "hbom-ecad",
			Mode: "internal",
			// ⚠ THE ENGINE READ FOUR FORMATS AND SAID SO NOWHERE. Every other
			// HBOM engine publishes an OperatorAction telling the customer what
			// to produce; this one — the only HBOM engine that reads a
			// REPOSITORY rather than an upload — published nothing, so a
			// customer whose design files were in an unsupported format saw
			// only "no hardware design files were found" after the scan.
			// Naming the formats before the scan is the difference between a
			// gap they can close and one they conclude is a product limit.
			OperatorAction: "Commit your hardware design files to the repository: a " +
				"KiCad schematic (.kicad_sch) or netlist (.net/.xml), an EAGLE " +
				"schematic (.sch), or a BOM export as CSV/TSV from KiCad, Altium " +
				"or OrCAD. AxeBOM reads the design you committed — it never " +
				"examines a physical board.",
			Families:      []events.Family{events.FamilyHBOM},
			SourceKinds:   []events.SourceKind{events.SourceGit, events.SourceUpload},
			Ecosystems:    []string{"hardware"},
			Produces:      []string{"hardware_components"},
			NativeFormat:  "axebom-hbom-json-1",
			DefaultWeight: 3,
		},
		{
			// HONEST LABEL: an IMPORT of a document the CUSTOMER produced by
			// running `cdxgen -t hbom` on their own device. AxeBOM never
			// touches the device and never claims to have inventoried one.
			//
			// cdxgen's hbom command inventories THE HOST IT RUNS ON — board,
			// firmware, TPM, storage, NIC — as CycloneDX 1.7. Running it
			// inside our sandbox would document AxeBOM's own container host
			// and present it as the customer's hardware, which is why this is
			// an upload path and never a container engine.
			//
			// RequiresImport says all of that as data — the same claim
			// github-dependency-graph-sbom makes about GitHub's published
			// SBOM, and like that engine this one IS dispatched.
			ID:   "hbom-cdxgen-host",
			Mode: "internal",
			OperatorAction: "Run `cdxgen -t hbom -o hbom.json` on the device you want " +
				"documented, then upload that file to the project. AxeBOM never runs it " +
				"— run inside our sandbox it would inventory our own container host and " +
				"present that as your hardware.",
			Families:       []events.Family{events.FamilyHBOM},
			SourceKinds:    []events.SourceKind{events.SourceUpload},
			Ecosystems:     []string{"hardware"},
			Produces:       []string{"hardware_components"},
			NativeFormat:   "cyclonedx-json-1.7",
			DefaultWeight:  2,
			RequiresImport: true,
		},
		{
			// HONEST LABEL: the same import as hbom-cdxgen-host above, widened
			// to the tools people actually have installed — lshw, dmidecode,
			// fwupdmgr, PowerShell's CIM cmdlets, a Redfish service's JSON.
			// Requiring one specific tool means most customers have nothing to
			// upload; this asks only that they ran SOMETHING on the machine.
			//
			// AxeBOM runs none of them. Each inventories THE MACHINE IT RUNS
			// ON, so invoking one in our sandbox would document AxeBOM's own
			// container host and present it as the customer's hardware.
			//
			// ⚠ ONE ENGINE, FIVE PARSERS. Resolve fans out a job per engine, so
			// five engines over one upload would leave four `unavailable` rows
			// in the Engine Coverage section of somebody who ran one tool —
			// reading as four broken things rather than one working one.
			// workers/hbom/adapters/hostreport.py dispatches internally and
			// records which parser matched.
			ID:   "hbom-host-report",
			Mode: "internal",
			OperatorAction: "Run one of these ON the machine you want documented and upload " +
				"the output: `axebom collect hardware` (ours, needs nothing installed), " +
				"`lshw -json`, `dmidecode`, `fwupdmgr get-devices --json`, PowerShell's " +
				"Get-CimInstance, or a Redfish export. AxeBOM runs none of them; it " +
				"cannot reach your machine.",
			Families:       []events.Family{events.FamilyHBOM},
			SourceKinds:    []events.SourceKind{events.SourceUpload},
			Ecosystems:     []string{"hardware"},
			Produces:       []string{"hardware_components"},
			NativeFormat:   "axebom-hbom-json-1",
			DefaultWeight:  2,
			RequiresImport: true,
		},
		{
			// HONEST LABEL: QBOM is largely a DERIVATION from CBOM crypto
			// assets. Only Table 8 device metadata is separately captured.
			ID:            "qbom-derive",
			Mode:          "internal",
			Families:      []events.Family{events.FamilyQBOM},
			SourceKinds:   []events.SourceKind{events.SourceGit, events.SourceUpload, events.SourceImage},
			Ecosystems:    []string{"generic"},
			Produces:      []string{"quantum_components"},
			NativeFormat:  "cyclonedx-json-1.6",
			DefaultWeight: 1,
			Derived:       true,
		},
		{
			// The Phase 6 mock. Registered so the machinery can be exercised
			// end to end before any real adapter exists — and so the tests that
			// prove idempotency and status derivation run against the same code
			// path a real engine will.
			ID:            "mock-engine",
			Scaffold:      true,
			Mode:          "internal",
			Families:      []events.Family{events.FamilySBOM},
			SourceKinds:   []events.SourceKind{events.SourceGit, events.SourceUpload, events.SourceImage},
			Ecosystems:    []string{"npm", "pypi"},
			Produces:      []string{"components"},
			NativeFormat:  "cyclonedx-json-1.6",
			DefaultWeight: 1,
		},
	}

	r := &Registry{engines: make(map[string]Engine, len(list))}
	for _, e := range list {
		r.engines[e.ID] = e
	}
	return r
}

// Get returns an engine by id.
func (r *Registry) Get(id string) (Engine, bool) {
	e, ok := r.engines[id]
	return e, ok
}

// IDs returns every registered engine id, sorted.
func (r *Registry) IDs() []string {
	out := make([]string, 0, len(r.engines))
	for id := range r.engines {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// ForFamily returns the engines in a family, sorted by id for determinism.
func (r *Registry) ForFamily(f events.Family) []Engine {
	var out []Engine
	for _, e := range r.engines {
		// Scaffolds are reachable by id and never by default — see Engine.Scaffold.
		if e.InFamily(f) && !e.Scaffold {
			out = append(out, e)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// ---------------------------------------------------------------------------
// Combination validation
// ---------------------------------------------------------------------------

// OffendingPair is one engine/source combination that cannot work.
type OffendingPair struct {
	Engine     string `json:"engine"`
	SourceKind string `json:"source_kind"`
	Reason     string `json:"reason"`
	// Suggestion names a viable alternative where one exists, so the error is
	// actionable rather than merely correct.
	Suggestion string `json:"suggestion,omitempty"`
}

// ValidateCombination checks every requested engine against the source kind.
//
// ⚠ RETURNS EVERY OFFENDING PAIR, NOT THE FIRST.
//
// Returning one at a time makes the user resubmit for each error in turn. The
// error carries the whole list so one correction fixes everything.
func (r *Registry) ValidateCombination(engineIDs []string, kind events.SourceKind,
	families []events.Family,
) error {
	var offending []OffendingPair
	var unknown []string

	for _, id := range engineIDs {
		engine, ok := r.Get(id)
		if !ok {
			unknown = append(unknown, id)
			continue
		}

		if !engine.Supports(kind) {
			// ⚠ NO SOURCE KINDS AT ALL IS A DIFFERENT FACT FROM THE WRONG ONE,
			// and it deserves a different sentence.
			//
			// "cannot read an upload source; it supports nothing" is true and
			// useless — it reads like a misconfiguration. An engine with an
			// empty SourceKinds is deliberately unreachable from fan-out
			// because it names an interactive path rather than a job
			// (hbom-csv, whose work happens at POST /v1/hbom/{projectId}/import).
			// Saying so is what makes the 422 actionable, which is this
			// package's whole stated reason for existing.
			reason := fmt.Sprintf("%s cannot read a %s source; it supports %s",
				id, kind, joinKinds(engine.SourceKinds))
			if len(engine.SourceKinds) == 0 {
				reason = fmt.Sprintf("%s is not a scan engine — it reads no source kind "+
					"because its work happens through an interactive import endpoint, "+
					"not a scan job", id)
			}
			offending = append(offending, OffendingPair{
				Engine: id, SourceKind: string(kind),
				Reason:     reason,
				Suggestion: r.suggestFor(kind, engine.Families),
			})
			continue
		}

		if len(families) > 0 {
			var inRequested bool
			for _, f := range families {
				if engine.InFamily(f) {
					inRequested = true
					break
				}
			}
			if !inRequested {
				offending = append(offending, OffendingPair{
					Engine: id, SourceKind: string(kind),
					Reason: fmt.Sprintf("%s produces %s, which is not among the requested BOM types",
						id, joinFamilies(engine.Families)),
				})
			}
		}
	}

	if len(unknown) == 0 && len(offending) == 0 {
		return nil
	}

	err := errs.New(errs.ScanEngineCombinationInvalid, buildCombinationMessage(unknown, offending))
	for _, p := range offending {
		err = err.WithDetail(errs.Detail{
			"engine": p.Engine, "source_kind": p.SourceKind,
			"reason": p.Reason, "suggestion": p.Suggestion,
		})
	}
	for _, id := range unknown {
		err = err.WithDetail(errs.Detail{
			"engine": id,
			"reason": "unknown engine id",
			"known":  strings.Join(r.IDs(), ", "),
		})
	}
	return err
}

// suggestFor names an engine in the same family that CAN read this source kind.
func (r *Registry) suggestFor(kind events.SourceKind, families []events.Family) string {
	var candidates []string
	for _, f := range families {
		for _, e := range r.ForFamily(f) {
			if e.Supports(kind) {
				candidates = append(candidates, e.ID)
			}
		}
	}
	if len(candidates) == 0 {
		return ""
	}
	sort.Strings(candidates)
	return "use " + strings.Join(dedupe(candidates), " or ") + " for this source kind"
}

func buildCombinationMessage(unknown []string, offending []OffendingPair) string {
	var parts []string
	if len(unknown) > 0 {
		parts = append(parts, fmt.Sprintf("unknown engine(s): %s", strings.Join(unknown, ", ")))
	}
	if len(offending) > 0 {
		names := make([]string, 0, len(offending))
		for _, p := range offending {
			names = append(names, p.Engine)
		}
		parts = append(parts, fmt.Sprintf("%d engine/source combination(s) cannot work: %s",
			len(offending), strings.Join(names, ", ")))
	}
	return strings.Join(parts, "; ") +
		". Every offending pair is listed in the error details, so one correction fixes all of them."
}

// ---------------------------------------------------------------------------
// Resolution
// ---------------------------------------------------------------------------

// Resolution is the outcome of resolving families into engines.
type Resolution struct {
	// Engines are the engines that will run, in a deterministic order.
	Engines []Engine
	// SkippedForSource are engines in a requested family that cannot read this
	// source kind.
	//
	// SKIPPED, NOT AN ERROR — and RECORDED. "SBOM for a container image" is a
	// legitimate request that simply excludes trivy-fs, and the exclusion must
	// reach the Engine Coverage section rather than vanishing.
	SkippedForSource []OffendingPair
}

// Resolve turns requested families into the engines that will run.
//
// A family with no usable engine for this source kind produces an EMPTY result
// rather than an error. The caller decides what to do — usually record it as an
// ecosystem with no available engine, which is exactly the honest denominator
// the Engine Coverage section exists to publish.
func (r *Registry) Resolve(families []events.Family, kind events.SourceKind,
	overrides map[events.Family][]string,
) Resolution {
	var res Resolution
	seen := map[string]bool{}

	for _, f := range families {
		candidates := r.ForFamily(f)

		// A tenant override replaces the default set for that family. Data,
		// not code — changing which engines run must not need a deploy.
		if ids, ok := overrides[f]; ok {
			candidates = nil
			for _, id := range ids {
				if e, found := r.Get(id); found {
					candidates = append(candidates, e)
				}
			}
		}

		for _, e := range candidates {
			if seen[e.ID] {
				continue
			}
			if !e.Supports(kind) {
				res.SkippedForSource = append(res.SkippedForSource, OffendingPair{
					Engine: e.ID, SourceKind: string(kind),
					Reason: fmt.Sprintf("%s cannot read a %s source", e.ID, kind),
				})
				continue
			}
			seen[e.ID] = true
			res.Engines = append(res.Engines, e)
		}
	}

	sort.Slice(res.Engines, func(i, j int) bool { return res.Engines[i].ID < res.Engines[j].ID })
	return res
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func joinKinds(kinds []events.SourceKind) string {
	out := make([]string, 0, len(kinds))
	for _, k := range kinds {
		out = append(out, string(k))
	}
	if len(out) == 0 {
		return "nothing"
	}
	return strings.Join(out, ", ")
}

func joinFamilies(families []events.Family) string {
	out := make([]string, 0, len(families))
	for _, f := range families {
		out = append(out, strings.ToUpper(string(f)))
	}
	return strings.Join(out, ", ")
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
