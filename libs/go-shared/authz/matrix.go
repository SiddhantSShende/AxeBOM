// Package authz decides who may do what.
//
// docs/05-SECURITY-MODEL.md §6.
//
// THE DESIGN RULE: authorization is a MATRIX, not scattered `if role == ...`
// checks. Scattered checks fail open — the check that was never written allows
// everything, and nothing tells you it is missing. A matrix fails closed: an
// endpoint with no entry is DENIED, and TestAuthzMatrix names it.
//
// The second rule is subtler and matters more:
//
//	CROSS-TENANT ACCESS IS 404, NEVER 403.
//
// A 403 confirms the resource exists. An attacker enumerating UUIDs learns
// which ones are real, which is itself the leak. Authorization answers "may
// this role do this?"; tenancy is answered separately by Postgres RLS, and a
// row that RLS filters out simply does not exist as far as the handler is
// concerned.
package authz

import (
	"fmt"
	"sort"
	"strings"
)

// Role within a tenant. Ordered least- to most-privileged.
type Role string

const (
	RoleViewer  Role = "viewer"
	RoleAnalyst Role = "analyst"
	RoleAdmin   Role = "admin"
	RoleOwner   Role = "owner"
)

// AllRoles in privilege order.
func AllRoles() []Role { return []Role{RoleViewer, RoleAnalyst, RoleAdmin, RoleOwner} }

// Valid reports whether r is a known role.
func (r Role) Valid() bool {
	for _, k := range AllRoles() {
		if k == r {
			return true
		}
	}
	return false
}

// rank orders roles for the `atLeast` helper.
func (r Role) rank() int {
	switch r {
	case RoleViewer:
		return 1
	case RoleAnalyst:
		return 2
	case RoleAdmin:
		return 3
	case RoleOwner:
		return 4
	default:
		return 0
	}
}

// RoleAtLeast reports whether actor holds at least the privilege of want.
//
// This is NOT a substitute for Allow — the matrix decides permissions, and
// privilege is deliberately not a single ladder for every action. It exists
// for the one question a matrix cell cannot express: may this actor grant THIS
// role to somebody else?
//
// Without that check an Admin invites a new Owner, signs in as them, and has
// escalated. Any endpoint that assigns a role must call it.
//
// An unknown role ranks 0, so it is never "at least" anything: unparseable
// input fails closed.
func RoleAtLeast(actor, want Role) bool {
	return actor.rank() >= want.rank() && actor.rank() > 0
}

// Resource is a protected noun.
type Resource string

const (
	ResourceTenant    Resource = "tenant"
	ResourceMember    Resource = "member"
	ResourceProject   Resource = "project"
	ResourcePractices Resource = "practices"
	ResourceRepoConn  Resource = "repo_connection"
	ResourceUpload    Resource = "upload"
	// ResourceWebSource is a project registered by URL (project.web_sources).
	// Kept distinct from ResourceRepoConn — there is no credential and no
	// provider — even though the two share the same sensitivity tier today;
	// see ResourceRepoConn's own cells for the reasoning this mirrors.
	ResourceWebSource  Resource = "web_source"
	ResourceScan       Resource = "scan"
	ResourceDependency Resource = "dependency"
	ResourceFinding    Resource = "finding"
	ResourceVEX        Resource = "vex"
	// ResourceCSAF is the CSAF 2.0 advisory a VEX statement is published as
	// (normalize.csaf_advisories). Kept distinct from ResourceVEX: reading
	// or publishing an advisory is a different action from triaging the
	// finding behind it, even though today both happen at the same roles.
	ResourceCSAF      Resource = "csaf"
	ResourceReport    Resource = "report"
	ResourceShareLink Resource = "share_link"
	ResourceComment   Resource = "comment"
	ResourceCampaign  Resource = "campaign"
	ResourceAuditLog  Resource = "audit_log"
	ResourceEngine    Resource = "engine"
	// ResourceHardware is HBOM: import, structured entry and part lookup.
	// Distinct from ResourceUpload — an HBOM import is stored as a component
	// tree the moment it is confirmed, not a raw file, and part lookup calls
	// a third-party commercial API on the tenant's behalf, which a plain
	// upload never does.
	ResourceHardware Resource = "hardware"
	// ResourceQuantumDevice is QBOM Table 8 device metadata: captured by
	// form, never scanned (there is no quantum-hardware scanner). Kept
	// distinct from ResourceHardware rather than reused — the two BOM types
	// happen to share a read/write sensitivity today (see the matrix cells
	// below), but they are different CERT-In tables owned by different
	// forms, and collapsing them would make a future divergence (e.g. a
	// per-tenant policy that restricts quantum data specifically) require
	// splitting the resource back out under load rather than by design.
	ResourceQuantumDevice Resource = "quantum_device"
	// ResourceCryptoAsset is CBOM's crypto-asset inventory
	// (normalize.crypto_assets) — discovered by cbomkit-theia, read-only from
	// this API today (no user-editable crypto asset exists, unlike HBOM/QBOM
	// which are captured by form). Kept distinct from ResourceDependency:
	// that resource is SBOM's software-component inventory specifically, and
	// the two are different tables scored against different CERT-In tables
	// (§4.2 vs Table 9) even though both are read-only discovery results.
	ResourceCryptoAsset Resource = "crypto_asset"
	// ResourceAIModel is AIBOM's model inventory (normalize.ai_models) —
	// discovered by workers/aibom, mostly read-only from this API like
	// ResourceCryptoAsset. Unlike crypto assets, four of its nineteen CERT-In
	// elements (security requirements, intended usage, out-of-scope usage,
	// attestation) ARE user-editable — no tool can ever report what a model
	// is for or must not be used for — so this resource, alone among the
	// read-only discovery resources, also grants ActionUpdate.
	ResourceAIModel Resource = "ai_model"
	// ResourceAIPolicy is a project's consent to send code to a third-party
	// LLM — `ai-bom --llm-enrich` and `cisco-aibom --llm-model`
	// (aibom.project_policy).
	//
	// ⚠ ITS OWN RESOURCE, NOT AN ACTION ON ResourceAIModel, AND THE REASON IS
	// THE BLAST RADIUS. Editing what a model is FOR changes one row of a
	// compliance document; consenting to LLM enrichment sends the customer's
	// SOURCE to a third party for every future scan of that project. Those are
	// not the same decision and must not share a permission — an Analyst may
	// do the first and only an Admin the second.
	ResourceAIPolicy Resource = "ai_policy"
	// ResourceAITag is an operator's EU AI Act / NIST AI RMF / ISO 42001
	// classification (aibom.compliance_tags). A declaration a named person
	// makes, never something AxeBOM infers — see model.EUAIActTiers.
	ResourceAITag Resource = "ai_tag"
	// ResourceAIAttestation is a recorded model-signature verification RESULT
	// (aibom.attestations).
	ResourceAIAttestation Resource = "ai_attestation"
	// ResourceAPIKey is a long-lived bearer credential (libs/go-shared/auth's
	// apikey.go). Deliberately Owner-only, not Admin like member management:
	// a key's scopes can run scans, read reports and triage VEX across the
	// whole tenant unattended, which is the tenant-deletion trust tier, not
	// the ordinary-admin one.
	ResourceAPIKey Resource = "api_key"
)

// Action is a verb applied to a Resource.
type Action string

const (
	ActionRead   Action = "read"
	ActionList   Action = "list"
	ActionCreate Action = "create"
	ActionUpdate Action = "update"
	ActionDelete Action = "delete"

	// Actions distinct enough to warrant their own row.
	ActionRun      Action = "run"      // trigger a scan or campaign
	ActionDownload Action = "download" // fetch a rendered report
	ActionShare    Action = "share"    // mint a share link
	ActionTriage   Action = "triage"   // set VEX status
	ActionInvite   Action = "invite"
	ActionCancel   Action = "cancel" // stop a running scan or campaign
	// ActionEnableRiskyResolution turns on package-manager resolution, which
	// EXECUTES arbitrary code from the scanned repository (npm lifecycle
	// scripts, Gradle build files). Deliberately separate from `update`:
	// accepting that risk is not an ordinary project edit.
	ActionEnableRiskyResolution Action = "enable_risky_resolution"
	// ActionConfigureEngines sets which engines run for a BOM family
	// (scan.engine_policy), tenant-wide. Deliberately separate from `update`
	// for the same reason as ActionEnableRiskyResolution: it changes what
	// code executes on every future scan in that family, not one project's
	// settings.
	ActionConfigureEngines Action = "configure_engines"
)

// Permission identifies one cell of the matrix.
type Permission struct {
	Resource Resource
	Action   Action
}

func (p Permission) String() string { return string(p.Resource) + ":" + string(p.Action) }

// rule is one matrix row.
type rule struct {
	// minRole is the least-privileged role permitted. Most rows are a simple
	// threshold, which keeps the matrix readable.
	minRole Role
	// conditional marks a permission whose answer depends on the RESOURCE, not
	// only the role — currently only report download, which is gated by the
	// report's visibility. The handler must call CanDownloadReport.
	conditional bool
	why         string
}

// matrix is THE authorization table.
//
// docs/05-SECURITY-MODEL.md §6 is the human-readable form; this is the
// enforced one. They are checked against each other by TestMatrixMatchesSpec.
var matrix = map[Permission]rule{
	// --- tenant administration ---
	{ResourceTenant, ActionRead}:   {minRole: RoleViewer},
	{ResourceTenant, ActionUpdate}: {minRole: RoleOwner, why: "billing and SSO settings"},
	{ResourceTenant, ActionDelete}: {minRole: RoleOwner},

	{ResourceMember, ActionList}:   {minRole: RoleAdmin},
	{ResourceMember, ActionInvite}: {minRole: RoleAdmin},
	{ResourceMember, ActionUpdate}: {minRole: RoleAdmin, why: "role changes"},
	{ResourceMember, ActionDelete}: {minRole: RoleAdmin},

	// --- projects ---
	{ResourceProject, ActionRead}:   {minRole: RoleViewer},
	{ResourceProject, ActionList}:   {minRole: RoleViewer},
	{ResourceProject, ActionCreate}: {minRole: RoleAnalyst},
	{ResourceProject, ActionUpdate}: {minRole: RoleAnalyst},
	{ResourceProject, ActionDelete}: {minRole: RoleAdmin},

	// CERT-In Table 5 category 3. Readable by anyone who can see the project,
	// because a report renders them.
	{ResourcePractices, ActionRead}:   {minRole: RoleViewer},
	{ResourcePractices, ActionUpdate}: {minRole: RoleAnalyst},

	{ResourceRepoConn, ActionRead}:   {minRole: RoleViewer},
	{ResourceRepoConn, ActionCreate}: {minRole: RoleAnalyst},
	{ResourceRepoConn, ActionDelete}: {minRole: RoleAnalyst},
	// Enumerating the provider's repositories, for the connect wizard.
	//
	// Analyst, NOT Viewer — deliberately stricter than repo_connection:read.
	// Reading an existing connection reveals a repository the tenant already
	// chose to register; this LISTS every private repository the signed-in
	// user can see at GitHub, which is a much larger disclosure and is only
	// needed by someone who is about to create a connection.
	{ResourceRepoConn, ActionList}: {minRole: RoleAnalyst},

	{ResourceUpload, ActionCreate}: {minRole: RoleAnalyst},
	{ResourceUpload, ActionRead}:   {minRole: RoleViewer},

	{ResourceWebSource, ActionCreate}: {minRole: RoleAnalyst},
	{ResourceWebSource, ActionRead}:   {minRole: RoleViewer},

	// --- scanning ---
	{ResourceScan, ActionRead}: {minRole: RoleViewer},
	{ResourceScan, ActionList}: {minRole: RoleViewer},
	{ResourceScan, ActionRun}:  {minRole: RoleAnalyst},
	// Cancel matches Run, not Delete. Whoever may start a scan may stop one:
	// requiring Admin to cancel would leave an Analyst who started a runaway
	// scan unable to stop it, waiting for someone with more privilege.
	{ResourceScan, ActionCancel}: {minRole: RoleAnalyst},
	{ResourceScan, ActionDelete}: {minRole: RoleAdmin},

	// Enabling package-manager resolution means running arbitrary code from
	// the scanned repository. Admin, not analyst.
	{ResourceProject, ActionEnableRiskyResolution}: {
		minRole: RoleAdmin,
		why:     "executes arbitrary code from the scanned repository",
	},

	{ResourceEngine, ActionList}: {minRole: RoleViewer},
	{ResourceEngine, ActionConfigureEngines}: {
		minRole: RoleAdmin,
		why:     "changes which engines run for every scan in this family",
	},

	// --- hardware BOM (import + structured entry, never a scan) ---
	// Read covers the tree itself and which part-lookup provider is
	// configured — neither discloses anything beyond what a Viewer already
	// sees on the project. Create covers every write: CSV preview and
	// import, saving a component, and a part lookup — a preview touches no
	// storage but still parses an uploaded file, which CLAUDE.md and the
	// upload resource above both treat as an Analyst-level action, and a
	// part lookup spends a commercial API quota on the tenant's behalf, the
	// same reasoning ResourceRepoConn's ActionList uses to require Analyst
	// over Viewer.
	{ResourceHardware, ActionRead}:   {minRole: RoleViewer},
	{ResourceHardware, ActionCreate}: {minRole: RoleAnalyst},
	{ResourceHardware, ActionUpdate}: {minRole: RoleAnalyst},
	// ⚠ ADMIN TO RETIRE A DEVICE, MATCHING project:delete AND FOR THE SAME
	// REASON. The delete is soft and the BOM documents survive it (a
	// normalization artifact is immutable, invariant 10) — but a device is the
	// thing a compliance report is ABOUT, and removing one from the register
	// changes what the organisation appears to have shipped. Analyst can edit
	// every field on it; only an Admin can make it stop being listed.
	{ResourceHardware, ActionDelete}: {minRole: RoleAdmin},

	// --- quantum BOM (device metadata, captured by form, never a scan) ---
	// Same read/write split as hardware BOM immediately above, and for the
	// same reason: read discloses nothing a Viewer cannot already see on the
	// project, and a save is a data-entry action gated at Analyst.
	{ResourceQuantumDevice, ActionRead}:   {minRole: RoleViewer},
	{ResourceQuantumDevice, ActionCreate}: {minRole: RoleAnalyst},

	// --- results ---
	{ResourceDependency, ActionRead}:  {minRole: RoleViewer},
	{ResourceDependency, ActionList}:  {minRole: RoleViewer},
	{ResourceCryptoAsset, ActionList}: {minRole: RoleViewer},

	// --- AI governance (services/aibom) ---
	//
	// ⚠ THE CONSENT SWITCHES ARE ADMIN, EVERYTHING ELSE IS ANALYST, AND THE
	// SPLIT IS THE POINT. Recording what a model is for, or how somebody
	// classifies it, is ordinary compliance work. Turning on LLM enrichment
	// ships the customer's source code to a third party on every future scan of
	// that project — a decision with a different blast radius and a different
	// signatory.
	{ResourceAIPolicy, ActionRead}:        {minRole: RoleViewer},
	{ResourceAIPolicy, ActionUpdate}:      {minRole: RoleAdmin, why: "sends source code to a third-party LLM"},
	{ResourceAITag, ActionList}:           {minRole: RoleViewer},
	{ResourceAITag, ActionUpdate}:         {minRole: RoleAnalyst},
	{ResourceAIAttestation, ActionList}:   {minRole: RoleViewer},
	{ResourceAIAttestation, ActionCreate}: {minRole: RoleAnalyst},
	// --- AI models (discovered, same read sensitivity as crypto assets;
	// the four user-supplied elements are a data-entry action, same Analyst
	// gate as quantum device's form save above) ---
	{ResourceAIModel, ActionList}:   {minRole: RoleViewer},
	{ResourceAIModel, ActionRead}:   {minRole: RoleViewer},
	{ResourceAIModel, ActionUpdate}: {minRole: RoleAnalyst},
	{ResourceFinding, ActionRead}:   {minRole: RoleViewer},
	{ResourceFinding, ActionList}:   {minRole: RoleViewer},

	{ResourceVEX, ActionRead}:   {minRole: RoleViewer},
	{ResourceVEX, ActionTriage}: {minRole: RoleAnalyst},
	// Publishing an advisory is at least as consequential as the triage
	// decision behind it — same RoleAnalyst floor as ResourceVEX's write.
	{ResourceCSAF, ActionRead}:   {minRole: RoleViewer},
	{ResourceCSAF, ActionCreate}: {minRole: RoleAnalyst},

	// --- reports ---
	// ⚠ ActionCreate WAS MISSING ENTIRELY from Phase 6 onward — POST
	// /v1/reports has always required (report, create), and a missing cell
	// fails closed (see Allow's own doc comment), so every role in every
	// tenant got a 403 minting ANY report through the real HTTP API for the
	// whole life of this codebase. Same RoleAnalyst floor as ResourceScan's
	// ActionRun and ResourceCSAF's ActionCreate: queuing a render consumes
	// real compute and produces a compliance artifact, the same class of
	// action as starting the scan that feeds it.
	{ResourceReport, ActionCreate}: {minRole: RoleAnalyst},
	{ResourceReport, ActionRead}:   {minRole: RoleViewer},
	{ResourceReport, ActionList}:   {minRole: RoleViewer},
	// Download depends on the REPORT, not only the role: a `private` report
	// contains vulnerability detail (CERT-In §5.3.2) and a Viewer must not
	// have it. See CanDownloadReport.
	{ResourceReport, ActionDownload}: {
		minRole:     RoleViewer,
		conditional: true,
		why:         "viewer may download public reports only",
	},
	{ResourceShareLink, ActionShare}:  {minRole: RoleAnalyst, why: "minting a share link exposes data outside the tenant"},
	{ResourceShareLink, ActionDelete}: {minRole: RoleAnalyst},

	// --- collaboration ---
	{ResourceComment, ActionRead}:   {minRole: RoleViewer},
	{ResourceComment, ActionCreate}: {minRole: RoleViewer},
	{ResourceComment, ActionUpdate}: {minRole: RoleViewer, why: "own comments; ownership checked by the handler"},
	{ResourceComment, ActionDelete}: {minRole: RoleViewer, why: "own comments; ownership checked by the handler"},

	// --- campaigns ---
	{ResourceCampaign, ActionRead}:   {minRole: RoleViewer},
	{ResourceCampaign, ActionList}:   {minRole: RoleViewer},
	{ResourceCampaign, ActionCreate}: {minRole: RoleAnalyst},
	{ResourceCampaign, ActionUpdate}: {minRole: RoleAnalyst},
	{ResourceCampaign, ActionDelete}: {minRole: RoleAnalyst},
	{ResourceCampaign, ActionRun}:    {minRole: RoleAnalyst},

	// --- audit ---
	{ResourceAuditLog, ActionList}: {minRole: RoleAdmin, why: "access trails are sensitive"},
	{ResourceAuditLog, ActionRead}: {minRole: RoleAdmin},

	// --- API keys ---
	// Owner only. A key is a durable, unattended bearer credential; minting
	// one is closer to "grant standing access to this tenant" than to an
	// ordinary member-management action, which is why this is stricter than
	// ResourceMember's Admin floor above.
	{ResourceAPIKey, ActionList}:   {minRole: RoleOwner},
	{ResourceAPIKey, ActionCreate}: {minRole: RoleOwner},
	{ResourceAPIKey, ActionDelete}: {minRole: RoleOwner},
}

// Decision is the outcome of an authorization check.
type Decision struct {
	Allowed bool
	// NeedsResourceCheck is true when the matrix permits the role but the final
	// answer depends on the resource — report download against visibility.
	// A handler that ignores this has a bug, so Allow() reports it explicitly.
	NeedsResourceCheck bool
	Reason             string
}

// Allow evaluates a (role, resource, action) triple.
//
// An UNREGISTERED permission is DENIED. That is the whole point: adding an
// endpoint without a matrix entry produces a 403 and a failing test, not a
// silently open door.
func Allow(role Role, resource Resource, action Action) Decision {
	if !role.Valid() {
		return Decision{Reason: fmt.Sprintf("unknown role %q", role)}
	}

	perm := Permission{Resource: resource, Action: action}
	r, ok := matrix[perm]
	if !ok {
		return Decision{
			Reason: fmt.Sprintf(
				"no authorization rule for %s — permissions FAIL CLOSED; "+
					"add it to libs/go-shared/authz/matrix.go and to "+
					"docs/05-SECURITY-MODEL.md §6", perm),
		}
	}

	if role.rank() < r.minRole.rank() {
		return Decision{Reason: fmt.Sprintf(
			"%s requires at least %s, caller is %s", perm, r.minRole, role)}
	}

	return Decision{
		Allowed:            true,
		NeedsResourceCheck: r.conditional,
		Reason:             r.why,
	}
}

// ReportVisibility mirrors report.reports.visibility.
type ReportVisibility string

const (
	VisibilityPublic  ReportVisibility = "public"
	VisibilityPrivate ReportVisibility = "private"
)

// CanDownloadReport resolves the one conditional permission.
//
// CERT-In §5.3.2 (p.32) requires maintaining BOTH a public version (non-
// sensitive) and a private one (containing vulnerabilities). A Viewer may have
// the public one; the private one needs Analyst or above.
func CanDownloadReport(role Role, visibility ReportVisibility) Decision {
	d := Allow(role, ResourceReport, ActionDownload)
	if !d.Allowed {
		return d
	}
	if visibility == VisibilityPrivate && role.rank() < RoleAnalyst.rank() {
		return Decision{Reason: "a private report contains vulnerability detail " +
			"(CERT-In §5.3.2); viewer may download public reports only"}
	}
	return Decision{Allowed: true}
}

// Permissions returns every registered permission, sorted. Used by
// TestAuthzMatrix to enumerate the whole surface.
func Permissions() []Permission {
	out := make([]Permission, 0, len(matrix))
	for p := range matrix {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	return out
}

// MinRole returns the least-privileged role for a permission.
func MinRole(p Permission) (Role, bool) {
	r, ok := matrix[p]
	if !ok {
		return "", false
	}
	return r.minRole, true
}

// ParseRole validates untrusted input.
func ParseRole(s string) (Role, error) {
	r := Role(strings.ToLower(strings.TrimSpace(s)))
	if !r.Valid() {
		return "", fmt.Errorf("invalid role %q", s)
	}
	return r, nil
}
