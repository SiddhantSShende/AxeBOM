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
	ResourceTenant     Resource = "tenant"
	ResourceMember     Resource = "member"
	ResourceProject    Resource = "project"
	ResourcePractices  Resource = "practices"
	ResourceRepoConn   Resource = "repo_connection"
	ResourceUpload     Resource = "upload"
	ResourceScan       Resource = "scan"
	ResourceDependency Resource = "dependency"
	ResourceFinding    Resource = "finding"
	ResourceVEX        Resource = "vex"
	ResourceReport     Resource = "report"
	ResourceShareLink  Resource = "share_link"
	ResourceComment    Resource = "comment"
	ResourceCampaign   Resource = "campaign"
	ResourceAuditLog   Resource = "audit_log"
	ResourceEngine     Resource = "engine"
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
	// ActionEnableRiskyResolution turns on package-manager resolution, which
	// EXECUTES arbitrary code from the scanned repository (npm lifecycle
	// scripts, Gradle build files). Deliberately separate from `update`:
	// accepting that risk is not an ordinary project edit.
	ActionEnableRiskyResolution Action = "enable_risky_resolution"
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

	{ResourceUpload, ActionCreate}: {minRole: RoleAnalyst},
	{ResourceUpload, ActionRead}:   {minRole: RoleViewer},

	// --- scanning ---
	{ResourceScan, ActionRead}:   {minRole: RoleViewer},
	{ResourceScan, ActionList}:   {minRole: RoleViewer},
	{ResourceScan, ActionRun}:    {minRole: RoleAnalyst},
	{ResourceScan, ActionDelete}: {minRole: RoleAdmin},

	// Enabling package-manager resolution means running arbitrary code from
	// the scanned repository. Admin, not analyst.
	{ResourceProject, ActionEnableRiskyResolution}: {
		minRole: RoleAdmin,
		why:     "executes arbitrary code from the scanned repository",
	},

	{ResourceEngine, ActionList}: {minRole: RoleViewer},

	// --- results ---
	{ResourceDependency, ActionRead}: {minRole: RoleViewer},
	{ResourceDependency, ActionList}: {minRole: RoleViewer},
	{ResourceFinding, ActionRead}:    {minRole: RoleViewer},
	{ResourceFinding, ActionList}:    {minRole: RoleViewer},

	{ResourceVEX, ActionRead}:   {minRole: RoleViewer},
	{ResourceVEX, ActionTriage}: {minRole: RoleAnalyst},

	// --- reports ---
	{ResourceReport, ActionRead}: {minRole: RoleViewer},
	{ResourceReport, ActionList}: {minRole: RoleViewer},
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
