package authz

import (
	"strings"
	"testing"
)

// TestAuthzMatrix enumerates EVERY (role, resource, action) triple.
//
// This is the phase's acceptance criterion. Its value is not that it checks
// each cell — it is that adding an endpoint without a matrix entry makes it
// FAIL, rather than silently allowing the request.
func TestAuthzMatrix(t *testing.T) {
	perms := Permissions()
	if len(perms) == 0 {
		t.Fatal("the matrix is empty")
	}
	t.Logf("%d permissions x %d roles = %d cells", len(perms), len(AllRoles()),
		len(perms)*len(AllRoles()))

	for _, p := range perms {
		minRole, ok := MinRole(p)
		if !ok {
			t.Fatalf("%s vanished from the matrix mid-test", p)
		}

		for _, role := range AllRoles() {
			d := Allow(role, p.Resource, p.Action)
			want := role.rank() >= minRole.rank()

			if d.Allowed != want {
				t.Errorf("%s for %s: allowed=%v, want %v (min role %s)",
					p, role, d.Allowed, want, minRole)
			}
			// A denial that does not say why is a support ticket.
			if !d.Allowed && strings.TrimSpace(d.Reason) == "" {
				t.Errorf("%s for %s: denied with no reason", p, role)
			}
		}
	}
}

// An unregistered permission must be DENIED and must say how to fix it.
func TestUnregisteredPermissionFailsClosed(t *testing.T) {
	d := Allow(RoleOwner, Resource("secret_vault"), Action("exfiltrate"))
	if d.Allowed {
		t.Fatal("an unregistered permission was ALLOWED — the matrix fails open")
	}
	for _, want := range []string{"FAIL CLOSED", "matrix.go"} {
		if !strings.Contains(d.Reason, want) {
			t.Errorf("denial reason should mention %q: %q", want, d.Reason)
		}
	}
}

// Even an owner is denied an action that has no rule. Privilege does not
// substitute for a decision nobody made.
func TestOwnerIsNotAWildcard(t *testing.T) {
	if Allow(RoleOwner, ResourceProject, Action("nuke_from_orbit")).Allowed {
		t.Error("owner was allowed an unregistered action")
	}
}

func TestUnknownRoleDenied(t *testing.T) {
	d := Allow(Role("superadmin"), ResourceProject, ActionRead)
	if d.Allowed {
		t.Fatal("an unknown role was allowed")
	}
	if !strings.Contains(d.Reason, "unknown role") {
		t.Errorf("reason = %q", d.Reason)
	}
}

// ---------------------------------------------------------------------------
// The specific rules that matter
// ---------------------------------------------------------------------------

// CERT-In §5.3.2 requires a public and a private version. The private one
// contains vulnerability detail, so a Viewer must not have it.
func TestViewerCannotDownloadPrivateReport(t *testing.T) {
	tests := []struct {
		role       Role
		visibility ReportVisibility
		want       bool
	}{
		{RoleViewer, VisibilityPublic, true},
		{RoleViewer, VisibilityPrivate, false}, // the rule this test exists for
		{RoleAnalyst, VisibilityPrivate, true},
		{RoleAdmin, VisibilityPrivate, true},
		{RoleOwner, VisibilityPrivate, true},
	}
	for _, tt := range tests {
		d := CanDownloadReport(tt.role, tt.visibility)
		if d.Allowed != tt.want {
			t.Errorf("%s downloading a %s report: allowed=%v, want %v (%s)",
				tt.role, tt.visibility, d.Allowed, tt.want, d.Reason)
		}
	}
}

// A handler that ignores NeedsResourceCheck would let a Viewer download a
// private report, so the flag must be set on exactly that permission.
func TestConditionalPermissionIsFlagged(t *testing.T) {
	d := Allow(RoleViewer, ResourceReport, ActionDownload)
	if !d.Allowed {
		t.Fatal("viewer should reach the resource check")
	}
	if !d.NeedsResourceCheck {
		t.Error("report download must set NeedsResourceCheck — otherwise a " +
			"handler that only checks Allowed leaks private reports")
	}

	// Ordinary permissions must NOT set it, or handlers learn to ignore it.
	if Allow(RoleViewer, ResourceProject, ActionRead).NeedsResourceCheck {
		t.Error("project read is unconditional and must not set NeedsResourceCheck")
	}
}

// Running package-manager resolution executes arbitrary code from the scanned
// repository. That is not an ordinary project edit.
func TestRiskyResolutionNeedsAdmin(t *testing.T) {
	if Allow(RoleAnalyst, ResourceProject, ActionEnableRiskyResolution).Allowed {
		t.Error("analyst must NOT be able to enable package-manager resolution — " +
			"it runs arbitrary code from the scanned repo")
	}
	if !Allow(RoleAdmin, ResourceProject, ActionEnableRiskyResolution).Allowed {
		t.Error("admin should be able to accept that risk")
	}
	// And it must be a distinct action from an ordinary update, or the risk
	// rides along with routine edits.
	if !Allow(RoleAnalyst, ResourceProject, ActionUpdate).Allowed {
		t.Error("analyst should still be able to edit a project normally")
	}
}

func TestViewerCannotMintShareLinks(t *testing.T) {
	if Allow(RoleViewer, ResourceShareLink, ActionShare).Allowed {
		t.Error("a share link exposes data outside the tenant; viewer must not mint one")
	}
	if !Allow(RoleAnalyst, ResourceShareLink, ActionShare).Allowed {
		t.Error("analyst should be able to share")
	}
}

func TestViewerCanCommentButNotTriage(t *testing.T) {
	if !Allow(RoleViewer, ResourceComment, ActionCreate).Allowed {
		t.Error("viewer should be able to comment")
	}
	if Allow(RoleViewer, ResourceVEX, ActionTriage).Allowed {
		t.Error("viewer must not set VEX status — that is a compliance assertion")
	}
}

func TestAuditLogNeedsAdmin(t *testing.T) {
	for _, r := range []Role{RoleViewer, RoleAnalyst} {
		if Allow(r, ResourceAuditLog, ActionList).Allowed {
			t.Errorf("%s must not read the audit log", r)
		}
	}
	if !Allow(RoleAdmin, ResourceAuditLog, ActionList).Allowed {
		t.Error("admin should read the audit log")
	}
}

func TestOnlyOwnerManagesTenant(t *testing.T) {
	for _, r := range []Role{RoleViewer, RoleAnalyst, RoleAdmin} {
		if Allow(r, ResourceTenant, ActionUpdate).Allowed {
			t.Errorf("%s must not change tenant/billing/SSO settings", r)
		}
	}
	if !Allow(RoleOwner, ResourceTenant, ActionUpdate).Allowed {
		t.Error("owner should manage the tenant")
	}
}

// ---------------------------------------------------------------------------
// Structural
// ---------------------------------------------------------------------------

// Every role must be able to do SOMETHING, or it is a role nobody can hold
// usefully — usually a sign a rank was typo'd.
func TestEveryRoleHasSomePermission(t *testing.T) {
	for _, role := range AllRoles() {
		n := 0
		for _, p := range Permissions() {
			if Allow(role, p.Resource, p.Action).Allowed {
				n++
			}
		}
		if n == 0 {
			t.Errorf("role %s can do nothing at all", role)
		}
		t.Logf("%-8s %d/%d permissions", role, n, len(Permissions()))
	}
}

// Privilege must be monotonic: anything a viewer may do, an owner may do.
// A non-monotonic matrix is almost always a mistake, and a confusing one.
func TestPrivilegeIsMonotonic(t *testing.T) {
	roles := AllRoles()
	for _, p := range Permissions() {
		for i := 0; i < len(roles)-1; i++ {
			lower, higher := roles[i], roles[i+1]
			if Allow(lower, p.Resource, p.Action).Allowed &&
				!Allow(higher, p.Resource, p.Action).Allowed {
				t.Errorf("%s: %s is allowed but %s is not — privilege is not monotonic",
					p, lower, higher)
			}
		}
	}
}

func TestParseRoleRejectsGarbage(t *testing.T) {
	for _, good := range []string{"viewer", "ANALYST", " admin ", "Owner"} {
		if _, err := ParseRole(good); err != nil {
			t.Errorf("ParseRole(%q) failed: %v", good, err)
		}
	}
	for _, bad := range []string{"", "root", "superuser", "owner;drop table"} {
		if _, err := ParseRole(bad); err == nil {
			t.Errorf("ParseRole(%q) should fail", bad)
		}
	}
}
