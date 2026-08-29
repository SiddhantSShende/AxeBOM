package iam

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/axebom/axebom/libs/go-shared/authz"

	"github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/admin"
	appV2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/application/v2"
	authorizationV2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/authorization/v2"
	filterV2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/filter/v2"
	instanceV2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/instance/v2"
	objectV2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/object/v2"
	orgV2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/org/v2"
	projectV2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/project/v2"
	settingsV2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/settings/v2"
	userV2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/user/v2"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// RoleKeys are the ZITADEL project roles, generated from the permission matrix.
//
// ⚠ FOUR COARSE ROLES, NOT FIFTY PERMISSIONS.
//
// The matrix in libs/go-shared/authz holds 50 resource:action cells. Those are
// NOT modelled as ZITADEL roles: fifty roles bloat every token, make the ZITADEL
// console unusable, and put product policy inside the identity provider where
// changing it means an IAM migration rather than a code change. ZITADEL's own
// guidance is coarse roles in the IdP and fine-grained policy in the
// application, and that is what this is.
//
// Generated from authz.AllRoles() rather than written out, so a role added to
// the matrix cannot be silently missing from ZITADEL.
func RoleKeys() []string {
	roles := authz.AllRoles()
	keys := make([]string, 0, len(roles))
	for _, r := range roles {
		keys = append(keys, string(r))
	}
	return keys
}

// ServiceRoleKey marks a machine user as one of our own components.
//
// It is deliberately NOT one of the four product roles. A service principal is
// not a person with elevated rights; it is a different KIND of caller, and the
// distinction is what lets RequireService refuse a human token on the one route
// that hands out a credential reference.
const ServiceRoleKey = "service"

// Spec is the desired state of the identity tier.
type Spec struct {
	// AdminOrg is the instance organisation that OWNS the project. Tenants are
	// separate organisations that receive a grant to it.
	AdminOrg string

	ProjectName string

	SPAName            string
	SPARedirectURIs    []string
	SPAPostLogoutURIs  []string
	SPAAdditionalHosts []string
	// DevMode permits http:// redirect URIs. Localhost development only —
	// ZITADEL rejects non-TLS redirects otherwise, and for good reason.
	DevMode bool

	// TrustedDomain is the bare hostname (NO port, NO scheme — ZITADEL's
	// validation rejects a colon with Errors.Instance.Domain.InvalidCharacter)
	// the browser actually uses, e.g. "192.168.30.202". ZITADEL resolves which
	// VIRTUAL INSTANCE a
	// request belongs to from the Host header, but validates the caller's
	// PUBLIC host — the one it actually redirects the browser to — against a
	// separate trusted-domain list; a public host that differs from the
	// instance's own configured domain (ZITADEL_EXTERNALDOMAIN, set once at
	// setup time) and isn't in that list is refused as "Instance.NotFound",
	// which reads like a routing bug rather than the untrusted-origin check
	// it is. Registering an ADDITIONAL trusted domain — this — is how a
	// second, later access path (a LAN IP, a different port-forward) starts
	// working without re-running ZITADEL's one-shot setup, which is
	// documented as NOT a config edit. Empty skips the step.
	TrustedDomain string

	APIName string

	// BrandName replaces "Zitadel" in the pinned login UI's own copy — e.g.
	// register.description reads "Create your Zitadel account." out of the
	// box, and that container image is never forked or rebuilt (MIT-licensed,
	// but forking it means tracking ZITADEL releases ourselves for a handful
	// of strings). ensureHostedLoginTranslation overrides the reachable
	// strings through ZITADEL's own text-customisation API instead. Empty
	// skips the step, leaving ZITADEL's defaults in place.
	BrandName string

	Tenants []TenantSpec
	// CrossOrgGrants authorise a user who lives in one organisation to act in
	// another.
	//
	// ⚠ A ZITADEL USER BELONGS TO EXACTLY ONE ORGANISATION, but an
	// AUTHORIZATION can be created in any organisation that holds a grant for
	// the project. That is how one human spans two tenants — which is the
	// carol@both.test fixture, and the case that proves the role is resolved
	// per tenant rather than per user.
	CrossOrgGrants  []CrossOrgGrant
	ServiceAccounts []string
	// ServiceKeyDir receives one JSON key per service account.
	//
	// ⚠ A KEY IS SHOWN ONCE AND NEVER AGAIN. ZITADEL returns the private key
	// in the create response and does not store it, so a key is minted only
	// when the file is absent — otherwise a re-run would silently replace a
	// credential that running services are still holding.
	ServiceKeyDir string
}

// CrossOrgGrant gives an existing user a role in an organisation that is not
// their own.
type CrossOrgGrant struct {
	Email   string
	HomeOrg string
	// TargetOrg is the organisation the role applies in.
	TargetOrg string
	Role      authz.Role
}

// TenantSpec is one AxeBOM tenant, which is one ZITADEL organisation.
type TenantSpec struct {
	OrgName string
	// Slug is the AxeBOM tenant to link this organisation to.
	//
	// ⚠ THE LINK IS BY SLUG, NOT BY NAME. auth.tenants.slug is UNIQUE;
	// auth.tenants.name is not, and this database already contains two rows
	// called "Acme Industries" left behind by the auth service's own tests.
	// Matching on a non-unique column made the link update two rows and
	// violate the unique constraint on zitadel_org_id — which reads as a bug
	// in ZITADEL rather than as an ambiguous query.
	Slug  string
	Users []UserSpec
}

// UserSpec is one human.
type UserSpec struct {
	Email      string
	GivenName  string
	FamilyName string
	// Password is development seeding only. Production users are invited and
	// choose their own credential; nothing here writes a password to a real
	// deployment because `iam bootstrap --tenants` is opt-in.
	Password string
	Role     authz.Role
}

// Result is what a bootstrap produced, and what `iam verify` reports.
type Result struct {
	Origin       string
	AdminOrgID   string
	ProjectID    string
	RoleKeys     []string
	SPAClientID  string
	APIClientID  string
	Orgs         []OrgResult
	ServiceUsers []ServiceUserResult
}

// OrgResult is a provisioned tenant organisation.
type OrgResult struct {
	Name  string
	Slug  string
	ID    string
	Users []UserResult
}

// UserResult is a provisioned human.
type UserResult struct {
	Email string
	ID    string
	Role  authz.Role
	// Created distinguishes "we made this" from "it was already here", so a
	// second run reads as a no-op rather than as unexplained silence.
	Created bool
}

// ServiceUserResult is a provisioned machine user.
type ServiceUserResult struct {
	Name    string
	ID      string
	Created bool
	// KeyPath is where the JSON key was written, or where an existing one was
	// found. Empty when no key directory was configured.
	KeyPath string
	// KeyMinted is true only when this run created the key.
	KeyMinted bool
}

// Bootstrap brings ZITADEL to the state described by spec.
//
// ⚠ IDEMPOTENT BY CONSTRUCTION. Every step is find-or-create, and an
// already-exists answer is success. A provisioning command that only works once
// is one people run once, forget, and then cannot use to repair a drifted
// instance.
func (c *Client) Bootstrap(ctx context.Context, spec Spec) (*Result, error) {
	res := &Result{Origin: c.Origin(), RoleKeys: RoleKeys()}

	adminOrgID, err := c.findOrg(ctx, spec.AdminOrg)
	if err != nil {
		return nil, err
	}
	if adminOrgID == "" {
		return nil, fmt.Errorf(
			"iam: the instance organisation %q does not exist.\n"+
				"      It is created by the setup one-shot from\n"+
				"      ZITADEL_FIRSTINSTANCE_ORG_NAME; check that the value there\n"+
				"      matches ZITADEL_ADMIN_ORG", spec.AdminOrg)
	}
	res.AdminOrgID = adminOrgID

	if res.ProjectID, err = c.ensureProject(ctx, adminOrgID, spec.ProjectName); err != nil {
		return nil, err
	}
	if err := c.ensureRoles(ctx, res.ProjectID); err != nil {
		return nil, err
	}
	if res.SPAClientID, err = c.ensureSPA(ctx, res.ProjectID, spec); err != nil {
		return nil, err
	}
	if spec.TrustedDomain != "" {
		if err := c.ensureTrustedDomain(ctx, spec.TrustedDomain); err != nil {
			return nil, err
		}
	}
	if res.APIClientID, err = c.ensureAPI(ctx, res.ProjectID, spec.APIName); err != nil {
		return nil, err
	}
	if spec.BrandName != "" {
		if err := c.ensureHostedLoginTranslation(ctx, spec.BrandName); err != nil {
			return nil, err
		}
	}
	if err := c.ensureLabelPolicy(ctx); err != nil {
		return nil, err
	}
	// ⚠ UNCONDITIONAL, UNLIKE THE TRANSLATION ABOVE.
	//
	// A missing BrandName is a cosmetic gap; a login policy that still allows
	// self-registration is a security gap disguised as a UX bug. See
	// ensureLoginPolicy for what happens without this.
	if err := c.ensureLoginPolicy(ctx); err != nil {
		return nil, err
	}

	for _, t := range spec.Tenants {
		org, err := c.ensureTenant(ctx, res.ProjectID, t)
		if err != nil {
			return nil, err
		}
		res.Orgs = append(res.Orgs, *org)
	}

	for _, g := range spec.CrossOrgGrants {
		if err := c.applyCrossOrgGrant(ctx, res.ProjectID, g); err != nil {
			return nil, err
		}
	}

	for _, name := range spec.ServiceAccounts {
		su, err := c.ensureServiceUser(ctx, adminOrgID, res.ProjectID, name)
		if err != nil {
			return nil, err
		}
		if spec.ServiceKeyDir != "" {
			if err := c.ensureServiceKey(ctx, su, spec.ServiceKeyDir); err != nil {
				return nil, err
			}
		}
		res.ServiceUsers = append(res.ServiceUsers, *su)
	}

	return res, nil
}

// ensureHostedLoginTranslation overrides the ZITADEL brand strings that leak
// through the pinned login UI, which we run unmodified (MIT-licensed, but
// forking a Next.js app to reword three strings is not a trade worth making).
//
// ⚠ THIS IS A SERVER-SIDE OVERRIDE THE LOGIN UI READS AT REQUEST TIME, NOT A
// FORK. `apps/login` calls SettingsService.GetHostedLoginTranslation on every
// render and deep-merges the result over its own English bundle
// (apps/login/src/i18n/request.ts) — exactly the extension point ZITADEL
// built for this. SetHostedLoginTranslation is the write side of that same
// API; nothing here touches the container image.
//
// Idempotent by construction: it always overwrites, which is correct for a
// value that is entirely OURS to set (unlike an org or a user, there is
// nothing here that could already exist with content worth preserving).
//
// ⚠ ONLY THE STRINGS A CALLER CAN ACTUALLY REACH ARE OVERRIDDEN.
// `idp.signInWithZitadel` (an external "log in with ZITADEL" IDP button) and
// `device.consent.disclaimer` (the OAuth device-code screen) are never
// rendered by our flow — we don't configure ZITADEL as an external IDP and
// don't expose device-code — so leaving them at ZITADEL's default is not an
// oversight; overriding unreachable strings would be dead configuration
// nobody could verify.
// ensureLoginPolicy turns off self-registration on the instance's default
// login policy.
//
// ---------------------------------------------------------------------------
// WHY THIS EXISTS
//
// ZITADEL's hosted login ships a "Register new user" link on by default
// (LoginPolicy.AllowRegister), and nothing else in this file ever touched it.
// AxeBOM's tenancy model is invite-only: an organisation IS a tenant
// (docs/05-SECURITY-MODEL.md), and a person is meant to arrive through
// ensureUser/ensureAuthorization below, already holding a role. A visitor who
// clicks "Register" instead gets a ZITADEL account with a role in NO
// organisation — and because ensureProject sets AuthorizationRequired: true,
// the OIDC callback then refuses to complete with Errors.User.GrantRequired,
// which the hosted login UI renders as an unhelpful "Unknown error occurred."
// The account creation itself silently succeeds; only the sign-in that was
// supposed to follow it fails, which is what makes this so easy to miss in
// testing — an operator using an already-granted seed account never triggers
// the path a genuine new visitor takes.
//
// Disabling the link is the correct fix, not a workaround: this product has no
// concept of an unaffiliated user, so a self-registration flow can only ever
// produce an account that the rest of the system is designed to reject.
//
// ⚠ READ-MODIFY-WRITE, NOT A BARE FLAG FLIP.
//
// UpdateLoginPolicyRequest is a full replacement of the policy, not a patch —
// sending it with every field at its Go zero value would also disable
// password login (AllowUsernamePassword), clear the MFA lifetime windows and
// the second/multi-factor lists, etc. So the current policy is read first and
// every field but AllowRegister is carried across unchanged.
// ensureTrustedDomain registers domain (host:port) as an additional public
// host ZITADEL will accept, alongside whatever ZITADEL_EXTERNALDOMAIN was set
// to at setup time. Adding one never removes another — see the Spec.TrustedDomain
// doc comment for why this exists.
func (c *Client) ensureTrustedDomain(ctx context.Context, domain string) error {
	cctx, cancel := callCtx(ctx)
	defer cancel()

	// The v1 AdminService has an equivalent RPC but it is deprecated in favor
	// of this one (instance service v2).
	_, err := c.api.InstanceServiceV2().AddTrustedDomain(cctx, &instanceV2.AddTrustedDomainRequest{
		TrustedDomain: domain,
	})
	if err != nil && !isAlreadyExists(err) {
		return fmt.Errorf("iam: trust domain %q: %w", domain, err)
	}
	return nil
}

func (c *Client) ensureLoginPolicy(ctx context.Context) error {
	cctx, cancel := callCtx(ctx)
	current, err := c.api.AdminService().GetLoginPolicy(cctx, &admin.GetLoginPolicyRequest{})
	cancel()
	if err != nil {
		return fmt.Errorf("iam: get login policy: %w", err)
	}
	p := current.GetPolicy()

	// Idempotent: a second bootstrap run against an instance that already has
	// this set makes no call at all.
	if !p.GetAllowRegister() {
		return nil
	}

	cctx, cancel = callCtx(ctx)
	defer cancel()
	_, err = c.api.AdminService().UpdateLoginPolicy(cctx, &admin.UpdateLoginPolicyRequest{
		AllowUsernamePassword:      p.GetAllowUsernamePassword(),
		AllowRegister:              false,
		AllowExternalIdp:           p.GetAllowExternalIdp(),
		ForceMfa:                   p.GetForceMfa(),
		PasswordlessType:           p.GetPasswordlessType(),
		HidePasswordReset:          p.GetHidePasswordReset(),
		IgnoreUnknownUsernames:     p.GetIgnoreUnknownUsernames(),
		DefaultRedirectUri:         p.GetDefaultRedirectUri(),
		PasswordCheckLifetime:      p.GetPasswordCheckLifetime(),
		ExternalLoginCheckLifetime: p.GetExternalLoginCheckLifetime(),
		MfaInitSkipLifetime:        p.GetMfaInitSkipLifetime(),
		SecondFactorCheckLifetime:  p.GetSecondFactorCheckLifetime(),
		MultiFactorCheckLifetime:   p.GetMultiFactorCheckLifetime(),
		AllowDomainDiscovery:       p.GetAllowDomainDiscovery(),
		DisableLoginWithEmail:      p.GetDisableLoginWithEmail(),
		DisableLoginWithPhone:      p.GetDisableLoginWithPhone(),
		ForceMfaLocalOnly:          p.GetForceMfaLocalOnly(),
	})
	if err != nil {
		return fmt.Errorf("iam: disable self-registration: %w", err)
	}
	return nil
}

func (c *Client) ensureHostedLoginTranslation(ctx context.Context, brand string) error {
	cctx, cancel := callCtx(ctx)
	defer cancel()

	translations, err := structpb.NewStruct(map[string]any{
		// The document <title> for every login-app page.
		"common": map[string]any{
			"title": "Sign in — " + brand,
		},
		// ⚠ THE FIELD IS LABELLED "Loginname" BY DEFAULT, AND EVERY LOGIN NAME
		// IN THIS PRODUCT IS AN EMAIL ADDRESS.
		//
		// Signup (Client.Signup, below) never sets a separate ZITADEL username —
		// only Profile and Email — so ZITADEL falls back to the email as the
		// login name for every account this app creates, seeded fixtures
		// included. "Loginname" asks the visitor for a concept this product
		// does not have; "Email" asks for the thing they actually typed two
		// screens ago. Key path from apps/login/locales/en.json:
		// loginname.labels.loginname.
		"loginname": map[string]any{
			"labels": map[string]any{
				"loginname": "Email",
			},
		},
		// Reached by clicking "Register new user" on the loginname screen —
		// the exact string reported: "Create your Zitadel account."
		"register": map[string]any{
			"description": "Create your " + brand + " account.",
		},
	})
	if err != nil {
		return fmt.Errorf("iam: build hosted login translation: %w", err)
	}

	_, err = c.api.SettingsServiceV2().SetHostedLoginTranslation(cctx,
		&settingsV2.SetHostedLoginTranslationRequest{
			Level:        &settingsV2.SetHostedLoginTranslationRequest_Instance{Instance: true},
			Locale:       "en",
			Translations: translations,
		})
	if err != nil {
		return fmt.Errorf("iam: set hosted login translation: %w", err)
	}
	return nil
}

// ensureLabelPolicy pushes AxeBOM's palette onto ZITADEL's hosted screens
// (the login form, its error and consent pages) via the one customization
// surface ZITADEL exposes for them — colour and logo, not layout or CSS.
//
// ⚠ THE HEX VALUES ARE COPIED FROM tokens.css BY HAND, NOT IMPORTED.
// frontend/src/design/tokens.css is the source of truth for the app's own
// palette (CLAUDE.md — one document owns a fact). ZITADEL's login runs as a
// separate application with no build step this repo controls, so there is no
// way to reference the CSS custom properties directly; keeping the two in
// sync is a manual, occasional task; if the palette moves, this drifts until
// someone next touches this function.
//
// ⚠ FULL REPLACEMENT, LIKE ensureLoginPolicy ABOVE. The current policy is
// read first and every field this function does not care about — including
// ThemeMode, so a visitor's light/dark preference keeps working exactly as
// it does in the AxeBOM app itself — is carried across unchanged.
func (c *Client) ensureLabelPolicy(ctx context.Context) error {
	cctx, cancel := callCtx(ctx)
	current, err := c.api.AdminService().GetLabelPolicy(cctx, &admin.GetLabelPolicyRequest{})
	cancel()
	if err != nil {
		return fmt.Errorf("iam: get label policy: %w", err)
	}
	p := current.GetPolicy()

	const (
		primaryLight    = "#4338ca"
		backgroundLight = "#fbfbfd"
		warnLight       = "#b91c1c"
		fontLight       = "#16161a"
		primaryDark     = "#6366f1"
		backgroundDark  = "#0e0e11"
		warnDark        = "#ef4444"
		fontDark        = "#ececf1"
	)

	// Idempotent: a second bootstrap run against an instance already on this
	// palette makes no call at all.
	if p.GetPrimaryColor() == primaryLight && p.GetPrimaryColorDark() == primaryDark {
		return nil
	}

	cctx, cancel = callCtx(ctx)
	defer cancel()
	_, err = c.api.AdminService().UpdateLabelPolicy(cctx, &admin.UpdateLabelPolicyRequest{
		PrimaryColor:        primaryLight,
		BackgroundColor:     backgroundLight,
		WarnColor:           warnLight,
		FontColor:           fontLight,
		PrimaryColorDark:    primaryDark,
		BackgroundColorDark: backgroundDark,
		WarnColorDark:       warnDark,
		FontColorDark:       fontDark,
		HideLoginNameSuffix: p.GetHideLoginNameSuffix(),
		DisableWatermark:    p.GetDisableWatermark(),
		ThemeMode:           p.GetThemeMode(),
	})
	if err != nil {
		return fmt.Errorf("iam: update label policy: %w", err)
	}

	// ⚠ A DRAFT UNTIL ACTIVATED. UpdateLabelPolicy writes to a staged policy
	// that GetPreviewLabelPolicy would show; visitors keep seeing the old one
	// until this call promotes it live — the same two-stage model ZITADEL's
	// own console uses before its "Activate" button.
	cctx, cancel = callCtx(ctx)
	defer cancel()
	if _, err := c.api.AdminService().ActivateLabelPolicy(cctx, &admin.ActivateLabelPolicyRequest{}); err != nil {
		return fmt.Errorf("iam: activate label policy: %w", err)
	}
	return nil
}

// ErrOrgNameTaken and ErrEmailTaken distinguish a signup conflict from every
// other failure, so the HTTP layer can answer 409 instead of 500.
var (
	ErrOrgNameTaken = errors.New("iam: an organisation with this name already exists")
	ErrEmailTaken   = errors.New("iam: this email is already registered")
)

// Signup provisions a brand-new tenant organisation and its first user, as
// Owner, for a self-service "create your organisation" flow.
//
// ⚠ NOT Bootstrap's idempotent find-or-create semantics. Bootstrap is an
// operator command run against organisations it already expects to find;
// Signup is reachable by an anonymous visitor, so attaching them to an
// EXISTING organisation because the name collided would hand a stranger
// Owner access to somebody else's tenant. Every step here fails closed on a
// collision instead of adopting what is already there — see ensureOrg's
// `created` return and the instance-wide email lookup below.
func (c *Client) Signup(ctx context.Context, projectID, orgName string, u UserSpec) (*OrgResult, error) {
	orgID, created, err := c.ensureOrg(ctx, orgName)
	if err != nil {
		return nil, err
	}
	if !created {
		return nil, ErrOrgNameTaken
	}

	// ⚠ ACROSS THE WHOLE INSTANCE, NOT SCOPED TO THE NEW ORG. The organisation
	// above was just created and has no users yet, so an org-scoped lookup
	// could never find a collision — it would let one email address claim a
	// second, unrelated organisation.
	if existing, err := c.FindUserByEmail(ctx, u.Email); err != nil {
		return nil, err
	} else if existing != "" {
		return nil, ErrEmailTaken
	}

	if err := c.ensureProjectGrant(ctx, projectID, orgID); err != nil {
		return nil, err
	}

	ur, err := c.ensureUser(ctx, orgID, projectID, u)
	if err != nil {
		return nil, err
	}

	return &OrgResult{Name: orgName, ID: orgID, Users: []UserResult{*ur}}, nil
}

// ---------------------------------------------------------------- primitives

func (c *Client) findOrg(ctx context.Context, name string) (string, error) {
	cctx, cancel := callCtx(ctx)
	defer cancel()

	resp, err := c.api.OrganizationServiceV2().ListOrganizations(cctx,
		&orgV2.ListOrganizationsRequest{
			Queries: []*orgV2.SearchQuery{{
				Query: &orgV2.SearchQuery_NameQuery{
					NameQuery: &orgV2.OrganizationNameQuery{
						Name:   name,
						Method: objectV2.TextQueryMethod_TEXT_QUERY_METHOD_EQUALS,
					},
				},
			}},
		})
	if err != nil {
		return "", fmt.Errorf("iam: list organisations: %w", err)
	}
	for _, o := range resp.GetResult() {
		if o.GetName() == name {
			return o.GetId(), nil
		}
	}
	return "", nil
}

func (c *Client) ensureOrg(ctx context.Context, name string) (string, bool, error) {
	if id, err := c.findOrg(ctx, name); err != nil || id != "" {
		return id, false, err
	}

	cctx, cancel := callCtx(ctx)
	defer cancel()

	resp, err := c.api.OrganizationServiceV2().AddOrganization(cctx,
		&orgV2.AddOrganizationRequest{Name: name})
	if err != nil {
		if !isAlreadyExists(err) {
			return "", false, fmt.Errorf("iam: create organisation %q: %w", name, err)
		}
		// Lost a race, or a name collision with a soft-deleted org. Re-read.
		id, ferr := c.findOrg(ctx, name)
		return id, false, ferr
	}
	return resp.GetOrganizationId(), true, nil
}

func (c *Client) ensureProject(ctx context.Context, orgID, name string) (string, error) {
	{
		cctx, cancel := callCtx(ctx)
		resp, err := c.api.ProjectServiceV2().ListProjects(cctx, &projectV2.ListProjectsRequest{
			Filters: []*projectV2.ProjectSearchFilter{{
				Filter: &projectV2.ProjectSearchFilter_ProjectNameFilter{
					ProjectNameFilter: &projectV2.ProjectNameFilter{
						ProjectName: name,
						Method:      filterV2.TextFilterMethod_TEXT_FILTER_METHOD_EQUALS,
					},
				},
			}},
		})
		cancel()
		if err != nil {
			return "", fmt.Errorf("iam: list projects: %w", err)
		}
		for _, p := range resp.GetProjects() {
			if p.GetName() == name {
				return p.GetProjectId(), nil
			}
		}
	}

	cctx, cancel := callCtx(ctx)
	defer cancel()

	resp, err := c.api.ProjectServiceV2().CreateProject(cctx, &projectV2.CreateProjectRequest{
		OrganizationId: orgID,
		Name:           name,
		// ⚠ ROLE ASSERTION MUST BE ON.
		//
		// Without it ZITADEL issues a perfectly valid token that carries no
		// roles claim at all, and every request is authorised as the fallback
		// role. The failure is silent and looks like a bug in our middleware.
		ProjectRoleAssertion: true,
		// A user with no role in this project cannot log in to it. That is the
		// cheapest possible tenant gate, and it fails closed.
		AuthorizationRequired: true,
	})
	if err != nil {
		return "", fmt.Errorf("iam: create project %q: %w", name, err)
	}
	return resp.GetProjectId(), nil
}

func (c *Client) ensureRoles(ctx context.Context, projectID string) error {
	for _, key := range RoleKeys() {
		if err := c.addRole(ctx, projectID, key, strings.ToUpper(key[:1])+key[1:], "product"); err != nil {
			return err
		}
	}
	// The service role is separate from the product roles on purpose — see the
	// comment on ServiceRoleKey.
	return c.addRole(ctx, projectID, ServiceRoleKey, "Service principal", "platform")
}

func (c *Client) addRole(ctx context.Context, projectID, key, display, group string) error {
	cctx, cancel := callCtx(ctx)
	defer cancel()

	_, err := c.api.ProjectServiceV2().AddProjectRole(cctx, &projectV2.AddProjectRoleRequest{
		ProjectId:   projectID,
		RoleKey:     key,
		DisplayName: display,
		Group:       &group,
	})
	if err != nil && !isAlreadyExists(err) {
		return fmt.Errorf("iam: add project role %q: %w", key, err)
	}
	return nil
}

func (c *Client) findApplication(ctx context.Context, projectID, name string) (string, error) {
	cctx, cancel := callCtx(ctx)
	defer cancel()

	resp, err := c.api.ApplicationServiceV2().ListApplications(cctx,
		&appV2.ListApplicationsRequest{
			Filters: []*appV2.ApplicationSearchFilter{
				{Filter: &appV2.ApplicationSearchFilter_ProjectIdFilter{
					ProjectIdFilter: &appV2.ProjectIDFilter{ProjectId: projectID},
				}},
				{Filter: &appV2.ApplicationSearchFilter_NameFilter{
					NameFilter: &appV2.ApplicationNameFilter{
						Name:   name,
						Method: filterV2.TextFilterMethod_TEXT_FILTER_METHOD_EQUALS,
					},
				}},
			},
		})
	if err != nil {
		return "", fmt.Errorf("iam: list applications: %w", err)
	}
	for _, a := range resp.GetApplications() {
		if a.GetName() == name {
			return a.GetApplicationId(), nil
		}
	}
	return "", nil
}

func (c *Client) ensureSPA(ctx context.Context, projectID string, spec Spec) (string, error) {
	appID, err := c.findApplication(ctx, projectID, spec.SPAName)
	if err != nil {
		return "", err
	}
	if appID != "" {
		// ⚠ RECONCILED, NOT RETURNED UNTOUCHED. iamVerify's own doc comment
		// claims re-running bootstrap "repairs" whatever is missing — that was
		// only true for orgs/users/roles. An application found by name used to
		// come back exactly as first created, so changing --public-url (a new
		// access origin) never reached ZITADEL's registered redirect URIs
		// short of deleting the application by hand and letting this recreate
		// it. Reconciling here is what makes the documented promise true.
		if err := c.reconcileSPA(ctx, projectID, appID, spec); err != nil {
			return "", err
		}
		return c.clientIDForApp(ctx, projectID, spec.SPAName)
	}

	cctx, cancel := callCtx(ctx)
	defer cancel()

	_, err = c.api.ApplicationServiceV2().CreateApplication(cctx, &appV2.CreateApplicationRequest{
		ProjectId: projectID,
		Name:      spec.SPAName,
		ApplicationType: &appV2.CreateApplicationRequest_OidcConfiguration{
			OidcConfiguration: &appV2.CreateOIDCApplicationRequest{
				RedirectUris:           spec.SPARedirectURIs,
				PostLogoutRedirectUris: spec.SPAPostLogoutURIs,
				AdditionalOrigins:      spec.SPAAdditionalHosts,
				ResponseTypes:          []appV2.OIDCResponseType{appV2.OIDCResponseType_OIDC_RESPONSE_TYPE_CODE},
				GrantTypes: []appV2.OIDCGrantType{
					appV2.OIDCGrantType_OIDC_GRANT_TYPE_AUTHORIZATION_CODE,
					// offline_access. Without it the SPA has to send the user
					// through a full redirect every time the 15-minute access
					// token expires.
					appV2.OIDCGrantType_OIDC_GRANT_TYPE_REFRESH_TOKEN,
				},
				// USER_AGENT + AUTH_METHOD_NONE is Authorization Code with PKCE
				// and no client secret. A browser cannot keep a secret, and
				// shipping one in a bundle is worse than having none because it
				// looks like security.
				ApplicationType: appV2.OIDCApplicationType_OIDC_APP_TYPE_USER_AGENT,
				AuthMethodType:  appV2.OIDCAuthMethodType_OIDC_AUTH_METHOD_TYPE_NONE,
				Version:         appV2.OIDCVersion_OIDC_VERSION_1_0,
				DevelopmentMode: spec.DevMode,
				// ⚠ JWT, NOT THE DEFAULT OPAQUE BEARER.
				//
				// Our services verify tokens locally against JWKS instead of
				// calling introspection on every request across seven
				// services. An opaque token cannot be verified locally at all,
				// so this setting is what makes the whole authentication design
				// work — and the compensating control for losing instant
				// revocation is the 15-minute lifetime set in compose.
				AccessTokenType:          appV2.OIDCTokenType_OIDC_TOKEN_TYPE_JWT,
				AccessTokenRoleAssertion: true,
				IdTokenRoleAssertion:     true,
			},
		},
	})
	if err != nil && !isAlreadyExists(err) {
		return "", fmt.Errorf("iam: create SPA application %q: %w", spec.SPAName, err)
	}
	return c.clientIDForApp(ctx, projectID, spec.SPAName)
}

// reconcileSPA brings an EXISTING application's redirect/logout URIs and
// additional origins in line with spec. Only these three fields are set —
// UpdateOIDCApplicationConfigurationRequest's own contract is "if not set,
// unchanged", so everything ensureSPA's CreateApplication call established
// once (grant types, token type, role assertion, ...) is left alone here.
func (c *Client) reconcileSPA(ctx context.Context, projectID, appID string, spec Spec) error {
	cctx, cancel := callCtx(ctx)
	defer cancel()

	_, err := c.api.ApplicationServiceV2().UpdateApplication(cctx, &appV2.UpdateApplicationRequest{
		ApplicationId: appID,
		ProjectId:     projectID,
		ApplicationType: &appV2.UpdateApplicationRequest_OidcConfiguration{
			OidcConfiguration: &appV2.UpdateOIDCApplicationConfigurationRequest{
				RedirectUris:           spec.SPARedirectURIs,
				PostLogoutRedirectUris: spec.SPAPostLogoutURIs,
				AdditionalOrigins:      spec.SPAAdditionalHosts,
			},
		},
	})
	// A prior run already reconciled it to this exact spec: ZITADEL answers
	// "No changes" with FailedPrecondition rather than a silent no-op success,
	// which is the expected happy path here, not a failure.
	if err != nil && !isNoChanges(err) {
		return fmt.Errorf("iam: reconcile SPA application %q redirect URIs: %w", spec.SPAName, err)
	}
	return nil
}

// isNoChanges recognizes ZITADEL's FailedPrecondition("No changes") response
// to an update request that would leave the resource exactly as it already
// is — the expected result of calling a reconcile step twice with the same
// desired state, not an error.
func isNoChanges(err error) bool {
	if err == nil {
		return false
	}
	st, ok := status.FromError(err)
	if !ok || st.Code() != codes.FailedPrecondition {
		return false
	}
	return strings.Contains(strings.ToLower(err.Error()), "no changes")
}

func (c *Client) ensureAPI(ctx context.Context, projectID, name string) (string, error) {
	if id, err := c.clientIDForApp(ctx, projectID, name); err != nil || id != "" {
		return id, err
	}

	cctx, cancel := callCtx(ctx)
	defer cancel()

	_, err := c.api.ApplicationServiceV2().CreateApplication(cctx, &appV2.CreateApplicationRequest{
		ProjectId: projectID,
		Name:      name,
		ApplicationType: &appV2.CreateApplicationRequest_ApiConfiguration{
			ApiConfiguration: &appV2.CreateAPIApplicationRequest{
				// Private key JWT rather than basic auth: the introspection
				// credential is then a key that never leaves the pod, not a
				// shared secret that lands in an env var on seven services.
				AuthMethodType: appV2.APIAuthMethodType_API_AUTH_METHOD_TYPE_PRIVATE_KEY_JWT,
			},
		},
	})
	if err != nil && !isAlreadyExists(err) {
		return "", fmt.Errorf("iam: create API application %q: %w", name, err)
	}
	return c.clientIDForApp(ctx, projectID, name)
}

// clientIDForApp returns the OAuth client id of a named application.
//
// The client id is what the SPA and the resource servers actually need; the
// application id is an internal handle and using one where the other belongs
// produces an "unauthorized client" that gives no hint which id was wrong.
func (c *Client) clientIDForApp(ctx context.Context, projectID, name string) (string, error) {
	appID, err := c.findApplication(ctx, projectID, name)
	if err != nil || appID == "" {
		return "", err
	}

	cctx, cancel := callCtx(ctx)
	defer cancel()

	resp, err := c.api.ApplicationServiceV2().GetApplication(cctx,
		&appV2.GetApplicationRequest{ApplicationId: appID})
	if err != nil {
		return "", fmt.Errorf("iam: read application %q: %w", name, err)
	}
	app := resp.GetApplication()
	if oidc := app.GetOidcConfiguration(); oidc != nil {
		return oidc.GetClientId(), nil
	}
	if api := app.GetApiConfiguration(); api != nil {
		return api.GetClientId(), nil
	}
	return "", fmt.Errorf("iam: application %q has no OIDC or API configuration", name)
}

// ------------------------------------------------------------------- tenants

func (c *Client) ensureTenant(ctx context.Context, projectID string, t TenantSpec) (*OrgResult, error) {
	orgID, _, err := c.ensureOrg(ctx, t.OrgName)
	if err != nil {
		return nil, err
	}
	if orgID == "" {
		return nil, fmt.Errorf("iam: organisation %q could not be created or found", t.OrgName)
	}

	// ⚠ A TENANT ORGANISATION CANNOT USE A PROJECT IT DOES NOT OWN WITHOUT A
	// GRANT. Without this, users in the tenant org authenticate successfully
	// and then carry an empty roles claim — which our middleware correctly
	// refuses, and which looks like a broken role mapping rather than a missing
	// grant.
	if err := c.ensureProjectGrant(ctx, projectID, orgID); err != nil {
		return nil, err
	}

	out := &OrgResult{Name: t.OrgName, Slug: t.Slug, ID: orgID}
	for _, u := range t.Users {
		ur, err := c.ensureUser(ctx, orgID, projectID, u)
		if err != nil {
			return nil, err
		}
		out.Users = append(out.Users, *ur)
	}
	return out, nil
}

func (c *Client) ensureProjectGrant(ctx context.Context, projectID, orgID string) error {
	cctx, cancel := callCtx(ctx)
	defer cancel()

	_, err := c.api.ProjectServiceV2().CreateProjectGrant(cctx, &projectV2.CreateProjectGrantRequest{
		ProjectId:             projectID,
		GrantedOrganizationId: orgID,
		RoleKeys:              append(RoleKeys(), ServiceRoleKey),
	})
	if err != nil && !isAlreadyExists(err) {
		return fmt.Errorf("iam: grant project to organisation %s: %w", orgID, err)
	}
	return nil
}

// FindUserByEmail looks up a user ACROSS THE WHOLE INSTANCE, not scoped to one
// organisation.
//
// findUserByEmail (unexported, below) requires knowing the org already, which
// is exactly what is missing for a self-registered account: the person who
// hit "Register" on the login screen chose their own organisation, and
// nothing here observed which one. This is the query that finds them anyway.
func (c *Client) FindUserByEmail(ctx context.Context, email string) (string, error) {
	cctx, cancel := callCtx(ctx)
	defer cancel()

	resp, err := c.api.UserServiceV2().ListUsers(cctx, &userV2.ListUsersRequest{
		Queries: []*userV2.SearchQuery{
			{Query: &userV2.SearchQuery_EmailQuery{
				EmailQuery: &userV2.EmailQuery{
					EmailAddress: email,
					Method:       objectV2.TextQueryMethod_TEXT_QUERY_METHOD_EQUALS_IGNORE_CASE,
				},
			}},
		},
	})
	if err != nil {
		return "", fmt.Errorf("iam: list users: %w", err)
	}
	for _, u := range resp.GetResult() {
		return u.GetUserId(), nil
	}
	return "", nil
}

// GrantRole authorizes an existing user (by ZITADEL user id, from
// FindUserByEmail) for one project role in one organisation.
//
// ⚠ THIS IS WHAT `Errors.User.GrantRequired` MEANS. ZITADEL will let anyone
// self-register through the login UI, but a registered user with no project
// grant cannot complete an OIDC flow for THIS application — correctly: the
// login UI's own "Continue" button on the account picker sends the request
// and gets a silent 403 back, which looks to the person clicking it like the
// button does nothing. Idempotent: an authorization that already exists is
// success, not an error, exactly like every other ensure* here.
func (c *Client) GrantRole(ctx context.Context, userID, projectID, orgID string, role authz.Role) error {
	return c.ensureAuthorization(ctx, userID, projectID, orgID, string(role))
}

func (c *Client) findUserByEmail(ctx context.Context, orgID, email string) (string, error) {
	cctx, cancel := callCtx(ctx)
	defer cancel()

	resp, err := c.api.UserServiceV2().ListUsers(cctx, &userV2.ListUsersRequest{
		Queries: []*userV2.SearchQuery{
			{Query: &userV2.SearchQuery_OrganizationIdQuery{
				OrganizationIdQuery: &userV2.OrganizationIdQuery{OrganizationId: orgID},
			}},
			{Query: &userV2.SearchQuery_EmailQuery{
				EmailQuery: &userV2.EmailQuery{
					EmailAddress: email,
					Method:       objectV2.TextQueryMethod_TEXT_QUERY_METHOD_EQUALS_IGNORE_CASE,
				},
			}},
		},
	})
	if err != nil {
		return "", fmt.Errorf("iam: list users: %w", err)
	}
	for _, u := range resp.GetResult() {
		return u.GetUserId(), nil
	}
	return "", nil
}

func (c *Client) ensureUser(ctx context.Context, orgID, projectID string, u UserSpec) (*UserResult, error) {
	out := &UserResult{Email: u.Email, Role: u.Role}

	id, err := c.findUserByEmail(ctx, orgID, u.Email)
	if err != nil {
		return nil, err
	}

	if id == "" {
		cctx, cancel := callCtx(ctx)
		req := &userV2.CreateUserRequest{
			OrganizationId: orgID,
			UserType: &userV2.CreateUserRequest_Human_{
				Human: &userV2.CreateUserRequest_Human{
					Profile: &userV2.SetHumanProfile{
						GivenName:  u.GivenName,
						FamilyName: u.FamilyName,
					},
					Email: &userV2.SetHumanEmail{
						Email: u.Email,
						// Pre-verified: this path only ever seeds development
						// fixtures, and there is no mailbox behind acme.test to
						// click a link in. Real users are invited and verify
						// their own address.
						Verification: &userV2.SetHumanEmail_IsVerified{IsVerified: true},
					},
				},
			},
		}
		if u.Password != "" {
			req.GetHuman().PasswordType = &userV2.CreateUserRequest_Human_Password{
				Password: &userV2.Password{Password: u.Password, ChangeRequired: false},
			}
		}
		resp, cerr := c.api.UserServiceV2().CreateUser(cctx, req)
		cancel()
		if cerr != nil && !isAlreadyExists(cerr) {
			return nil, fmt.Errorf("iam: create user %q: %w", u.Email, cerr)
		}
		if cerr == nil {
			id = resp.GetId()
			out.Created = true
		} else if id, err = c.findUserByEmail(ctx, orgID, u.Email); err != nil {
			return nil, err
		}
	}
	if id == "" {
		return nil, fmt.Errorf("iam: user %q could not be created or found", u.Email)
	}
	out.ID = id

	if err := c.ensureAuthorization(ctx, id, projectID, orgID, string(u.Role)); err != nil {
		return nil, err
	}
	return out, nil
}

func (c *Client) ensureServiceUser(ctx context.Context, orgID, projectID, name string) (*ServiceUserResult, error) {
	out := &ServiceUserResult{Name: name}

	id, err := c.findMachineUser(ctx, orgID, name)
	if err != nil {
		return nil, err
	}
	if id == "" {
		cctx, cancel := callCtx(ctx)
		resp, cerr := c.api.UserServiceV2().CreateUser(cctx, &userV2.CreateUserRequest{
			OrganizationId: orgID,
			Username:       &name,
			UserType: &userV2.CreateUserRequest_Machine_{
				Machine: &userV2.CreateUserRequest_Machine{
					Name:        name,
					Description: strPtr("AxeBOM service principal"),
					// JWT for the same reason the SPA uses it: our resource
					// servers verify locally and never introspect.
					AccessTokenType: userV2.AccessTokenType_ACCESS_TOKEN_TYPE_JWT,
				},
			},
		})
		cancel()
		if cerr != nil && !isAlreadyExists(cerr) {
			return nil, fmt.Errorf("iam: create service user %q: %w", name, cerr)
		}
		if cerr == nil {
			id = resp.GetId()
			out.Created = true
		} else if id, err = c.findMachineUser(ctx, orgID, name); err != nil {
			return nil, err
		}
	}
	if id == "" {
		return nil, fmt.Errorf("iam: service user %q could not be created or found", name)
	}
	out.ID = id

	return out, c.ensureAuthorization(ctx, id, projectID, orgID, ServiceRoleKey)
}

func (c *Client) findMachineUser(ctx context.Context, orgID, username string) (string, error) {
	cctx, cancel := callCtx(ctx)
	defer cancel()

	resp, err := c.api.UserServiceV2().ListUsers(cctx, &userV2.ListUsersRequest{
		Queries: []*userV2.SearchQuery{
			{Query: &userV2.SearchQuery_OrganizationIdQuery{
				OrganizationIdQuery: &userV2.OrganizationIdQuery{OrganizationId: orgID},
			}},
			{Query: &userV2.SearchQuery_UserNameQuery{
				UserNameQuery: &userV2.UserNameQuery{
					UserName: username,
					Method:   objectV2.TextQueryMethod_TEXT_QUERY_METHOD_EQUALS,
				},
			}},
		},
	})
	if err != nil {
		return "", fmt.Errorf("iam: list machine users: %w", err)
	}
	for _, u := range resp.GetResult() {
		return u.GetUserId(), nil
	}
	return "", nil
}

func (c *Client) ensureAuthorization(ctx context.Context, userID, projectID, orgID, role string) error {
	cctx, cancel := callCtx(ctx)
	defer cancel()

	_, err := c.api.AuthorizationServiceV2().CreateAuthorization(cctx,
		&authorizationV2.CreateAuthorizationRequest{
			UserId:         userID,
			ProjectId:      projectID,
			OrganizationId: orgID,
			RoleKeys:       []string{role},
		})
	if err != nil && !isAlreadyExists(err) {
		return fmt.Errorf("iam: authorize user %s as %q: %w", userID, role, err)
	}
	return nil
}

// ensureServiceKey mints a machine key the first time and never again.
func (c *Client) ensureServiceKey(ctx context.Context, su *ServiceUserResult, dir string) error {
	// 0750, not 0700: the two services that present one of these keys run in
	// containers as a DIFFERENT uid, and a directory nobody else can traverse
	// blocks the read before the file mode is even consulted. Group traverse
	// plus group_add on those two containers (deploy/compose/docker-compose.app.yml)
	// is what lets them in without making the directory world-readable.
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("iam: create key directory %s: %w", dir, err)
	}
	path := filepath.Join(dir, su.Name+".json")
	su.KeyPath = path

	if _, err := os.Stat(path); err == nil {
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("iam: check for existing key %s: %w", path, err)
	}

	cctx, cancel := callCtx(ctx)
	defer cancel()

	// ⚠ AN EXPIRY IS MANDATORY — ZITADEL rejects the request without one.
	// That is the right default: a service credential with no expiry is one
	// nobody ever rotates. A year is long enough not to be a nuisance and
	// short enough that the rotation path gets exercised.
	expires := timestamppb.New(time.Now().AddDate(1, 0, 0))

	resp, err := c.api.UserServiceV2().AddKey(cctx, &userV2.AddKeyRequest{
		UserId:         su.ID,
		ExpirationDate: expires,
	})
	if err != nil {
		return fmt.Errorf("iam: mint key for %q: %w", su.Name, err)
	}

	// 0640 — owner and group, never world.
	//
	// This is a private key that authenticates as a service principal, so
	// world-readable would be the same as published on a shared machine. Group
	// is the narrowest mode that still lets the campaign and fetcher containers
	// read it: they run as a different uid and join this file's group
	// explicitly. Anything wider is a standing credential any local account can
	// lift.
	//
	// In production these keys arrive from a secret manager with the platform's
	// own ownership, and this path never runs.
	//nolint:gosec // 0640 is deliberate and argued above: the containers that
	// present this key run as a different uid and read it by group. 0600
	// would satisfy the scanner and stop both services from starting.
	if err := os.WriteFile(path, resp.GetKeyContent(), 0o640); err != nil {
		return fmt.Errorf("iam: write key %s: %w", path, err)
	}
	su.KeyMinted = true
	return nil
}

// applyCrossOrgGrant authorises a user from one organisation inside another.
func (c *Client) applyCrossOrgGrant(ctx context.Context, projectID string, g CrossOrgGrant) error {
	homeID, err := c.findOrg(ctx, g.HomeOrg)
	if err != nil {
		return err
	}
	targetID, err := c.findOrg(ctx, g.TargetOrg)
	if err != nil {
		return err
	}
	if homeID == "" || targetID == "" {
		return fmt.Errorf("iam: cross-org grant for %s needs both %q and %q to exist",
			g.Email, g.HomeOrg, g.TargetOrg)
	}

	userID, err := c.findUserByEmail(ctx, homeID, g.Email)
	if err != nil {
		return err
	}
	if userID == "" {
		return fmt.Errorf("iam: cross-org grant: no user %s in %q", g.Email, g.HomeOrg)
	}

	return c.ensureAuthorization(ctx, userID, projectID, targetID, string(g.Role))
}

func strPtr(s string) *string { return &s }
