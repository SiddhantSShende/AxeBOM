package main

import (
	"context"
	"flag"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/axebom/axebom/libs/go-shared/authz"
	"github.com/axebom/axebom/libs/go-shared/iam"
	"github.com/axebom/axebom/libs/go-shared/platform/config"
	"github.com/axebom/axebom/libs/go-shared/platform/db"
)

// defaultKeyPath is where the ZITADEL setup one-shot writes the machine key.
//
// A BIND MOUNT, not a named volume, so this process can read it without
// shelling out to `docker cp`. See deploy/compose/docker-compose.iam.yml.
const defaultKeyPath = "deploy/compose/.data/zitadel-bootstrap/admin-sa.json"

func runIAM(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: axebom iam <bootstrap|verify> [flags]")
	}
	switch args[0] {
	case "bootstrap":
		return iamBootstrap(ctx, args[1:])
	case "verify":
		return iamVerify(ctx, args[1:])
	default:
		return fmt.Errorf("unknown iam subcommand %q", args[0])
	}
}

// iamFlags are shared by both subcommands.
type iamFlags struct {
	domain    string
	port      string
	insecure  bool
	keyPath   string
	adminOrg  string
	project   string
	publicURL string
	brandName string
}

func bindIAMFlags(fs *flag.FlagSet) *iamFlags {
	f := &iamFlags{}
	fs.StringVar(&f.domain, "domain", envOr("ZITADEL_DOMAIN", "localhost"),
		"ZITADEL hostname, without a port")
	fs.StringVar(&f.port, "port", envOr("ZITADEL_API_PORT", "58080"),
		"port this command connects on — the container's own port, not the public one")
	// ⚠ ALWAYS PLAINTEXT BY DEFAULT, INDEPENDENT OF ZITADEL_EXTERNALSECURE.
	// This dials ZITADEL's DIRECT port (58080), bypassing nginx entirely —
	// and ZITADEL_TLS_ENABLED is unconditionally "false" in
	// docker-compose.iam.yml because ZITADEL never terminates TLS itself; only
	// nginx does, for the browser-facing path this command doesn't use.
	// ZITADEL_EXTERNALSECURE describes THAT path's scheme (what the browser
	// sees), not this one — conflating them here made this command try HTTPS
	// against a port that only ever speaks plaintext the moment
	// ZITADEL_EXTERNALSECURE turned on, confirmed live: "http: server gave
	// HTTP response to HTTPS client".
	fs.BoolVar(&f.insecure, "insecure", true,
		"connect over plaintext h2c — true unless ZITADEL's own direct port has a cert of its own, which it does not in this deployment")
	fs.StringVar(&f.keyPath, "key", envOr("ZITADEL_BOOTSTRAP_KEY", defaultKeyPath),
		"machine-user JSON key written by the ZITADEL setup one-shot")
	fs.StringVar(&f.adminOrg, "admin-org", envOr("ZITADEL_ADMIN_ORG", "AxeBOM"),
		"the instance organisation that owns the project")
	fs.StringVar(&f.project, "project", envOr("ZITADEL_PROJECT_NAME", "axebom"),
		"ZITADEL project name")
	fs.StringVar(&f.publicURL, "public-url", envOr("ZITADEL_PUBLIC_URL", "http://localhost:5173"),
		"the origin the browser uses — redirect URIs are derived from it")
	// ⚠ NOT the same string as anywhere else the product names itself — this
	// only reaches the three ZITADEL login-UI strings iam.ensureHostedLoginTranslation
	// overrides ("Sign in — X", "Create your X account."). It exists as a flag
	// because the pinned login container is the one surface in this stack we
	// cannot rename by editing our own source.
	fs.StringVar(&f.brandName, "brand-name", envOr("ZITADEL_BRAND_NAME", "AxeBOM"),
		"replaces \"Zitadel\" in the login UI's own copy (title, register screen)")
	return f
}

// hostOf extracts the bare hostname from a URL (no port, no scheme), for
// registering ZITADEL's trusted-domain list (Spec.TrustedDomain) — confirmed
// against the live instance: passing host:port fails with
// "Errors.Instance.Domain.InvalidCharacter" on the colon, so this must be a
// domain name only. An unparseable input returns "" so callers skip the step
// rather than trust a malformed value.
func hostOf(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

// publicOrigin splits a URL into the host:port and scheme
// iam.Config.PublicHost/PublicScheme need — see PublicScheme's own doc
// comment for why the CLI has to set both once ZITADEL_EXTERNALSECURE can be
// true: it dials ZITADEL's direct port in plaintext regardless (that port
// never has a cert of its own), which no longer matches the public issuer's
// scheme on its own the way it did when everything was plain http. An
// unparseable input returns ("", ""), so callers skip the override rather
// than trust a malformed value, matching hostOf's own failure mode above.
func publicOrigin(rawURL string) (host, scheme string) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", ""
	}
	return u.Host, u.Scheme
}

func envOr(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

// ---------------------------------------------------------------- bootstrap

func iamBootstrap(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("iam bootstrap", flag.ExitOnError)
	f := bindIAMFlags(fs)
	seed := fs.Bool("seed-tenants", true,
		"create the two development organisations and their users")
	link := fs.Bool("link", true,
		"write the org and user ids into auth.tenants / auth.users")
	writeEnv := fs.Bool("write-env", false,
		"upsert ZITADEL_PROJECT_ID/ZITADEL_SPA_CLIENT_ID/ZITADEL_ISSUER into .env at the repo root")
	if err := fs.Parse(args); err != nil {
		return err
	}

	pubHost, pubScheme := publicOrigin(f.publicURL)
	client, err := iam.Connect(ctx, iam.Config{
		Domain:       f.domain,
		Port:         f.port,
		Insecure:     f.insecure,
		KeyPath:      resolveFromRepoRoot(f.keyPath),
		PublicHost:   pubHost,
		PublicScheme: pubScheme,
	})
	if err != nil {
		return err
	}
	defer func() { _ = client.Close() }()

	spec := iam.Spec{
		AdminOrg:    f.adminOrg,
		ProjectName: f.project,
		SPAName:     "AxeBOM Web",
		APIName:     "AxeBOM API",
		BrandName:   f.brandName,
		// ⚠ ZITADEL MATCHES REDIRECT URIs EXACTLY. A trailing slash, a
		// different port or http-vs-https is a rejected login with a message
		// that names neither the expected nor the received value.
		SPARedirectURIs: []string{
			f.publicURL + "/auth/callback",
			f.publicURL + "/auth/silent",
		},
		SPAPostLogoutURIs:  []string{f.publicURL + "/"},
		SPAAdditionalHosts: []string{f.publicURL},
		// Development mode permits the http:// redirect URIs above. It must be
		// off wherever the origin is real.
		DevMode:       strings.HasPrefix(f.publicURL, "http://"),
		TrustedDomain: hostOf(f.publicURL),
		// Alongside the bootstrap key, in a directory that is already
		// gitignored. Services read their key from here.
		ServiceKeyDir: resolveFromRepoRoot("deploy/compose/.data/zitadel-bootstrap/service-keys"),
		ServiceAccounts: []string{
			// The two components that call another service on a tenant's
			// behalf today: campaign -> scan-orchestrator, fetcher -> project.
			"svc-campaign",
			"svc-fetcher",
		},
	}
	if *seed {
		spec.Tenants = devTenants()
		// Carol lives in Acme as an analyst and is a VIEWER in Beta. One
		// human, two tenants, two different roles — the fixture that makes a
		// per-user role resolution bug visible instead of plausible.
		spec.CrossOrgGrants = []iam.CrossOrgGrant{{
			Email:     "carol@both.test",
			HomeOrg:   "Acme Industries",
			TargetOrg: "Beta Corp",
			Role:      authz.RoleViewer,
		}}
	}

	res, err := client.Bootstrap(ctx, spec)
	if err != nil {
		return err
	}

	if *link && *seed {
		if err := linkIdentities(ctx, res); err != nil {
			return err
		}
	}

	printBootstrap(res, f.publicURL)

	if *writeEnv {
		// ⚠ WHAT MAKES `task dev` ABLE TO BOOTSTRAP ITSELF. Without this, the
		// three values above are printed for a human to paste into .env by
		// hand — the two-step dance that left 6 of 8 app services crash-
		// looping on a fresh clone until someone did that and re-ran
		// `docker compose up -d` (see docs/STATE.md's 2026-08-24 (g) entry).
		envPath := resolveFromRepoRoot(".env")
		updates := map[string]string{
			"ZITADEL_PROJECT_ID":    res.ProjectID,
			"ZITADEL_SPA_CLIENT_ID": res.SPAClientID,
			"ZITADEL_ISSUER":        f.publicURL,
		}
		if err := upsertEnvFile(envPath, updates); err != nil {
			return fmt.Errorf("iam bootstrap: write .env: %w", err)
		}
		fmt.Printf("wrote ZITADEL_PROJECT_ID, ZITADEL_SPA_CLIENT_ID, ZITADEL_ISSUER to %s\n", envPath)
	}
	return nil
}

// upsertEnvFile replaces `KEY=` lines matching updates and appends any key
// not already present, leaving every other line — comments, ordering,
// unrelated values — untouched. Missing entirely, it is created; existing
// file permissions are preserved rather than reset, since .env commonly holds
// secrets and its access mode is a deliberate choice this command should not
// override.
func upsertEnvFile(path string, updates map[string]string) error {
	mode := os.FileMode(0o644)
	data, err := os.ReadFile(path) // #nosec G304 -- fixed ".env" path resolved from the repo root, not caller input
	switch {
	case err == nil:
		if fi, statErr := os.Stat(path); statErr == nil {
			mode = fi.Mode().Perm()
		}
	case os.IsNotExist(err):
		data = nil
	default:
		return err
	}

	lines := strings.Split(string(data), "\n")
	seen := make(map[string]bool, len(updates))
	for i, line := range lines {
		for key, val := range updates {
			if strings.HasPrefix(line, key+"=") {
				lines[i] = key + "=" + val
				seen[key] = true
			}
		}
	}

	var missing []string
	for key := range updates {
		if !seen[key] {
			missing = append(missing, key)
		}
	}
	sort.Strings(missing) // deterministic output, not map iteration order
	for _, key := range missing {
		lines = append(lines, key+"="+updates[key])
	}

	return os.WriteFile(path, []byte(strings.Join(lines, "\n")), mode) // #nosec G304 G703 -- same fixed ".env" path as above
}

// devTenants mirrors migrations/seed/0001_dev_tenants.sql.
//
// ⚠ TWO TENANTS, NOT ONE. A single-tenant fixture cannot show a cross-tenant
// leak: every row it returns is legitimately visible. The seed deliberately
// gives both tenants a project called payments-api for the same reason, so a
// leak appears as duplicate rows rather than as nothing at all.
//
// Carol belongs to both, with a DIFFERENT role in each. She is the fixture that
// proves the role is resolved per tenant rather than per user.
func devTenants() []iam.TenantSpec {
	// ⚠ NOT the legacy seed password `axebom-dev-only`.
	//
	// ZITADEL's default password policy requires upper case, lower case, a
	// digit and a symbol, and the old value has none of those. Weakening the
	// instance policy so a fixture fits is exactly the change that survives
	// into production, so the fixture moves instead. It matches
	// ZITADEL_ADMIN_PASSWORD, so there is one dev credential to remember
	// rather than two.
	//
	// The old hash still sits in migrations/seed/0001_dev_tenants.sql and is
	// still asserted by seed_login_test.go; both belong to the auth service
	// that ZITADEL replaces, and both go when it does.
	// The suppression below is correct and the scanner is not: this is the
	// password of a SEEDED FIXTURE ACCOUNT in a local ZITADEL, printed to the
	// operator so they can sign in as alice. It authenticates nothing outside
	// a development instance, and hiding it in an env var would only mean the
	// next person cannot log in.
	const devPassword = "AxeBOM-dev-only1!" //nolint:gosec // dev fixture, printed on purpose
	return []iam.TenantSpec{
		{
			OrgName: "Acme Industries",
			Slug:    "acme",
			Users: []iam.UserSpec{
				{Email: "alice@acme.test", GivenName: "Alice", FamilyName: "Owner",
					Password: devPassword, Role: authz.RoleOwner},
				{Email: "aaron@acme.test", GivenName: "Aaron", FamilyName: "Analyst",
					Password: devPassword, Role: authz.RoleAnalyst},
				{Email: "carol@both.test", GivenName: "Carol", FamilyName: "Consultant",
					Password: devPassword, Role: authz.RoleAnalyst},
			},
		},
		{
			OrgName: "Beta Corp",
			Slug:    "beta",
			Users: []iam.UserSpec{
				{Email: "bob@beta.test", GivenName: "Bob", FamilyName: "Owner",
					Password: devPassword, Role: authz.RoleOwner},
			},
		},
	}
}

// linkIdentities writes the ZITADEL ids onto the existing seeded rows.
//
// ⚠ THIS IS WHAT KEEPS created_by MEANINGFUL. Six tables across five schemas
// hold `created_by uuid NOT NULL` pointing at auth.users.id. Without this
// linking step the same person would arrive as a NEW AxeBOM user on first
// login, and every project, report and campaign the seed created would be
// attributed to somebody who no longer appears to exist.
//
// Matching is by email and by tenant name, both of which the seed controls.
func linkIdentities(ctx context.Context, res *iam.Result) error {
	cfg, err := config.LoadService("gateway")
	if err != nil {
		return err
	}
	pool, err := db.Open(ctx, cfg.Postgres)
	if err != nil {
		return fmt.Errorf("iam: connect to Postgres to link identities: %w", err)
	}
	defer pool.Close()

	// Raw, deliberately: this writes across tenants by design, and it runs as
	// an operator command rather than in a request path. It is the one place
	// the mapping is established, so it cannot itself be tenant-scoped.
	conn := pool.Raw()

	for _, org := range res.Orgs {
		if org.Slug == "" {
			continue
		}
		tag, err := conn.Exec(ctx,
			`UPDATE auth.tenants SET zitadel_org_id = $1, updated_at = now()
			  WHERE slug = $2 AND deleted_at IS NULL
			    AND (zitadel_org_id IS NULL OR zitadel_org_id = $1)`,
			org.ID, org.Slug)
		if err != nil {
			return fmt.Errorf("iam: link organisation %q: %w", org.Name, err)
		}
		if tag.RowsAffected() == 0 {
			// Not fatal: a ZITADEL org with no matching seeded tenant is
			// normal outside development. Say so rather than failing.
			fmt.Printf("  note: no seeded tenant with slug %q to link\n", org.Slug)
		}

		for _, u := range org.Users {
			tag, err := conn.Exec(ctx,
				`UPDATE auth.users
				    SET zitadel_user_id = $1, auth_provider = 'oidc', updated_at = now()
				  WHERE email = $2 AND deleted_at IS NULL
				    AND (zitadel_user_id IS NULL OR zitadel_user_id = $1)`,
				u.ID, u.Email)
			if err != nil {
				return fmt.Errorf("iam: link user %q: %w", u.Email, err)
			}
			if tag.RowsAffected() == 0 {
				fmt.Printf("  note: no seeded user %s to link\n", u.Email)
			}
		}
	}
	return nil
}

func printBootstrap(res *iam.Result, publicURL string) {
	fmt.Printf("ZITADEL provisioned at %s\n\n", res.Origin)
	fmt.Printf("  instance org   %s\n", res.AdminOrgID)
	fmt.Printf("  project        %s\n", res.ProjectID)
	fmt.Printf("  roles          %s + %s\n",
		strings.Join(res.RoleKeys, ", "), iam.ServiceRoleKey)
	fmt.Printf("  spa client_id  %s\n", res.SPAClientID)
	fmt.Printf("  api client_id  %s\n\n", res.APIClientID)

	for _, o := range res.Orgs {
		fmt.Printf("  org %-20s %s\n", o.Name, o.ID)
		for _, u := range o.Users {
			state := "exists"
			if u.Created {
				state = "created"
			}
			fmt.Printf("      %-20s %-20s %-8s %s\n", u.Email, u.ID, u.Role, state)
		}
	}
	if len(res.ServiceUsers) > 0 {
		fmt.Println()
		for _, s := range res.ServiceUsers {
			state := "exists"
			if s.Created {
				state = "created"
			}
			key := ""
			switch {
			case s.KeyMinted:
				key = "key minted -> " + s.KeyPath
			case s.KeyPath != "":
				key = "key exists -> " + s.KeyPath
			}
			fmt.Printf("  service %-16s %-20s %-8s %s\n", s.Name, s.ID, state, key)
		}
	}

	// The two values every other component needs. Printed as env lines so they
	// can be pasted rather than transcribed.
	fmt.Printf("\nPut these in .env — the SPA and the services both read them:\n\n")
	fmt.Printf("  ZITADEL_PROJECT_ID=%s\n", res.ProjectID)
	fmt.Printf("  ZITADEL_SPA_CLIENT_ID=%s\n", res.SPAClientID)
	fmt.Printf("  ZITADEL_ISSUER=%s\n\n", publicURL)
}

// ------------------------------------------------------------------- verify

func iamVerify(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("iam verify", flag.ExitOnError)
	f := bindIAMFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}

	pubHost, pubScheme := publicOrigin(f.publicURL)
	client, err := iam.Connect(ctx, iam.Config{
		Domain:       f.domain,
		Port:         f.port,
		Insecure:     f.insecure,
		KeyPath:      resolveFromRepoRoot(f.keyPath),
		PublicHost:   pubHost,
		PublicScheme: pubScheme,
	})
	if err != nil {
		return err
	}
	defer func() { _ = client.Close() }()

	// Verify is a bootstrap with nothing new to create. Every step is
	// find-or-create, so running it reports the current state without changing
	// it — and if something IS missing, it is repaired, which is the useful
	// behaviour for a command someone runs because login is broken.
	res, err := client.Bootstrap(ctx, iam.Spec{
		AdminOrg:    f.adminOrg,
		ProjectName: f.project,
		SPAName:     "AxeBOM Web",
		APIName:     "AxeBOM API",
		BrandName:   f.brandName,
		SPARedirectURIs: []string{
			f.publicURL + "/auth/callback",
			f.publicURL + "/auth/silent",
		},
		SPAPostLogoutURIs:  []string{f.publicURL + "/"},
		SPAAdditionalHosts: []string{f.publicURL},
		DevMode:            strings.HasPrefix(f.publicURL, "http://"),
		TrustedDomain:      hostOf(f.publicURL),
	})
	if err != nil {
		return err
	}

	fmt.Printf("issuer        %s\n", f.publicURL)
	fmt.Printf("management    %s\n", res.Origin)
	fmt.Printf("project       %s\n", res.ProjectID)
	fmt.Printf("spa client    %s\n", res.SPAClientID)
	fmt.Printf("roles         %s\n", strings.Join(res.RoleKeys, ", "))
	fmt.Println()

	return printTenantMapping(ctx)
}

// printTenantMapping is the answer to "why was my token rejected".
//
// A token carries a ZITADEL organisation id; RLS needs an AxeBOM tenant
// UUID. Every authentication failure that is not a bad signature is a missing
// row in this table.
func printTenantMapping(ctx context.Context) error {
	cfg, err := config.LoadService("gateway")
	if err != nil {
		return err
	}
	pool, err := db.Open(ctx, cfg.Postgres)
	if err != nil {
		return fmt.Errorf("iam: connect to Postgres: %w", err)
	}
	defer pool.Close()

	rows, err := pool.Raw().Query(ctx,
		`SELECT t.name, t.id::text, COALESCE(t.zitadel_org_id, '')
		   FROM auth.tenants t
		  WHERE t.deleted_at IS NULL
		  ORDER BY t.name`)
	if err != nil {
		return err
	}
	defer rows.Close()

	fmt.Printf("%-24s %-38s %s\n", "TENANT", "AXEBOM ID", "ZITADEL ORG")

	// ⚠ LINKED TENANTS ARE ALWAYS PRINTED; UNLINKED ONES ARE CAPPED.
	//
	// This command exists to answer "why was my token rejected", and the
	// answer is almost always in a LINKED row. The development database
	// accumulates hundreds of throwaway tenants from integration tests, and
	// printing every one buries the four rows somebody actually came to read
	// under a screen of noise — a diagnostic nobody scrolls is a diagnostic
	// nobody uses. The count below still reports the true total.
	const maxUnlinked = 5
	unlinked := 0
	for rows.Next() {
		var name, id, org string
		if err := rows.Scan(&name, &id, &org); err != nil {
			return err
		}
		if org == "" {
			unlinked++
			if unlinked > maxUnlinked {
				continue
			}
			org = "— not linked —"
		}
		fmt.Printf("%-24s %-38s %s\n", name, id, org)
	}
	if unlinked > maxUnlinked {
		fmt.Printf("%-24s %-38s %s\n",
			fmt.Sprintf("... and %d more", unlinked-maxUnlinked), "", "— not linked —")
	}
	if err := rows.Err(); err != nil {
		return err
	}

	if unlinked > 0 {
		fmt.Printf("\n%d tenant(s) have no ZITADEL organisation. Nobody can sign in to "+
			"them until they do —\nrun `axebom iam bootstrap` to create and link "+
			"the development organisations.\n", unlinked)
	}
	return nil
}

// resolveKeyPathForTests keeps filepath imported when the constant above moves.
var _ = filepath.Join
