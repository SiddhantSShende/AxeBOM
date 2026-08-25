package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/axebom/axebom/libs/go-shared/auth"
	"github.com/axebom/axebom/libs/go-shared/platform/config"
)

// runAPIKey is an operator escape hatch for minting a credential without a
// browser session — CI bootstrapping (perf/*.js needs one; see its own
// README) and local scripting are the two real uses.
//
// ⚠ SAME OWNER-CONNECTION SHAPE AS `audit export`, AND FOR THE SAME REASON:
// this is a local operator tool run outside the application path, not a
// second way to mint a key that skips ResourceAPIKey's RoleOwner gate — the
// real product surface is POST /v1/api-keys, authenticated and authorized
// like everything else. This exists because a CI job has no browser to sign
// in with, not to make minting easier for a person who does.
func runAPIKey(ctx context.Context, args []string) error {
	if len(args) == 0 || args[0] != "mint" {
		return fmt.Errorf("usage: axebom apikey mint --tenant <id> --name <name> --scopes scan:run,report:read [--created-by <user-id>] [--ttl-days N]")
	}

	fs := flag.NewFlagSet("apikey mint", flag.ContinueOnError)
	tenantID := fs.String("tenant", "", "tenant id the key belongs to (required)")
	name := fs.String("name", "", "a name the key can be revoked by (required)")
	scopesRaw := fs.String("scopes", "", "comma-separated scopes, e.g. scan:run,report:read (required)")
	createdBy := fs.String("created-by", "", "auth.users id to attribute the key to (required)")
	ttlDays := fs.Int("ttl-days", 0, "key lifetime in days (default: apikey.DefaultTTL)")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if *tenantID == "" || *name == "" || *scopesRaw == "" || *createdBy == "" {
		return fmt.Errorf("--tenant, --name, --scopes and --created-by are all required")
	}

	scopes, err := auth.ParseScopes(strings.Split(*scopesRaw, ","))
	if err != nil {
		return err
	}
	var ttl time.Duration
	if *ttlDays > 0 {
		ttl = time.Duration(*ttlDays) * 24 * time.Hour
	}

	minted, err := auth.Mint(*tenantID, *name, *createdBy, scopes, ttl, time.Now())
	if err != nil {
		return err
	}

	cfg, err := config.LoadService("gateway") // any service's Postgres config works
	if err != nil {
		return err
	}
	conn, err := pgx.Connect(ctx, cfg.Postgres.AdminDSN())
	if err != nil {
		return fmt.Errorf("connect as owner (%s): %w", cfg.Postgres.Redacted(), err)
	}
	defer func() { _ = conn.Close(ctx) }()

	err = conn.QueryRow(ctx, `
		INSERT INTO auth.api_keys
			(tenant_id, name, key_id, hash, scopes, created_by, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING id, created_at`,
		*tenantID, minted.Record.Name, minted.Record.KeyID, minted.Record.Hash,
		auth.ScopeStrings(minted.Record.Scopes), *createdBy, minted.Record.ExpiresAt,
	).Scan(&minted.Record.ID, &minted.Record.CreatedAt)
	if err != nil {
		return fmt.Errorf("store api key: %w", err)
	}

	// ⚠ THE KEY, AND ONLY THE KEY, ON STDOUT. Everything else goes to stderr
	// so `KEY=$(axebom apikey mint ...)` works in a script without the
	// informational line ending up inside the credential.
	fmt.Println(minted.Key)
	fmt.Fprintf(os.Stderr, "id=%s key_id=%s expires=%s\n",
		minted.Record.ID, minted.Record.KeyID,
		minted.Record.ExpiresAt.UTC().Format(time.RFC3339))
	return nil
}
