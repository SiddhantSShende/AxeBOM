// Package migrations embeds the SQL migration files.
//
// This package exists only so the files can be embedded. `go:embed` cannot
// reach outside its own package directory, and the migrations belong at the
// repository root where they are discoverable — not buried inside
// libs/go-shared/platform/db.
//
// Embedding rather than reading from disk means a deployed binary carries its
// own schema. A migration job that depends on a directory being shipped
// alongside it fails in exactly the environment where it is hardest to debug.
package migrations

import "embed"

// FS holds every migration, one directory per schema.
//
// `all:` includes files beginning with `_` or `.`, which the default pattern
// would skip.
//
//go:embed all:bootstrap all:auth all:project all:scan all:normalize
//go:embed all:report all:campaign all:comment all:notify
var FS embed.FS

// SeedFS holds development seed data.
//
// Kept separate from FS so it can never be picked up by a migration run. Seed
// data reaching production would be a quiet disaster: fake tenants, fake users,
// and known-value UUIDs in a real database.
//
//go:embed all:seed
var SeedFS embed.FS
