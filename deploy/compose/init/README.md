# Postgres init scripts

Mounted read-only at `/docker-entrypoint-initdb.d` by `docker-compose.yml`.

**This directory is deliberately empty of SQL.** Schema creation, the
`encorebom_app` role and the RLS helpers are owned by
`migrations/bootstrap/0001_schemas_role_helpers.sql` and applied by
`encorebom db migrate` — not by an init script.

The directory exists only so Docker does not create it root-owned on first
`compose up`. Putting SQL here would give the schema two sources of truth,
and the init path runs exactly once per volume, so a change here would
silently not apply to an existing stack.
