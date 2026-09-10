-- +goose Up
-- ===========================================================================
-- The `aibom` schema — the tenth service's own namespace.
--
-- ⚠ SCHEMA CREATION LIVES IN bootstrap, NOT IN THE SERVICE'S OWN DIRECTORY.
-- Every schema, the application role, and the RLS helpers are created here
-- because `MigrationOrder` runs bootstrap first and every later migration
-- calls `app.enable_tenant_rls`. A `CREATE SCHEMA` inside `migrations/aibom/`
-- would work exactly once — on a database where nothing else had needed it —
-- and would leave the grants below scattered across two places.
--
-- ⚠ WHY A TENTH SERVICE AT ALL, when `services/project` already writes the
-- operator-supplied half of Table 10.
--
-- Because it writes it onto `normalize.ai_models`, with a targeted UPDATE, and
-- that is a mutation of normalized data — the one thing CLAUDE.md invariant 10
-- says never happens. It worked only because the AIBOM normalize consumer
-- learned to read the previous document's values back before writing a new one
-- (M2's `load_prior_user_values`), which is a read-back hack compensating for a
-- write that should not exist.
--
-- Operator input is not a normalization OUTPUT. It is durable state a person
-- entered, it outlives every re-normalization by construction rather than by
-- rescue, and it belongs in a schema owned by the service that collects it.
-- ===========================================================================

CREATE SCHEMA IF NOT EXISTS aibom;

GRANT USAGE ON SCHEMA aibom TO axebom_app;

-- Same reasoning as 0001's block for the other eight schemas: default
-- privileges mean a new table in this schema is reachable by the application
-- role without every migration remembering to GRANT.
ALTER DEFAULT PRIVILEGES IN SCHEMA aibom
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO axebom_app;

ALTER DEFAULT PRIVILEGES IN SCHEMA aibom
  GRANT USAGE, SELECT ON SEQUENCES TO axebom_app;

-- +goose Down
DROP SCHEMA IF EXISTS aibom CASCADE;
