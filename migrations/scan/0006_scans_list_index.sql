-- +goose Up
-- ===========================================================================
-- GET /v1/scans needs a keyset index it does not have.
--
-- scans_tenant_project_idx (migrations/scan/0001) is ordered on created_at,
-- which cannot serve a keyset paginated on id: `WHERE id < $cursor` against
-- that index still has to walk every row created_at DESC to find the ones
-- with a smaller id, degrading to a sequential scan under the tenant filter
-- as the table grows.
--
-- `id DESC` is the correct order to keyset on regardless: ids are UUIDv7, so
-- `ORDER BY id DESC` is already chronological, and unlike created_at it can
-- never tie — two scans created in the same millisecond still sort uniquely,
-- which a cursor needs to avoid skipping or repeating a row.
--
-- project_id is optional in the query (?project_id=), so it is the second
-- key rather than a separate index: a query with no project_id filter still
-- benefits from (tenant_id, id DESC) being a strict prefix of this index.
-- ===========================================================================

CREATE INDEX scans_tenant_project_id_idx ON scan.scans (tenant_id, project_id, id DESC);

-- +goose Down
DROP INDEX IF EXISTS scan.scans_tenant_project_id_idx;
