-- +goose Up
-- ===========================================================================
-- project — projects, classifications, CERT-In practices, sources.
-- Implements docs/01-DATA-MODEL.md §2.
--
-- NOTE ON CROSS-SCHEMA REFERENCES: created_by points at auth.users but carries
-- NO foreign key. An FK is a JOIN dependency that would block extracting this
-- service later (ADR-0001 mitigation 2). Referential integrity across schemas
-- is the application's job.
-- ===========================================================================

CREATE TABLE project.projects (
    id              uuid PRIMARY KEY DEFAULT app.uuid_v7(),
    tenant_id       uuid NOT NULL,
    name            text NOT NULL,
    description     text,

    source_type     text NOT NULL
                    CHECK (source_type IN ('github', 'gitlab', 'bitbucket',
                                           'upload', 'image', 'manual')),

    -- CERT-In §3.2 (PDF p.12-13). Read the allowed values from the compliance
    -- profile, never from a hardcoded list in application code.
    sdlc_stage      text NOT NULL DEFAULT 'source'
                    CHECK (sdlc_stage IN ('design', 'source', 'build',
                                          'analyzed', 'deployed', 'runtime')),

    validity_start  date,
    validity_end    date,

    owner_name      text,
    owner_email     citext,
    owner_github    text,
    owner_phone     text,

    created_by      uuid NOT NULL,   -- -> auth.users.id, no FK (see header)
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    deleted_at      timestamptz,

    UNIQUE (tenant_id, name),
    -- Enforced in the schema, not only the handler: a validity window that
    -- ends before it starts renders as a nonsense compliance claim.
    CONSTRAINT validity_window_ordered
        CHECK (validity_end IS NULL OR validity_start IS NULL
               OR validity_end >= validity_start)
);

CREATE INDEX projects_tenant_idx ON project.projects (tenant_id)
    WHERE deleted_at IS NULL;

CREATE TRIGGER touch_updated_at BEFORE UPDATE ON project.projects
    FOR EACH ROW EXECUTE FUNCTION app.touch_updated_at();

SELECT app.enable_tenant_rls('project.projects');

-- ---------------------------------------------------------------------------
-- classifications — a project may carry ANY subset of the five BOM types.
--
-- tenant_id is denormalized here on purpose. RLS predicates cannot traverse a
-- foreign key without a subquery on every row, so every tenant-scoped table
-- carries its own tenant_id.
-- ---------------------------------------------------------------------------
CREATE TABLE project.project_classifications (
    project_id  uuid NOT NULL REFERENCES project.projects (id) ON DELETE CASCADE,
    tenant_id   uuid NOT NULL,
    bom_type    text NOT NULL
                CHECK (bom_type IN ('SBOM', 'CBOM', 'QBOM', 'AIBOM', 'HBOM')),
    created_at  timestamptz NOT NULL DEFAULT now(),

    PRIMARY KEY (project_id, bom_type)
);

CREATE INDEX project_classifications_tenant_idx
    ON project.project_classifications (tenant_id, bom_type);

SELECT app.enable_tenant_rls('project.project_classifications');

-- ---------------------------------------------------------------------------
-- practices — CERT-In Table 5, category 3 (PDF p.22).
--
-- THE COMMONLY-MISSED MINIMUM ELEMENT. "Minimum Elements" is three categories,
-- not just the 21 data fields: Data Fields, Automation Support, AND Practices
-- and Processes. These six are per-PROJECT settings captured at registration,
-- not a report section. A tool implementing only the data fields and claiming
-- CERT-In compliance is overstating.
-- ---------------------------------------------------------------------------
CREATE TABLE project.practices (
    project_id      uuid PRIMARY KEY REFERENCES project.projects (id) ON DELETE CASCADE,
    tenant_id       uuid NOT NULL,

    -- certin.sbom.pp.frequency — cron expression or human cadence.
    frequency       text,
    -- certin.sbom.pp.depth
    depth           text CHECK (depth IS NULL OR depth IN
                        ('top_level', 'n_level', 'delivery', 'transitive', 'complete')),
    -- certin.sbom.pp.known_unknowns — auto-seeded by the normalizer from
    -- ecosystems detected with no available engine; the user may extend it.
    known_unknowns  text,
    -- certin.sbom.pp.distribution_and_delivery
    distribution    text,
    -- certin.sbom.pp.access_control — CERT-In §5.3.2 requires BOTH a public
    -- and a private version be maintainable.
    access_control  text CHECK (access_control IS NULL
                                OR access_control IN ('public', 'private')),
    -- certin.sbom.pp.accommodation_of_mistakes — the errata mechanism.
    errata_policy   text,

    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX practices_tenant_idx ON project.practices (tenant_id);

CREATE TRIGGER touch_updated_at BEFORE UPDATE ON project.practices
    FOR EACH ROW EXECUTE FUNCTION app.touch_updated_at();

SELECT app.enable_tenant_rls('project.practices');

-- ---------------------------------------------------------------------------
-- repository_connections
-- ---------------------------------------------------------------------------
CREATE TABLE project.repository_connections (
    id               uuid PRIMARY KEY DEFAULT app.uuid_v7(),
    tenant_id        uuid NOT NULL,
    project_id       uuid NOT NULL REFERENCES project.projects (id) ON DELETE CASCADE,

    provider         text NOT NULL
                     CHECK (provider IN ('github', 'gitlab', 'bitbucket')),
    repo_url         text NOT NULL,
    -- The provider's NUMERIC id. Repository names change; this does not.
    repo_external_id text,
    default_branch   text,

    -- A VAULT PATH, never a token. If a token string ever lands in this
    -- column, a database backup becomes a credential dump.
    credential_ref   text,

    last_synced_at   timestamptz,
    created_at       timestamptz NOT NULL DEFAULT now(),
    updated_at       timestamptz NOT NULL DEFAULT now(),

    UNIQUE (project_id, repo_url)
);

CREATE INDEX repo_connections_tenant_idx ON project.repository_connections (tenant_id, project_id);

CREATE TRIGGER touch_updated_at BEFORE UPDATE ON project.repository_connections
    FOR EACH ROW EXECUTE FUNCTION app.touch_updated_at();

SELECT app.enable_tenant_rls('project.repository_connections');

-- ---------------------------------------------------------------------------
-- uploads — manifests, lockfiles, source archives, HBOM CSVs.
--
-- Phase 4 stores these; it does NOT extract them. Extraction is untrusted-input
-- handling and belongs in the Phase 5 sandbox.
-- ---------------------------------------------------------------------------
CREATE TABLE project.uploads (
    id                 uuid PRIMARY KEY DEFAULT app.uuid_v7(),
    tenant_id          uuid NOT NULL,
    project_id         uuid NOT NULL REFERENCES project.projects (id) ON DELETE CASCADE,

    kind               text NOT NULL
                       CHECK (kind IN ('source_archive', 'manifest', 'lockfile',
                                       'sbom', 'hbom_csv', 'image_tarball')),
    storage_ref        text NOT NULL,
    sha256             text NOT NULL,
    size_bytes         bigint NOT NULL CHECK (size_bytes >= 0),
    -- Sanitized and truncated BEFORE insert: user filenames contain newlines,
    -- NUL bytes and 8KB paths, and a NUL silently truncates a text value.
    original_filename  text,

    uploaded_by        uuid NOT NULL,   -- -> auth.users.id, no FK
    created_at         timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX uploads_tenant_project_idx ON project.uploads (tenant_id, project_id);
CREATE INDEX uploads_sha_idx            ON project.uploads (sha256);

SELECT app.enable_tenant_rls('project.uploads');

-- +goose Down
DROP TABLE IF EXISTS project.uploads;
DROP TABLE IF EXISTS project.repository_connections;
DROP TABLE IF EXISTS project.practices;
DROP TABLE IF EXISTS project.project_classifications;
DROP TABLE IF EXISTS project.projects;
