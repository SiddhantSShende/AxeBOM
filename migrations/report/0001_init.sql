-- +goose Up
-- ===========================================================================
-- report — rendered reports and share links.
-- Implements docs/01-DATA-MODEL.md §8.
-- ===========================================================================

CREATE TABLE report.reports (
    id                uuid PRIMARY KEY DEFAULT app.uuid_v7(),
    tenant_id         uuid NOT NULL,
    scan_id           uuid NOT NULL,   -- -> scan.scans.id, no FK (cross-schema)

    bom_document_ids  uuid[] NOT NULL DEFAULT '{}',
    bom_type          text NOT NULL,
    level             text NOT NULL
                      CHECK (level IN ('top_level','n_level','delivery','transitive','complete')),
    standard          text NOT NULL CHECK (standard IN ('SPDX','CycloneDX','native')),
    format            text NOT NULL CHECK (format IN ('pdf','xlsx','json','spdx','cyclonedx')),

    -- CERT-In §5.3.2 (p.32) requires BOTH versions be maintainable: a public
    -- one with non-sensitive information, and a private one containing
    -- vulnerability detail.
    visibility        text NOT NULL DEFAULT 'private'
                      CHECK (visibility IN ('public','private')),

    -- Rendering is ASYNC. A Complete BOM can exceed 50k components, and a
    -- synchronous request would time out long before the PDF finished.
    status            text NOT NULL DEFAULT 'queued'
                      CHECK (status IN ('queued','rendering','ready','failed')),

    storage_ref       text,
    sha256            text,
    size_bytes        bigint CHECK (size_bytes IS NULL OR size_bytes >= 0),

    -- Detached Ed25519 signature. CERT-In §5.3.3.2 and §5.3.5: integrity, and
    -- consumer-side verification via `axebom verify`.
    signature         text,
    signing_key_id    text,

    -- 50k components is 3000+ PDF pages. The cap produces a truncation NOTE
    -- pointing at the XLSX/JSON rather than an OOM.
    truncated         boolean NOT NULL DEFAULT false,
    truncation_note   text,

    error_code        text,
    created_at        timestamptz NOT NULL DEFAULT now(),
    updated_at        timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX reports_tenant_scan_idx ON report.reports (tenant_id, scan_id);
CREATE INDEX reports_status_idx      ON report.reports (status)
    WHERE status IN ('queued','rendering');

CREATE TRIGGER touch_updated_at BEFORE UPDATE ON report.reports
    FOR EACH ROW EXECUTE FUNCTION app.touch_updated_at();

SELECT app.enable_tenant_rls('report.reports');

-- ---------------------------------------------------------------------------
-- share_links
--
-- Only the HASH of the token is stored. A database read must not yield a
-- working link — the same reasoning as auth.sessions.
-- ---------------------------------------------------------------------------
CREATE TABLE report.share_links (
    id              uuid PRIMARY KEY DEFAULT app.uuid_v7(),
    tenant_id       uuid NOT NULL,
    report_id       uuid NOT NULL REFERENCES report.reports (id) ON DELETE CASCADE,

    token_hash      text NOT NULL UNIQUE,
    expires_at      timestamptz,
    max_downloads   int CHECK (max_downloads IS NULL OR max_downloads > 0),
    download_count  int NOT NULL DEFAULT 0 CHECK (download_count >= 0),

    created_by      uuid NOT NULL,
    revoked_at      timestamptz,
    created_at      timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX share_links_report_idx ON report.share_links (report_id);
CREATE INDEX share_links_tenant_idx ON report.share_links (tenant_id);
CREATE INDEX share_links_active_idx ON report.share_links (expires_at)
    WHERE revoked_at IS NULL;

SELECT app.enable_tenant_rls('report.share_links');

-- +goose Down
DROP TABLE IF EXISTS report.share_links;
DROP TABLE IF EXISTS report.reports;
