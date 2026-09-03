-- +goose Up
-- ===========================================================================
-- report.reports — add "docx" as a producible format.
--
-- services/report/internal/render/docx.go renders a real, valid .docx —
-- stdlib archive/zip + encoding/xml only, the same "structural guarantee,
-- not configured" security posture pdf.go's own network-isolation comment
-- documents for PDF (no third-party OOXML library in the path that could
-- resolve a remote reference or emit a live MS Word field code from
-- attacker-influenced BOM text). Wired the same way "pdf" already is:
-- service.parseFormat, worker.renderArtifact/mediaType, StorageKey (docx
-- needs no special-case extension, unlike spdx/cyclonedx's *.spdx.json /
-- *.cdx.json).
-- ===========================================================================

ALTER TABLE report.reports DROP CONSTRAINT reports_format_check;
ALTER TABLE report.reports ADD CONSTRAINT reports_format_check
    CHECK (format IN ('pdf','docx','xlsx','json','spdx','cyclonedx'));

-- +goose Down
ALTER TABLE report.reports DROP CONSTRAINT reports_format_check;
ALTER TABLE report.reports ADD CONSTRAINT reports_format_check
    CHECK (format IN ('pdf','xlsx','json','spdx','cyclonedx'));
