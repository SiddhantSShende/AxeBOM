-- +goose Up
-- ===========================================================================
-- report.reports — add "mlbom" as a producible format.
--
-- ⚠ THE CycloneDX ML-BOM IS A DIFFERENT DOCUMENT FROM THE `cyclonedx` ONE,
-- WHICH IS WHY IT NEEDS ITS OWN VALUE RATHER THAN A FLAG.
--
-- `cyclonedx` is serialized by protobom and maps every AI model onto a generic
-- component with namespaced properties. protobom v0.5.8's `sbom.Node` has no
-- `modelCard` — the string does not appear anywhere in the module — so every
-- ML-aware consumer reads an AIBOM exported that way as a list of unremarkable
-- software. `mlbom` is serialized by `services/report/internal/export/mlbom.go`
-- through CycloneDX's own Go library and carries `modelCard`,
-- `modelParameters`, dataset `data` components and the inference services.
--
-- Both are CycloneDX 1.6 and both validate against the same schema; the
-- difference is content, not format, which is why `parseStandard` maps `mlbom`
-- onto the CycloneDX standard rather than inventing a second one.
--
-- ⚠ THIS CONSTRAINT CAUGHT THE FORMAT BEFORE A CUSTOMER DID, AND THAT IS THE
-- POINT OF IT. `service.parseFormat` accepted `mlbom` the moment the renderer
-- existed; the row insert failed with a check violation, so the API answered
-- 500 rather than storing a format nothing could render. A closed set in Go and
-- a closed set in SQL are two statements of one rule, and they drift the moment
-- only one of them is updated.
-- ===========================================================================

ALTER TABLE report.reports DROP CONSTRAINT reports_format_check;
ALTER TABLE report.reports ADD CONSTRAINT reports_format_check
    CHECK (format IN ('pdf','docx','xlsx','json','spdx','cyclonedx','mlbom'));

-- +goose Down
ALTER TABLE report.reports DROP CONSTRAINT reports_format_check;
ALTER TABLE report.reports ADD CONSTRAINT reports_format_check
    CHECK (format IN ('pdf','docx','xlsx','json','spdx','cyclonedx'));
