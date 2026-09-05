-- +goose Up
-- ===========================================================================
-- normalize.bom_documents.device_id — which device this parts list describes.
--
-- ⚠ A PLAIN uuid WITH NO FOREIGN KEY, exactly as project_id and scan_id are.
-- project.hardware_devices lives in another service's schema, and an FK across
-- that boundary is a JOIN dependency that would block extracting the service
-- later (ADR-0001 mitigation 2, and the note at the head of
-- migrations/project/0001_init.sql). Referential integrity across schemas is
-- the application's job.
--
-- NULL is the ordinary state and stays legal forever: every HBOM document
-- written before devices existed has no device, and a project-level import that
-- names no device still works exactly as it did. The column narrows a query, it
-- does not gate one.
-- ===========================================================================

ALTER TABLE normalize.bom_documents ADD COLUMN device_id uuid;

CREATE INDEX bom_documents_device_idx
    ON normalize.bom_documents (tenant_id, device_id, bom_type, generated_at DESC)
    WHERE device_id IS NOT NULL;

-- +goose Down
DROP INDEX IF EXISTS normalize.bom_documents_device_idx;
ALTER TABLE normalize.bom_documents DROP COLUMN IF EXISTS device_id;
