-- +goose Up
-- ===========================================================================
-- project.hardware_devices — a device is a row, not a convention.
--
-- ⚠ BEFORE THIS TABLE THERE WAS NO DEVICE ANYWHERE IN THE SCHEMA.
-- `grep -riE '\bdevice\b' migrations/` returned three comments and no tables.
--
-- In practice the level-0 row of normalize.hardware_components WAS the device:
-- fixtures/hbom-nested/parts.csv line 2 is an ENC-GW-4400 with a serial, a
-- manufacturer and an origin, and cdxgen_host.py synthesizes exactly such a
-- root. But it is a component row inside a VERSIONED document, which means:
--
--   * no stable identity — ReplaceHardwareTree writes a whole new document on
--     every re-import, so nothing about "this device" survives;
--   * no uniqueness or index on serial_number (only hardware_mpn_idx on
--     model_number), so the same physical unit could be registered twice with
--     nothing noticing;
--   * no way to address one — GET /v1/hbom/{projectId} returns `roots []` and
--     has no notion of WHICH device;
--   * one hardware tree per project, when a project is routinely a product line
--     with several devices in it.
--
-- ⚠ THIS TABLE IS IDENTITY AND REGISTRATION, NOT THE PARTS LIST.
--
-- The parts tree stays in normalize.hardware_components, versioned, immutable
-- per normalization (invariant 10). What lives here is the small, stable set a
-- human types once and then re-imports parts against.
--
-- ⚠ AND THE DUPLICATION WITH THE ROOT COMPONENT ROW IS DELIBERATE.
--
-- `manufacturer` here and `hardware_components.manufacturer_name` on the root
-- are two DIFFERENT facts that happen to usually agree: this is what the
-- customer REGISTERED, that is what a parse of their file PRODUCED. Collapsing
-- them would destroy the only signal that a schematic disagrees with the
-- device somebody believes they are documenting, which is exactly the kind of
-- discrepancy a hardware BOM exists to surface.
-- ===========================================================================

CREATE TABLE project.hardware_devices (
    id              uuid PRIMARY KEY DEFAULT app.uuid_v7(),
    tenant_id       uuid NOT NULL,
    project_id      uuid NOT NULL REFERENCES project.projects (id) ON DELETE CASCADE,

    -- What the customer calls it. The only required field: a device nobody can
    -- name is one nobody can find again.
    name            text NOT NULL CHECK (length(trim(name)) > 0),

    manufacturer    text,
    model_number    text,
    -- ⚠ serial AND lot are separate, because they answer different questions.
    -- A serial identifies ONE unit; a lot identifies a production batch. A
    -- board sampled from a batch has a lot and no serial, and recording the
    -- lot in the serial column would assert a uniqueness that is not true.
    serial_number   text,
    lot_number      text,
    -- The customer's own asset register id, if they have one. Not ours, and
    -- never generated — an invented asset tag is worse than none.
    asset_tag       text,

    firmware_version text,
    -- Where the unit physically is. Free text on purpose: "Rack 4, Pune DC"
    -- and "field-deployed, customer site 118" are both real answers and no
    -- enum covers them.
    location        text,

    -- CERT-In Table 11 element 23. Same closed set as
    -- normalize.hardware_components.criticality, and it must stay the same
    -- set — see the note on that column.
    criticality     text CHECK (criticality IS NULL OR criticality IN
                                ('critical', 'high', 'medium', 'low', 'unknown')),

    notes           text,

    created_by      uuid NOT NULL,   -- -> auth.users.id, no FK (cross-schema)
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    deleted_at      timestamptz
);

-- ⚠ UNIQUE ON SERIAL WITHIN A TENANT, NOT WITHIN A PROJECT, AND ONLY WHEN ONE
-- IS GIVEN.
--
-- A serial number identifies a physical unit. The same unit appearing in two
-- projects is a mistake worth refusing, not a legitimate modelling choice —
-- whereas two units of the same MODEL are entirely normal, which is why there
-- is no constraint on model_number. The partial index is what keeps a device
-- with no serial (a design under development, a batch sample) legal.
CREATE UNIQUE INDEX hardware_devices_serial_idx
    ON project.hardware_devices (tenant_id, serial_number)
    WHERE serial_number IS NOT NULL AND deleted_at IS NULL;

CREATE UNIQUE INDEX hardware_devices_asset_tag_idx
    ON project.hardware_devices (tenant_id, asset_tag)
    WHERE asset_tag IS NOT NULL AND deleted_at IS NULL;

CREATE INDEX hardware_devices_project_idx
    ON project.hardware_devices (tenant_id, project_id)
    WHERE deleted_at IS NULL;

-- Lookup by part number is a real workflow — "which of our devices use this
-- obsolete controller?" starts here.
CREATE INDEX hardware_devices_model_idx
    ON project.hardware_devices (tenant_id, model_number)
    WHERE model_number IS NOT NULL AND deleted_at IS NULL;

CREATE TRIGGER touch_updated_at BEFORE UPDATE ON project.hardware_devices
    FOR EACH ROW EXECUTE FUNCTION app.touch_updated_at();

SELECT app.enable_tenant_rls('project.hardware_devices');

-- +goose Down
DROP TABLE IF EXISTS project.hardware_devices;
