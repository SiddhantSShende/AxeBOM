-- +goose Up
-- ===========================================================================
-- project.hardware_devices.criticality — four values, like everything else.
--
-- ⚠ THIS COLUMN ACCEPTED A VALUE THAT COULD NEVER SURVIVE THE JOURNEY.
--
-- Its CHECK allowed {critical, high, medium, low, unknown}. Three other places
-- allow four: the compliance profile (element 23, p.23, transcribed verbatim),
-- normalize.hardware_components' own CHECK, and workers/hbom/model.py's
-- CRITICALITY_VALUES. So a device registered as `unknown` was stored here and
-- was unrepresentable in the parts table its tree flows into.
--
-- The Go constant that fed the device form carried the same fifth value —
-- under a comment reading "⚠ IT MUST MATCH normalize.hardware_components.
-- criticality". The comment stated precisely the invariant the line below it
-- broke. Both now derive from the profile, and this brings the column with
-- them.
--
-- ⚠ NO CAPABILITY IS LOST. Leaving criticality NULL already means exactly what
-- `unknown` meant, and the product reports it as `not-provided`; CLAUDE.md
-- invariant 3 scores both as zero either way. What is lost is a dropdown option
-- that looked recordable and was not transportable.
--
-- ⚠ VERIFIED EMPTY BEFORE WRITING THIS: 0 rows in the dev database use
-- 'unknown'. The UPDATE below is belt-and-braces for any environment that has
-- one — NULL is the honest landing place, being what the value already meant.
UPDATE project.hardware_devices SET criticality = NULL WHERE criticality = 'unknown';

ALTER TABLE project.hardware_devices
    DROP CONSTRAINT IF EXISTS hardware_devices_criticality_check;

ALTER TABLE project.hardware_devices
    ADD CONSTRAINT hardware_devices_criticality_check
    CHECK (criticality IS NULL OR criticality IN ('critical', 'high', 'medium', 'low'));

-- +goose Down
ALTER TABLE project.hardware_devices
    DROP CONSTRAINT IF EXISTS hardware_devices_criticality_check;

ALTER TABLE project.hardware_devices
    ADD CONSTRAINT hardware_devices_criticality_check
    CHECK (criticality IS NULL OR criticality IN ('critical', 'high', 'medium', 'low', 'unknown'));
