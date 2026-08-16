-- +goose Up
-- ===========================================================================
-- engine_runs.error_code / error_message
--
-- A FAILED ENGINE MUST BE ABLE TO SAY WHY.
--
-- scan.scans already carries these; engine_runs did not, which left a failed
-- run with nowhere to record its cause. `diagnostics` is the wrong home: those
-- are NON-FATAL problems that explain a `partial` status, and mixing a terminal
-- failure into them would make "did this engine work?" unanswerable without
-- reading prose.
--
-- Without this the UI can only offer "it failed", which is not actionable, and
-- the Engine Coverage section cannot distinguish "timed out" from "crashed".
--
-- Recorded in docs/01-DATA-MODEL.md §3.
-- ===========================================================================

ALTER TABLE scan.engine_runs
    ADD COLUMN error_code    text,
    ADD COLUMN error_message text;

COMMENT ON COLUMN scan.engine_runs.error_code IS
'Stable machine code from the error taxonomy for a terminal failure. Distinct
from diagnostics, which are non-fatal problems explaining a partial status.';

-- +goose Down
ALTER TABLE scan.engine_runs
    DROP COLUMN IF EXISTS error_code,
    DROP COLUMN IF EXISTS error_message;
