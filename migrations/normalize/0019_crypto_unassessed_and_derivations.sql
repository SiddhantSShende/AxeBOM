-- +goose Up
-- ===========================================================================
-- crypto_assets — an `unassessed` deprecation status, and `derivations`.
--
-- ⚠ `unassessed` IS NOT `current`, AND THE CONSTRAINT FORCED THE LIE.
--
-- The CHECK from 0003 allowed current/deprecated/weak/broken and nothing else,
-- so the deprecation rules had no way to say "no verdict". Every path that
-- could not reach one — an RSA key with no reported size, an unnamed asset, an
-- algorithm no rule recognised, a protocol with no version — was written as
-- `current` with an apologetic rationale. A reviewer filtering on status saw all
-- of them as fine, and the unsized RSA key is the one most likely to be a legacy
-- 1024-bit key.
--
-- The value set is axebom_shared.crypto.deprecation.STATUSES; the compliance
-- profile's `axebom.crypto.deprecation_status` extension lists the same values,
-- and libs/py-shared/axebom_shared/crypto/test_crypto.py holds all three
-- together.
--
-- ⚠ `derivations` SAYS WHICH CERT-In VALUES AXEBOM FILLED, AND FROM WHERE.
--
-- When an engine identifies an algorithm exactly ("AES-256-GCM") but does not
-- report a CERT-In field (classical security level, OID), the normalizer fills
-- it from a closed, cited reference table (axebom_shared.crypto.reference). The
-- value is real and counts as present for completeness; this column names the
-- source of each one — {column: reference_id} — so every report can footnote it
-- and a reader can tell an engine's claim from AxeBOM's lookup. An empty object
-- means every value on the row came from the engine.
-- ===========================================================================

ALTER TABLE normalize.crypto_assets
    DROP CONSTRAINT crypto_assets_deprecation_status_check;

ALTER TABLE normalize.crypto_assets
    ADD CONSTRAINT crypto_assets_deprecation_status_check CHECK (
        deprecation_status IS NULL OR
        deprecation_status IN ('current', 'deprecated', 'weak', 'broken', 'unassessed'));

ALTER TABLE normalize.crypto_assets
    ADD COLUMN derivations jsonb NOT NULL DEFAULT '{}'::jsonb;

COMMENT ON COLUMN normalize.crypto_assets.derivations IS
'Which CERT-In columns on this row AxeBOM filled from a cited reference table
rather than the engine reporting them: {column: reference_id}, the reference ids
defined in axebom_shared.crypto.reference. Such a value counts as present, and
every report footnotes it with its source. Empty means engine-reported only.';

-- +goose Down
ALTER TABLE normalize.crypto_assets DROP COLUMN IF EXISTS derivations;

ALTER TABLE normalize.crypto_assets
    DROP CONSTRAINT crypto_assets_deprecation_status_check;

-- NOT VALID: rows already written with `unassessed` stay exactly as written.
-- Normalized data is never rewritten in place (CLAUDE.md invariant 10); the
-- narrower constraint applies to new rows only.
ALTER TABLE normalize.crypto_assets
    ADD CONSTRAINT crypto_assets_deprecation_status_check CHECK (
        deprecation_status IS NULL OR
        deprecation_status IN ('current', 'deprecated', 'weak', 'broken')) NOT VALID;
