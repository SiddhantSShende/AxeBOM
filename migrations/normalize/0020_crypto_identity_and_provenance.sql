-- +goose Up
-- ===========================================================================
-- normalize.crypto_assets — identity, evidence and attributes.
-- normalize.crypto_asset_provenance — which engines saw each asset.
--
-- ⚠ A CRYPTO ASSET HAD NO IDENTITY, SO A SECOND ENGINE COULD ONLY DUPLICATE IT.
--
-- `component_key` held the ENGINE's own `bom-ref` — for cbomkit-theia a random
-- UUID minted per run — so nothing in the database could say whether two rows
-- were the same RSA key, and the moment a second crypto engine (source-code
-- discovery) reported an algorithm theia also reported, the CBOM would have
-- listed it twice. `asset_key` is the crypto counterpart of `components.
-- component_key` and `ai_models.model_key`, produced by the normalizer from the
-- ladder in docs/03-NORMALIZER-SPEC.md §1.6. Every tier is prefixed
-- (`algorithm:` / `key:` / `cert:` / `protocol:` / `name:` / `opaque:`) so two
-- tiers can never collide.
--
-- ⚠ `asset_key` IS UNIQUE PER DOCUMENT, NOT GLOBALLY. The same algorithm appears
-- in many documents and at successive normalization versions (invariant 10).
--
-- ⚠ `evidence` IS WHERE THE ASSET WAS SEEN, VERBATIM — [{path, line, engine}],
-- repository-relative. It existed in every engine's output all along and was
-- thrown away after guessing a "surface" from it, so no report could say where
-- a key or an algorithm was. Location is evidence, never identity (§1.4): the
-- same certificate in two folders is one certificate with two locations.
--
-- ⚠ `attributes` HOLDS FACTS THAT ARE NOT CERT-In FIELDS — padding, curve,
-- parameter set, NIST quantum category (0–6), key-material type, whether a
-- private key was committed. Evidence only; never scored.
-- ===========================================================================

-- ⚠ FORCE IS LIFTED FOR THE LENGTH OF THIS MIGRATION, THE WAY 0012 AND 0016 DO
-- IT: the backfill below is a data statement, and under FORCE ROW LEVEL SECURITY
-- a non-superuser owner would evaluate an unset `app.current_tenant_id` and fail.
ALTER TABLE normalize.crypto_assets NO FORCE ROW LEVEL SECURITY;

ALTER TABLE normalize.crypto_assets
    ADD COLUMN asset_key           text,
    ADD COLUMN identity_rule       text,
    ADD COLUMN identity_confidence text,
    ADD COLUMN evidence            jsonb NOT NULL DEFAULT '[]'::jsonb,
    ADD COLUMN attributes          jsonb NOT NULL DEFAULT '{}'::jsonb;

-- ⚠ THE BACKFILL IS OPAQUE, NOT RECONSTRUCTED — the reasoning 0016 gives. Rows
-- written before this migration came from a pipeline that computed no identity;
-- minting a plausible key for them would assert an identity nobody established.
-- `opaque:` never merges with anything, and re-normalizing stored artifacts at
-- the new ruleset replaces these rows with real keys (ADR-0003).
UPDATE normalize.crypto_assets
   SET asset_key = 'opaque:' || id::text,
       identity_rule = 'opaque',
       identity_confidence = 'low'
 WHERE asset_key IS NULL;

ALTER TABLE normalize.crypto_assets
    ALTER COLUMN asset_key SET NOT NULL,
    ALTER COLUMN identity_rule SET NOT NULL,
    ALTER COLUMN identity_confidence SET NOT NULL,
    ADD CONSTRAINT crypto_assets_document_asset_key_key UNIQUE (bom_document_id, asset_key),
    ADD CONSTRAINT crypto_assets_identity_rule_check CHECK (identity_rule IN (
        'algorithm',
        'algorithm-name',
        'key-fingerprint',
        'key-location',
        'certificate-fingerprint',
        'certificate-issuer-serial',
        'certificate-subject-issuer-validity',
        'protocol',
        'name',
        'opaque'
    )),
    ADD CONSTRAINT crypto_assets_identity_confidence_check
        CHECK (identity_confidence IN ('high', 'medium', 'low'));

ALTER TABLE normalize.crypto_assets FORCE ROW LEVEL SECURITY;

CREATE INDEX crypto_assets_asset_key_idx ON normalize.crypto_assets (asset_key);

COMMENT ON COLUMN normalize.crypto_assets.asset_key IS
    'Merge key from the 03-NORMALIZER-SPEC §1.6 ladder. Prefixed per tier; never an engine bom-ref.';
COMMENT ON COLUMN normalize.crypto_assets.identity_rule IS
    'Which §1.6 ladder rule produced asset_key. The CHECK mirrors the normalizer''s closed set.';
COMMENT ON COLUMN normalize.crypto_assets.evidence IS
    'Where each engine saw this asset: [{path, line, engine}], repository-relative, verbatim.';
COMMENT ON COLUMN normalize.crypto_assets.attributes IS
    'Non-CERT-In facts (padding, curve, parameter set, NIST quantum category, material type, committed private key). Never scored.';

CREATE TABLE normalize.crypto_asset_provenance (
    id              uuid PRIMARY KEY DEFAULT app.uuid_v7(),
    tenant_id       uuid NOT NULL,
    crypto_asset_id uuid NOT NULL REFERENCES normalize.crypto_assets (id) ON DELETE CASCADE,

    engine_id       text NOT NULL,
    engine_version  text,

    -- The engine's own reference for the asset (a CycloneDX bom-ref). Kept for
    -- tracing back into the raw artifact; ⚠ NEVER an identity input — theia
    -- mints a fresh random bom-ref on every run.
    native_ref      text,

    -- What that engine called it, verbatim. Engines disagree (`SHA256-RSA`,
    -- `SHA256withRSA`, `sha256WithRSAEncryption`) and the disagreement is worth
    -- being able to see afterwards.
    observed_name   text,

    -- Which stored raw artifact this came from (ADR-0003: immutable evidence).
    artifact_sha256 text,

    -- Where THIS engine saw it. Two engines can evidence one asset from
    -- different lines; merging the arrays would lose which said what.
    evidence        jsonb NOT NULL DEFAULT '[]'::jsonb,

    created_at      timestamptz NOT NULL DEFAULT now(),

    UNIQUE (crypto_asset_id, engine_id)
);

CREATE INDEX crypto_asset_provenance_asset_idx  ON normalize.crypto_asset_provenance (crypto_asset_id);
CREATE INDEX crypto_asset_provenance_tenant_idx ON normalize.crypto_asset_provenance (tenant_id);

SELECT app.enable_tenant_rls('normalize.crypto_asset_provenance');

-- ⚠ EXPLICIT, for the reason 0011 and 0018 record: default privileges are per
-- grantor, and the failure mode without this is `permission denied` on the first
-- live CBOM normalization.
GRANT SELECT, INSERT ON normalize.crypto_asset_provenance TO axebom_normalize_writer;

-- +goose Down
DROP TABLE IF EXISTS normalize.crypto_asset_provenance;

DROP INDEX IF EXISTS normalize.crypto_assets_asset_key_idx;

ALTER TABLE normalize.crypto_assets
    DROP CONSTRAINT IF EXISTS crypto_assets_identity_confidence_check,
    DROP CONSTRAINT IF EXISTS crypto_assets_identity_rule_check,
    DROP CONSTRAINT IF EXISTS crypto_assets_document_asset_key_key,
    DROP COLUMN IF EXISTS attributes,
    DROP COLUMN IF EXISTS evidence,
    DROP COLUMN IF EXISTS identity_confidence,
    DROP COLUMN IF EXISTS identity_rule,
    DROP COLUMN IF EXISTS asset_key;
