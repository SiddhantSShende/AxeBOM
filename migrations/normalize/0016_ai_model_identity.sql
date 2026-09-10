-- +goose Up
-- ===========================================================================
-- normalize.ai_models — identity, evidence, provenance and verification.
--
-- ⚠ THIS TABLE HAD NO IDENTITY COLUMN, AND THAT IS WHY ONE MODEL BECAME THREE
-- ROWS. Every other canonical table carries the key it merges on:
-- `components.component_key`, `crypto_assets.component_key`. `ai_models` carried
-- only `model_name`, so the merge key existed for the length of one Python
-- dictionary and was then thrown away — leaving nothing in the database that
-- could say whether two rows were the same model, and no way to find out later.
--
-- Measured before this migration, on real data: a single repository using
-- `meta-llama/Llama-3-8B` produced three rows named `transformers`,
-- `HuggingFace Transformers` and `HuggingFace Transformers Model`. Those are
-- three labels the engine gave one Python library; the actual model appeared in
-- none of them.
--
-- `model_key` is the AI-model counterpart of `03-NORMALIZER-SPEC.md` §1.2's
-- `component_key` ladder, produced by `workers/aibom/identity.py`. Every tier is
-- prefixed (`purl:` / `hash:` / `oci:` / `api:` / `file:` / `name:` / `opaque:`)
-- so two tiers can never collide even with identical payloads.
--
-- ⚠ `model_key` IS NOT UNIQUE, AND MUST NOT BE. The same model legitimately
-- appears in many documents, and in the same document at successive
-- normalization versions (CLAUDE.md invariant 10 — version, never overwrite).
-- Uniqueness belongs to `(bom_document_id, model_key)`, which is what
-- `bulk._ai_model_id`'s uuid5 already derives its surrogate from.
-- ===========================================================================

-- ⚠ FORCE IS LIFTED FOR THE LENGTH OF THIS MIGRATION, THE WAY 0012 DOES IT.
--
-- normalize.ai_models carries FORCE ROW LEVEL SECURITY (migration 0003's
-- `app.enable_tenant_rls`), which applies the tenant policy to the table OWNER
-- too. The backfill below is a data statement, so under a non-superuser owner it
-- would evaluate `current_setting('app.current_tenant_id')` — unset during a
-- migration — and fail. It happens to work on a superuser-owned dev database,
-- which is exactly the kind of difference that surfaces first in production.
ALTER TABLE normalize.ai_models NO FORCE ROW LEVEL SECURITY;

ALTER TABLE normalize.ai_models
    ADD COLUMN model_key     text,
    ADD COLUMN identity_rule text,
    ADD COLUMN identity_confidence text,
    ADD COLUMN source_engine text,
    ADD COLUMN evidence      jsonb NOT NULL DEFAULT '[]'::jsonb,
    ADD COLUMN verified      boolean NOT NULL DEFAULT false;

-- ⚠ THE BACKFILL IS DELIBERATELY OPAQUE, NOT RECONSTRUCTED.
--
-- Rows written before this migration were produced by a pipeline that computed no
-- identity, so there is no key to recover — only a name that was, for the rows
-- this actually affects, the name of the wrong thing. Deriving `name:<model_name>`
-- from them would mint a plausible-looking key asserting an identity nobody
-- established, which is precisely the fabrication this whole change is about.
--
-- `opaque:` is the ladder's own "never merges with anything" tier, so these rows
-- stay individually addressable, never dedup against each other, and are visibly
-- pre-identity to anyone reading them. Re-running normalization at a new version
-- replaces them with real keys; that is the designed path (ADR-0003).
UPDATE normalize.ai_models
   SET model_key = 'opaque:' || id::text,
       identity_rule = 'opaque',
       identity_confidence = 'low'
 WHERE model_key IS NULL;

ALTER TABLE normalize.ai_models
    ALTER COLUMN model_key SET NOT NULL,
    ALTER COLUMN identity_rule SET NOT NULL,
    ALTER COLUMN identity_confidence SET NOT NULL;

ALTER TABLE normalize.ai_models FORCE ROW LEVEL SECURITY;

-- Reading "every document this model appears in" is the dependency-explorer query
-- and the lineage query; both start from the key.
CREATE INDEX ai_models_model_key_idx ON normalize.ai_models (model_key);

COMMENT ON COLUMN normalize.ai_models.model_key IS
    'Merge key from workers/aibom/identity.py. Prefixed per tier; never a package purl.';
COMMENT ON COLUMN normalize.ai_models.identity_rule IS
    'Which ladder rule produced model_key: hf_repo | weight_digest | oci_digest | api_model | local_file | name | opaque.';
COMMENT ON COLUMN normalize.ai_models.evidence IS
    'Where each engine says it saw this model, verbatim. Never a path we inferred.';
COMMENT ON COLUMN normalize.ai_models.verified IS
    'True only when an engine confirmed the model resolves upstream. Never assumed.';

-- +goose Down
DROP INDEX IF EXISTS normalize.ai_models_model_key_idx;

ALTER TABLE normalize.ai_models
    DROP COLUMN IF EXISTS verified,
    DROP COLUMN IF EXISTS evidence,
    DROP COLUMN IF EXISTS source_engine,
    DROP COLUMN IF EXISTS identity_confidence,
    DROP COLUMN IF EXISTS identity_rule,
    DROP COLUMN IF EXISTS model_key;
