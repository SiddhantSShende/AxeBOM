-- +goose Up
-- ===========================================================================
-- normalize.ai_assets — everything an AI scan finds that is NOT a model.
-- normalize.ai_model_provenance — which engines saw each model.
--
-- ⚠ WITHOUT THE FIRST TABLE, THREE REAL DISCOVERIES ARE COMPUTED AND THROWN
-- AWAY, WHICH IS THE FAILURE INVARIANT 12 NAMES AS WORSE THAN NOT LOOKING.
--
-- Measured on one real tree (workers/aibom/testdata/ai-langchain, captured in
-- airom-ai-langchain.cdx.json and cdxgen-ai-ai-langchain.cdx.json), the two new
-- AIBOM engines report, with file:line evidence:
--
--     a system prompt              src/app.py:9
--     a prompt file                prompts/classifier.txt
--     a Chroma vector store        requirements.txt:4
--     a RAG pipeline               src/app.py:14
--     two inference services       openai, meta-llama
--
-- None of those is a model and none is a software dependency, so before this
-- table there was nowhere to put any of them. The engines would have run, found
-- them, and produced a report that mentioned none of it.
--
-- ⚠ TYPE-AWARE, THE SAME REASONING AS CBOM'S TABLE 9 (CLAUDE.md invariant 5).
-- A prompt, a vector store and an inference endpoint have different meaningful
-- fields; scoring an endpoint against "content hash" would report every AIBOM at
-- a falsely low coverage. `asset_type` is the discriminator, and the closed set
-- below mirrors `workers/aibom/discovery.ASSET_TYPES` exactly — a value not in
-- it is refused by the database rather than stored and rendered as a category
-- nothing knows how to score.
--
-- ⚠ THE SECOND TABLE EXISTS BECAUSE `ai_models.source_engine` IS SINGULAR AND
-- THE ANSWER IS NOT.
--
-- Three engines now discover AI usage independently, and on the tree above all
-- three converge on the same `model_key` for `meta-llama/Llama-3-8B`. "Which
-- engine found this model" therefore has three answers, and a text column can
-- hold one. This is the AI counterpart of `normalize.component_provenance`,
-- which has recorded exactly this for SBOM components since 0001 — one row per
-- (model, engine), never a delimited list in a scalar.
--
-- A model seen by one engine and missed by two is the single most useful fact
-- for a reviewer weighing how much to trust a row, and it is invisible without
-- this table.
-- ===========================================================================

CREATE TABLE normalize.ai_assets (
    id              uuid PRIMARY KEY DEFAULT app.uuid_v7(),
    tenant_id       uuid NOT NULL,
    bom_document_id uuid NOT NULL REFERENCES normalize.bom_documents (id) ON DELETE CASCADE,

    -- The discriminator. See the header: this is the closed set
    -- workers/aibom/discovery.ASSET_TYPES declares, and the CHECK is what stops
    -- the two drifting apart silently.
    asset_type      text NOT NULL,

    -- ⚠ THE MERGE KEY, AND IT IS PREFIXED FOR THE SAME REASON `model_key` IS.
    -- `prompt:src/app.py:9` and `vector_store:chroma` can never collide even if
    -- an engine names a prompt "chroma". Produced by the normalizer, never by an
    -- engine.
    asset_key       text NOT NULL,

    name            text NOT NULL,
    provider        text,

    -- file:line, exactly as the engine reported it — the shape
    -- discovery.occurrence_locations normalizes airom's {location,line} and
    -- cdxgen's `path#Lline` into. A JSON array, never a delimited string.
    evidence        jsonb NOT NULL DEFAULT '[]'::jsonb,

    -- Which model this asset serves, when the engine said so. An inference
    -- service names the model it fronts; a prompt usually names nothing.
    -- ⚠ THE KEY, NOT A FOREIGN KEY: the model may have been found by a
    -- different engine, or not at all, and a dangling reference is a truer
    -- record than dropping the asset.
    serves_model_key text,

    -- Per-asset facts that do not deserve a column each. `deployment`,
    -- `transport_security`, `engine_confidence` and whatever a future engine
    -- reports. Never scored; evidence only.
    attributes      jsonb NOT NULL DEFAULT '{}'::jsonb,

    created_at      timestamptz NOT NULL DEFAULT now(),

    -- One row per asset per document. A re-normalization writes a NEW document
    -- (invariant 10), so this never blocks a corrected pass.
    UNIQUE (bom_document_id, asset_key),

    CONSTRAINT ai_assets_type_check CHECK (asset_type IN (
        'prompt',
        'vector_store',
        'rag_pipeline',
        'embedding',
        'agent',
        'tool',
        'mcp_server',
        'endpoint',
        'dataset'
    ))
);

CREATE INDEX ai_assets_document_idx ON normalize.ai_assets (bom_document_id);
CREATE INDEX ai_assets_tenant_idx   ON normalize.ai_assets (tenant_id);
CREATE INDEX ai_assets_type_idx     ON normalize.ai_assets (bom_document_id, asset_type);

SELECT app.enable_tenant_rls('normalize.ai_assets');

CREATE TABLE normalize.ai_model_provenance (
    id           uuid PRIMARY KEY DEFAULT app.uuid_v7(),
    tenant_id    uuid NOT NULL,
    ai_model_id  uuid NOT NULL REFERENCES normalize.ai_models (id) ON DELETE CASCADE,

    engine_id    text NOT NULL,

    -- What that engine called the model, verbatim. Kept because the engines
    -- disagree in ways worth being able to see afterwards: for one model on one
    -- tree, ai-bom said `HuggingFace Transformers Model`, airom said
    -- `meta-llama/llama-3-8b` and cdxgen said `Llama-3-8B`.
    observed_name text,

    -- The engine's own confidence, where it publishes one (airom does, as a
    -- number; cdxgen as low/medium/high). ⚠ EVIDENCE, NEVER SCORED — a third
    -- party changing its heuristics must not move a compliance percentage.
    confidence   text,

    -- Where THIS engine saw it. Two engines can evidence the same model from
    -- different lines, and merging the arrays would lose which said what.
    evidence     jsonb NOT NULL DEFAULT '[]'::jsonb,

    created_at   timestamptz NOT NULL DEFAULT now(),

    UNIQUE (ai_model_id, engine_id)
);

CREATE INDEX ai_model_provenance_model_idx  ON normalize.ai_model_provenance (ai_model_id);
CREATE INDEX ai_model_provenance_tenant_idx ON normalize.ai_model_provenance (tenant_id);

SELECT app.enable_tenant_rls('normalize.ai_model_provenance');

-- ⚠ EXPLICIT, EVEN THOUGH 0006's ALTER DEFAULT PRIVILEGES SHOULD COVER IT — the
-- reasoning 0011 records: default privileges are recorded PER GRANTOR and apply
-- only to tables created by the same role that ran 0006. The failure mode
-- without these lines is `permission denied for table` on the first live AIBOM
-- normalization, at whatever hour that is.
GRANT SELECT, INSERT ON normalize.ai_assets           TO axebom_normalize_writer;
GRANT SELECT, INSERT ON normalize.ai_model_provenance TO axebom_normalize_writer;

-- +goose Down
DROP TABLE IF EXISTS normalize.ai_model_provenance;
DROP TABLE IF EXISTS normalize.ai_assets;
