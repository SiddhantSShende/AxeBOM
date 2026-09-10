-- +goose Up
-- ===========================================================================
-- The `aibom` schema — what a PERSON says about an AI model, and what AxeBOM
-- verified about it. Neither is a normalization output.
--
-- ⚠ THE WHOLE POINT OF THIS SCHEMA IS THAT `normalize.ai_models` STOPS BEING
-- UPDATED.
--
-- `services/project` collected the operator-supplied half of CERT-In Table 10
-- and wrote it with `UPDATE normalize.ai_models SET intended_usage = …`. That
-- is a mutation of normalized data, which CLAUDE.md invariant 10 says never
-- happens — normalization is replayable, and a replay must reproduce the same
-- rows from the same artifacts. It survived only because the AIBOM normalize
-- consumer learned to read the PREVIOUS document's values back before writing a
-- new one, which is a rescue for a write that should not exist. Anything that
-- rescue missed — a model whose identity changed between passes, a first
-- normalization after an operator answered — silently lost the answer.
--
-- Held here instead, keyed by `(tenant, project, model_key)`, operator input
-- outlives every re-normalization BY CONSTRUCTION. The normalizer reads it and
-- writes it into the new document; nothing updates the old one.
-- ===========================================================================

-- ---------------------------------------------------------------------------
-- Operator-supplied Table 10 elements
-- ---------------------------------------------------------------------------
--
-- ⚠ ONE COLUMN PER ELEMENT, NOT A JSONB BAG, and the reason is invariant 2 in
-- reverse. Which elements are operator-supplied is declared once in
-- `docs/reference/certin-v2.0.yaml` (`user_supplied: true`) and both languages
-- generate their field sets from it — so a bag keyed by field id would let the
-- database accept an id the profile does not define, and nothing would notice.
-- Named columns make a profile revision a migration, which is the visible,
-- reviewable form of that change.
CREATE TABLE aibom.model_user_values (
    id          uuid PRIMARY KEY DEFAULT app.uuid_v7(),
    tenant_id   uuid NOT NULL,
    project_id  uuid NOT NULL,

    -- ⚠ THE MODEL KEY, NOT THE ai_models ROW ID. A normalization writes NEW
    -- rows (invariant 10), so a row id is valid for exactly one document and an
    -- operator's answer would be orphaned by the next scan. `model_key` is
    -- stable across documents by design — it is the merge key the identity
    -- ladder produces (`03-NORMALIZER-SPEC.md` §1.5).
    --
    -- ⚠ AND NOT A FOREIGN KEY EITHER, deliberately: this schema must not
    -- reference `normalize.*` (invariant 11 — schema per service, no
    -- cross-schema joins in SQL). An answer recorded for a model that a later
    -- scan no longer finds is kept, not cascaded away: the operator said
    -- something true about a model that was there.
    model_key   text NOT NULL,

    security_requirements text,
    intended_usage        text,
    out_of_scope_usage    text,
    environmental_impact  text,
    attestation_signature text,

    updated_by  uuid NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now(),

    UNIQUE (tenant_id, project_id, model_key)
);

CREATE INDEX model_user_values_project_idx ON aibom.model_user_values (tenant_id, project_id);

SELECT app.enable_tenant_rls('aibom.model_user_values');

CREATE TRIGGER touch_updated_at BEFORE UPDATE ON aibom.model_user_values
    FOR EACH ROW EXECUTE FUNCTION app.touch_updated_at();

-- ---------------------------------------------------------------------------
-- Per-project AI policy — the two switches that send data to a third party
-- ---------------------------------------------------------------------------
--
-- ⚠ BOTH DEFAULT OFF AND BOTH ARE A DECISION SOMEBODY MAKES, NOT A SETTING
-- THEY DISCOVER AFTERWARDS IN AN EGRESS LOG.
--
--   llm_enrich  — `ai-bom --llm-enrich` resolves ambiguous model references by
--                 asking an LLM, which means sending CODE CONTEXT to a third
--                 party.
--   cisco       — `cisco-aibom analyze` always requires `--llm-model`; the same
--                 exposure, and it is why that engine is registered and
--                 disabled (`policy.Engine.Disabled`).
--
-- Turning either on is recorded with WHO and WHEN, because "we consented" is a
-- claim somebody has to be able to check. Neither flag alone is sufficient to
-- make the engine run: the sandbox has no network and there is no egress proxy
-- yet, so today these record an intent the platform still refuses to act on —
-- which is the honest state and is what the UI must say.
CREATE TABLE aibom.project_policy (
    tenant_id   uuid NOT NULL,
    project_id  uuid NOT NULL,

    llm_enrich_enabled boolean NOT NULL DEFAULT false,
    cisco_enabled      boolean NOT NULL DEFAULT false,

    -- Null until somebody turns one of them on. Not defaulted to the row's
    -- creator: creating a project is not consenting to anything.
    consent_recorded_by uuid,
    consent_recorded_at timestamptz,

    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now(),

    PRIMARY KEY (tenant_id, project_id)
);

SELECT app.enable_tenant_rls('aibom.project_policy');

CREATE TRIGGER touch_updated_at BEFORE UPDATE ON aibom.project_policy
    FOR EACH ROW EXECUTE FUNCTION app.touch_updated_at();

-- ---------------------------------------------------------------------------
-- Compliance tagging — EU AI Act, NIST AI RMF, ISO/IEC 42001
-- ---------------------------------------------------------------------------
--
-- ⚠ THESE ARE THE OPERATOR'S CLASSIFICATION, NEVER AxeBOM's.
--
-- Whether a system is "high-risk" under the EU AI Act depends on what it is
-- USED FOR — the deployment context, the sector, whether a human is in the
-- loop — none of which is visible in a repository. A product that inferred a
-- risk tier from an import statement would be manufacturing a legal conclusion
-- out of a dependency graph, and a customer would carry it into an audit.
--
-- So AxeBOM records what a person declared, attributes it to them, and renders
-- it as a declaration. `rationale` is not decoration: a tier with no stated
-- reason is unreviewable, and the field exists to make the absence visible.
CREATE TABLE aibom.compliance_tags (
    id          uuid PRIMARY KEY DEFAULT app.uuid_v7(),
    tenant_id   uuid NOT NULL,
    project_id  uuid NOT NULL,
    -- Empty string means "the whole project". A per-model tag overrides it —
    -- one repository can hold a high-risk classifier and a spell-checker.
    model_key   text NOT NULL DEFAULT '',

    -- ⚠ CLOSED SETS, CHECKED. A free-text tier renders as a compliance claim
    -- and cannot be aggregated or filtered; a typo would silently become a
    -- fourth category. Mirrors `libs/go-shared/model`'s generated constants.
    eu_ai_act_tier   text,
    nist_ai_rmf      text[] NOT NULL DEFAULT '{}',
    iso_42001        text[] NOT NULL DEFAULT '{}',
    rationale        text,

    declared_by uuid NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now(),

    UNIQUE (tenant_id, project_id, model_key),

    CONSTRAINT compliance_tags_eu_tier_check CHECK (
        eu_ai_act_tier IS NULL OR eu_ai_act_tier IN (
            'unacceptable',
            'high',
            'limited',
            'minimal',
            -- ⚠ A FIRST-CLASS VALUE, NOT AN ABSENCE. "Nobody has classified
            -- this yet" and "somebody looked and could not decide" are
            -- different states, and only one of them is a task for a person.
            'undetermined'
        )
    )
);

CREATE INDEX compliance_tags_project_idx ON aibom.compliance_tags (tenant_id, project_id);

SELECT app.enable_tenant_rls('aibom.compliance_tags');

CREATE TRIGGER touch_updated_at BEFORE UPDATE ON aibom.compliance_tags
    FOR EACH ROW EXECUTE FUNCTION app.touch_updated_at();

-- ---------------------------------------------------------------------------
-- Attestation verification records — CERT-In Table 10 element 19
-- ---------------------------------------------------------------------------
--
-- ⚠ A VERIFICATION RESULT, NOT A SIGNATURE, AND THE DISTINCTION IS THE VALUE.
--
-- Element 19 asks for the model's attestation. Storing the operator's typed
-- statement "signed by us" satisfies the letter and asserts nothing checkable.
-- A row here says: AxeBOM ran `model_signing` against a named bundle, and this
-- is what came back — including `verified = false`, which is a real and useful
-- answer that the free-text field cannot express.
--
-- ⚠ `verified` NEVER DEFAULTS TO TRUE, the same rule `normalize.ai_models
-- .verified` carries. A model nobody could verify is not a model somebody
-- verified.
CREATE TABLE aibom.attestations (
    id          uuid PRIMARY KEY DEFAULT app.uuid_v7(),
    tenant_id   uuid NOT NULL,
    project_id  uuid NOT NULL,
    model_key   text NOT NULL,

    verified    boolean NOT NULL DEFAULT false,
    -- How it was checked: `sigstore-model-signing` today. Recorded rather than
    -- assumed, because a future second method must not be indistinguishable
    -- from this one in a stored record.
    method      text NOT NULL,
    -- What the signature says, when it says anything: the signer identity and
    -- the issuer that vouched for it. Both null on a failed verification, and
    -- that is the honest shape — a failed check establishes no identity.
    signer_identity text,
    signer_issuer   text,
    -- The digest that was actually checked. Without it a verification record
    -- cannot be tied to a specific artifact and is worth very little.
    digest      text,

    -- Why it failed, in the tool's own words. Null on success.
    failure_reason text,

    -- The verifier's full response, kept verbatim. Same reasoning as a raw
    -- scanner artifact: the parsed columns are a view, and six months later the
    -- question is usually about something the view dropped.
    raw         jsonb NOT NULL DEFAULT '{}'::jsonb,

    verified_at timestamptz NOT NULL DEFAULT now(),
    recorded_by uuid NOT NULL,

    -- ⚠ NOT UNIQUE PER MODEL. Verification is a statement about a MOMENT, the
    -- same reasoning campaigns exist for. Re-verifying appends; the newest row
    -- is the current answer and the older ones are the history that makes a
    -- changed answer legible.
    created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX attestations_model_idx ON aibom.attestations (tenant_id, project_id, model_key, created_at DESC);

SELECT app.enable_tenant_rls('aibom.attestations');

-- ---------------------------------------------------------------------------
-- The normalize consumer reads operator input. It writes nothing here.
-- ---------------------------------------------------------------------------
--
-- ⚠ THIS WIDENS `axebom_normalize_writer`, AND ONLY BY SELECT ON ONE SCHEMA.
--
-- That role exists to make invariant 10 structural: it holds SELECT+INSERT on
-- `normalize` and no UPDATE or DELETE anywhere, so a bug cannot overwrite
-- normalized data. Reading operator input does not touch that property — there
-- is no write grant here at all — and it is what lets the values be carried
-- into a NEW document instead of being UPDATE-ed onto an old one, which is the
-- behaviour this schema exists to remove.
GRANT USAGE ON SCHEMA aibom TO axebom_normalize_writer;
GRANT SELECT ON aibom.model_user_values TO axebom_normalize_writer;
GRANT SELECT ON aibom.compliance_tags   TO axebom_normalize_writer;
GRANT SELECT ON aibom.attestations      TO axebom_normalize_writer;

-- +goose Down
DROP TABLE IF EXISTS aibom.attestations;
DROP TABLE IF EXISTS aibom.compliance_tags;
DROP TABLE IF EXISTS aibom.project_policy;
DROP TABLE IF EXISTS aibom.model_user_values;
