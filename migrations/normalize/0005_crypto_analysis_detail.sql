-- +goose Up
-- ===========================================================================
-- crypto_assets — the rest of the analysis, and the QBOM grouping.
--
-- 0003 gave the three headline analysis outputs (quantum_vulnerable,
-- pqc_recommendation, deprecation_status) real columns, with the reasoning
-- spelled out there: "AxeBOM analysis... NOT CERT-In fields... EXCLUDED from
-- coverage." workers/cbom/normalize/crypto.py's analyse() always produced
-- more than those three — quantum_family, an optional grover_note, the
-- rationale text behind both verdicts, deprecation's reference, and the
-- effective bit strength after Grover — and none of it had anywhere to go.
-- Finishing that decision, not starting a new one: same exclusion-from-
-- coverage reasoning, same columns-not-jsonb treatment 0003 already gave
-- their siblings.
--
-- ⚠ `quantum_readiness_group` IS PRE-COMPUTED IN PYTHON, NOT DERIVED IN GO.
--
-- workers/qbom/derive.py's own docstring: "Recomputing here would be a
-- second implementation of the rules, and the two would disagree the first
-- time one changed." That warning was written about a report re-deriving
-- what the CBOM normalizer already decided; a Go report renderer doing the
-- same four-way if/elif over quantum_vulnerable/grover_note/quantum_family
-- would be exactly that second implementation. So the classification itself
-- — which of the four QBOM readiness buckets this asset belongs in — is
-- computed once, in Python, at CBOM-normalization time, and stored. Go reads
-- a column; it does not know PQC_FAMILIES exists.
-- ===========================================================================

ALTER TABLE normalize.crypto_assets
    ADD COLUMN quantum_family        text,
    ADD COLUMN grover_note           text,
    ADD COLUMN quantum_rationale     text,
    ADD COLUMN deprecation_rationale text,
    ADD COLUMN deprecation_reference text,
    ADD COLUMN effective_quantum_bits int,
    ADD COLUMN analysis_diagnostics  jsonb NOT NULL DEFAULT '[]'::jsonb,
    ADD COLUMN quantum_readiness_group text
        CHECK (quantum_readiness_group IS NULL OR quantum_readiness_group IN
              ('vulnerable', 'grover_note', 'post_quantum', 'unassessed'));

COMMENT ON COLUMN normalize.crypto_assets.quantum_readiness_group IS
'Which of QuantumReadiness''s four buckets this asset falls in — mirrors
workers/qbom/derive.py:derive_readiness() exactly, computed once in Python at
CBOM-normalization time. NULL means unset (a row written before this column,
or an asset the CBOM normalizer never ran analyse() over). AxeBOM analysis,
not a CERT-In field: excluded from coverage, same as its three 0003 siblings.';

CREATE INDEX crypto_assets_readiness_group_idx
    ON normalize.crypto_assets (bom_document_id, quantum_readiness_group)
    WHERE quantum_readiness_group IS NOT NULL;

-- +goose Down
DROP INDEX IF EXISTS normalize.crypto_assets_readiness_group_idx;
ALTER TABLE normalize.crypto_assets
    DROP COLUMN IF EXISTS quantum_readiness_group,
    DROP COLUMN IF EXISTS analysis_diagnostics,
    DROP COLUMN IF EXISTS effective_quantum_bits,
    DROP COLUMN IF EXISTS deprecation_reference,
    DROP COLUMN IF EXISTS deprecation_rationale,
    DROP COLUMN IF EXISTS quantum_rationale,
    DROP COLUMN IF EXISTS grover_note,
    DROP COLUMN IF EXISTS quantum_family;
