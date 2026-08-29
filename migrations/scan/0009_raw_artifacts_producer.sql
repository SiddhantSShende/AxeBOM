-- +goose Up
-- ===========================================================================
-- scan.raw_artifacts gains `producer` — a raw artifact from a component that
-- is NOT a dispatched engine.
--
-- Two components stage artifacts without ever getting an engine_runs row:
-- the fetcher (a git clone's source_archive, plus an optional native_output
-- like a GitHub Dependency Graph SBOM) and services/webrecon (a url source's
-- discovery + JS-fingerprint result, also native_output). Neither is an
-- "engine" in the scan.engine_runs sense — CreateScan never dispatches
-- either as a policy.Engine — so engine_run_id has always been NULL for
-- their artifacts.
--
-- That was a latent bug, not a deliberate gap: LoadRawArtifactsForEngines
-- INNER JOINs raw_artifacts to engine_runs to resolve an engine id, which
-- can never match a NULL engine_run_id. Nothing ever recorded these
-- artifacts either (handleFetchResult never called RecordRawArtifacts), so
-- the two failures canceled out silently — github-dependency-graph-sbom's
-- NativeSBOMRef wiring (Milestone 3) has never actually worked end to end,
-- despite every unit test passing, because those tests exercise the
-- adapter and the client in isolation, never the full orchestrator FanOut
-- path against a real fetch result. Found while wiring the identical
-- mechanism for webrecon (Milestone 5) and fixed for both at once.
--
-- producer is nullable and mutually exclusive with engine_run_id: an
-- artifact is attributed to exactly one of "a dispatched engine's run" or
-- "a named producer component", never both, never neither.
-- ===========================================================================

ALTER TABLE scan.raw_artifacts
    ADD COLUMN producer text,
    ADD CONSTRAINT raw_artifacts_engine_run_xor_producer
        CHECK ((engine_run_id IS NULL) <> (producer IS NULL));

-- +goose Down
ALTER TABLE scan.raw_artifacts
    DROP CONSTRAINT raw_artifacts_engine_run_xor_producer,
    DROP COLUMN producer;
