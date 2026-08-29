-- +goose Up
-- ===========================================================================
-- findings.fix_version_ordering's CHECK constraint never matched what
-- libs/py-shared/axebom_shared/normalize/findings.py's resolve_fix_version()
-- actually emits.
--
-- The constraint (migration 0002) only ever allowed 'known'/'unknown'. The
-- real code has always returned one of THREE values, never 'known':
--   'comparator' — a fix version was reported AND an ecosystem-correct
--                  comparator exists (fixed_in_min is trustworthy)
--   'unknown'    — a fix version was reported but no comparator exists for
--                  this ecosystem (a lexical sort would risk reporting the
--                  wrong minimum — findings.py's own "never guess" rule)
--   'none'       — no fix version was reported at all
--
-- Found the hard way: this is the FIRST time a real NormalizeTriggerV1-
-- driven write (workers/sbom/normalize_consumer.py) ever pushed real
-- pipeline.normalize() output through bulk.py into this actual constrained
-- table — every prior test supplied a hand-picked 'unknown' in its fixture
-- data (see test_writer.py's canonical_model(), which says so directly:
-- "REQUIRED... every finding a real pipeline run produces sets it"),
-- sidestepping the mismatch entirely. A real scan's findings would have
-- failed this CHECK on every finding with an actual reported fix version,
-- the moment cluster_store.py's write path made a real write possible.
--
-- Widened to match the code (the SSOT for what this column actually holds),
-- not the other way around — findings.py's three-way distinction is more
-- precise than the original two-way design and is what
-- docs/01-DATA-MODEL.md must now document.
-- ===========================================================================
ALTER TABLE normalize.findings DROP CONSTRAINT findings_fix_version_ordering_check;

ALTER TABLE normalize.findings ADD CONSTRAINT findings_fix_version_ordering_check
    CHECK (fix_version_ordering IN ('comparator', 'unknown', 'none'));

-- +goose Down
ALTER TABLE normalize.findings DROP CONSTRAINT findings_fix_version_ordering_check;

ALTER TABLE normalize.findings ADD CONSTRAINT findings_fix_version_ordering_check
    CHECK (fix_version_ordering IN ('known', 'unknown'));
