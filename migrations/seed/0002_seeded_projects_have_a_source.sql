-- ===========================================================================
-- The seeded GitHub projects get the repository connection they always claimed.
--
-- ⚠ EVERY SEEDED PROJECT WAS UNSCANNABLE, AND TWO OF THEM ASSERTED A SOURCE
-- THAT DID NOT EXIST.
--
-- 0001 registers `payments-api` and `ml-inference` with
-- `source_type = 'github'` and seeds no `repository_connections` row and no
-- `uploads` row — for any project. `handler.Source` resolves a github project
-- by reading its connections, finds none, and the fetcher answers
-- FETCH_NO_SOURCE: "the project has no repository connection or uploaded file,
-- so there is nothing to fetch".
--
-- The pipeline handled that correctly and said so on every engine run. The
-- problem is that it was the ONLY thing a fresh `task dev` could do: the first
-- scan a new developer or reviewer runs, on the flagship seeded project, failed
-- with nine failed engines. Measured on this stack — every `payments-api` scan
-- on record is `failed`, while every upload-sourced scan completed.
--
-- ⚠ AND THE STATE ITSELF IS INVALID, INDEPENDENT OF THE DEMO. A project whose
-- `source_type` is `github` and which has no connection is a registration that
-- claims something untrue. Seeding it taught every reader that the combination
-- is normal.
--
-- ⚠ PUBLIC REPOSITORIES, NO CREDENTIAL. `credential_ref` is NULL, which the
-- fetcher explicitly supports — `credential()` treats an empty ref as "a public
-- repository … demanding one would block the common case". No token is
-- invented, and nothing here reaches Vault.
--
-- These two were chosen because prior live proof-of-life runs on this stack
-- used them successfully (docs/STATE.md, 2026-08-26): small, stable, and real
-- dependency graphs rather than a fixture that proves nothing.
-- ===========================================================================

INSERT INTO project.repository_connections
    (tenant_id, project_id, provider, repo_url, repo_external_id, default_branch)
VALUES
    ('01900000-0000-7000-8000-00000000000a',
     '01900000-0000-7000-8000-0000000000f1',
     'github', 'https://github.com/expressjs/express', '237159', 'master'),

    ('01900000-0000-7000-8000-00000000000a',
     '01900000-0000-7000-8000-0000000000f2',
     'github', 'https://github.com/koajs/koa', '7385902', 'master')
ON CONFLICT (project_id, repo_url) DO NOTHING;

-- ⚠ NO `-- +goose Down` SECTION, AND NO GOOSE MARKERS AT ALL.
--
-- Seed files are NOT migrations — 0001 says so in its first line and carries no
-- goose annotations. The runner executes the whole file as SQL, so a
-- `-- +goose Down` line is an ORDINARY COMMENT and every statement beneath it
-- runs too. The first version of this file inserted the two connections and
-- then immediately deleted them, and reported "seed applied" while changing
-- nothing.
--
-- Idempotence comes from ON CONFLICT above, the same way every statement in
-- 0001 gets it — the seed is re-run on every `task dev`.
