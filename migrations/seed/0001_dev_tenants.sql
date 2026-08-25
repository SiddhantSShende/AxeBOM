-- ===========================================================================
-- Development seed. NOT a migration — never runs in production.
--
-- TWO TENANTS, DELIBERATELY.
--
-- Isolation bugs are invisible with one tenant: every query returns the right
-- rows because there are no wrong rows to return. The second tenant is what
-- makes a missing RLS policy show up as a test failure instead of as a breach.
--
-- The two tenants share PROJECT NAMES on purpose. A cross-tenant leak then
-- surfaces as duplicate-looking data rather than as nothing at all, which is
-- much easier to notice by eye during manual testing.
-- ===========================================================================

-- Fixed UUIDs so tests can reference them without a lookup round-trip.
-- v7-shaped (the 7 in position 13) to match what app.uuid_v7() produces.
--
--   tenant A  01900000-0000-7000-8000-00000000000a  Acme Industries
--   tenant B  01900000-0000-7000-8000-00000000000b  Beta Corp
--
-- Written as literals rather than psql \set variables: this file is executed
-- through database/sql, which has no psql meta-commands.

BEGIN;

-- ---------------------------------------------------------------------------
-- Tenants
-- ---------------------------------------------------------------------------
INSERT INTO auth.tenants (id, name, slug, plan) VALUES
    ('01900000-0000-7000-8000-00000000000a', 'Acme Industries',  'acme',  'enterprise'),
    ('01900000-0000-7000-8000-00000000000b', 'Beta Corp',        'beta',  'team')
ON CONFLICT (id) DO NOTHING;

-- ---------------------------------------------------------------------------
-- Users. GLOBAL — note carol belongs to BOTH tenants, which is the case that
-- would break if users were tenant-scoped.
--
-- ⚠ THE PASSWORD IS `axebom-dev-only` AND IT IS THE SAME FOR EVERY USER.
--
-- Named so that it cannot be mistaken for a credential. This file is loaded
-- only by `Migrator.Seed`, which refuses any host that is not localhost,
-- 127.0.0.1 or `postgres` (libs/go-shared/platform/db/seed.go) — the hashes
-- below cannot be installed into a remote database by accident.
--
-- Publishing the hash costs nothing that publishing the password does not
-- already cost: a seed nobody can log into is not a seed. What matters is that
-- these are REAL argon2id hashes at the parameters the service uses, not a
-- placeholder — a seed whose users cannot authenticate leaves the whole login
-- path untested by hand, which is exactly how it stayed broken.
--
--   $argon2id$v=19$m=19456,t=2,p=1$...
--
-- Generated with libs/go-shared/auth.HashPassword, one distinct salt each, and
-- p=1 rather than DefaultArgon2Params() so the committed artifact does not
-- depend on the CPU count of the machine that produced it. Verification reads
-- the parameters back out of the encoded hash, so this verifies anywhere, and
-- NeedsRehash leaves it alone.
--
-- ⚠ carol has NO PASSWORD, DELIBERATELY. Her `auth_provider` is `github`, so
-- she is the SSO-only account: `Service.Login` has a branch for a user with an
-- empty hash and returns the same generic error as a wrong password, because
-- answering "use GitHub instead" would confirm the address is registered.
-- Giving her a local password would delete the only fixture that reaches that
-- branch. She reaches her two tenants through the OAuth path, which is what
-- she is here to exercise.
-- ---------------------------------------------------------------------------
INSERT INTO auth.users (id, email, name, auth_provider, status, password_hash) VALUES
    ('01900000-0000-7000-8000-0000000000a1', 'alice@acme.test',  'Alice Owner',   'local', 'active',
     '$argon2id$v=19$m=19456,t=2,p=1$LoFY4Q5+7C0bAI0i3p59ZQ$frddvmV6u4oxvUkpDmnJjg+BSmnfG/ciVth69HWalxo'),
    ('01900000-0000-7000-8000-0000000000a2', 'aaron@acme.test',  'Aaron Analyst', 'local', 'active',
     '$argon2id$v=19$m=19456,t=2,p=1$VnLb+JaTQnB/uJZkSJBCgw$EA6Ju67Y4jCw5q7mmZsxFKTuxPWy1AT2ABj1FIJiTFc'),
    ('01900000-0000-7000-8000-0000000000b1', 'bob@beta.test',    'Bob Owner',     'local', 'active',
     '$argon2id$v=19$m=19456,t=2,p=1$qfkzFOAv80OjZIkY5ckZSA$werfey9WFRTnsdJDUFddTrEwIZZka+mM8pVKg8o+CH4'),
    ('01900000-0000-7000-8000-0000000000c1', 'carol@both.test',  'Carol Consultant', 'github', 'active',
     NULL)
-- ⚠ DO UPDATE, not DO NOTHING, for password_hash ALONE.
--
-- The seed is idempotent and every other row here is DO NOTHING, but these
-- users already exist in every database seeded before the hashes were added —
-- and DO NOTHING would leave every one of those developers unable to log in,
-- with a seed that looks like it ran. Only the hash is written back: a name or
-- a status changed by hand while testing is left alone.
ON CONFLICT (id) DO UPDATE SET password_hash = EXCLUDED.password_hash;

INSERT INTO auth.memberships (tenant_id, user_id, role, accepted_at) VALUES
    ('01900000-0000-7000-8000-00000000000a', '01900000-0000-7000-8000-0000000000a1', 'owner',   now()),
    ('01900000-0000-7000-8000-00000000000a', '01900000-0000-7000-8000-0000000000a2', 'analyst', now()),
    ('01900000-0000-7000-8000-00000000000b', '01900000-0000-7000-8000-0000000000b1', 'owner',   now()),
    -- Carol: analyst in A, viewer in B. Exercises per-tenant role resolution.
    ('01900000-0000-7000-8000-00000000000a', '01900000-0000-7000-8000-0000000000c1', 'analyst', now()),
    ('01900000-0000-7000-8000-00000000000b', '01900000-0000-7000-8000-0000000000c1', 'viewer',  now())
ON CONFLICT (tenant_id, user_id) DO NOTHING;

-- ---------------------------------------------------------------------------
-- Projects. SAME NAME in both tenants — see the header.
-- ---------------------------------------------------------------------------
INSERT INTO project.projects
    (id, tenant_id, name, description, source_type, sdlc_stage,
     validity_start, validity_end, owner_name, owner_email, created_by)
VALUES
    ('01900000-0000-7000-8000-0000000000f1',
     '01900000-0000-7000-8000-00000000000a',
     'payments-api', 'Acme payments service', 'github', 'source',
     '2026-01-01', '2027-01-01', 'Alice Owner', 'alice@acme.test',
     '01900000-0000-7000-8000-0000000000a1'),

    ('01900000-0000-7000-8000-0000000000f2',
     '01900000-0000-7000-8000-00000000000a',
     'ml-inference', 'Acme model serving', 'github', 'build',
     '2026-01-01', NULL, 'Aaron Analyst', 'aaron@acme.test',
     '01900000-0000-7000-8000-0000000000a1'),

    -- Same name as Acme's. A cross-tenant read shows up as two rows.
    ('01900000-0000-7000-8000-0000000000f3',
     '01900000-0000-7000-8000-00000000000b',
     'payments-api', 'Beta payments service', 'upload', 'analyzed',
     '2026-03-01', '2026-12-31', 'Bob Owner', 'bob@beta.test',
     '01900000-0000-7000-8000-0000000000b1')
ON CONFLICT (id) DO NOTHING;

-- ---------------------------------------------------------------------------
-- Classifications
-- ---------------------------------------------------------------------------
INSERT INTO project.project_classifications (project_id, tenant_id, bom_type) VALUES
    ('01900000-0000-7000-8000-0000000000f1', '01900000-0000-7000-8000-00000000000a', 'SBOM'),
    ('01900000-0000-7000-8000-0000000000f1', '01900000-0000-7000-8000-00000000000a', 'CBOM'),
    ('01900000-0000-7000-8000-0000000000f2', '01900000-0000-7000-8000-00000000000a', 'SBOM'),
    ('01900000-0000-7000-8000-0000000000f2', '01900000-0000-7000-8000-00000000000a', 'AIBOM'),
    ('01900000-0000-7000-8000-0000000000f3', '01900000-0000-7000-8000-00000000000b', 'SBOM')
ON CONFLICT DO NOTHING;

-- ---------------------------------------------------------------------------
-- Practices — CERT-In Table 5, category 3.
--
-- Acme's payments-api has all six. Beta's project deliberately has NONE, so
-- Phase 9's coverage reporting has a project that legitimately shows a gap.
-- A seed where everything is complete cannot exercise the honest path.
-- ---------------------------------------------------------------------------
INSERT INTO project.practices
    (project_id, tenant_id, frequency, depth, known_unknowns,
     distribution, access_control, errata_policy)
VALUES
    ('01900000-0000-7000-8000-0000000000f1',
     '01900000-0000-7000-8000-00000000000a',
     '0 2 * * 1', 'complete',
     'Vendored C libraries under third_party/ have no manifest and no engine covers them.',
     'Signed CycloneDX published to the customer portal on each release.',
     'private',
     'Corrections re-normalize stored raw artifacts into a new version; superseded reports are retained.')
ON CONFLICT (project_id) DO NOTHING;

COMMIT;
