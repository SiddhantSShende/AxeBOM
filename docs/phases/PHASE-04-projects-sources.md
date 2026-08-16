# Phase 4 — Projects and sources

**Estimated: 1.5 weeks** · Depends on Phases 1, 3.

## Read first

1. `docs/STATE.md`
2. `docs/01-DATA-MODEL.md` §2 (schema `project`)
3. **`docs/06-COMPLIANCE-PROFILES.md` §6** — why practices are a product feature
4. `docs/reference/certin-v2.0.yaml` → `sbom.minimum_element_categories`
5. `docs/07-FRONTEND-SPEC.md` §6 (connect wizard)

## Goal

Register projects two ways — GitHub connection or manual/upload — with owner, validity, BOM-type classifications, SDLC stage, and the six CERT-In practices settings.

## Preconditions

Auth works; a user can sign in and land in a tenant with a role.

## Out of scope

No scanning, no cloning (Phase 5 owns anything that touches an untrusted URL). This phase **stores** a repo URL and validates its shape; it does not fetch it.

## Deliverables

```
services/project/
  handler/    projects CRUD, connect-repo, uploads, practices
  service/    project, classification, practices, connection, upload
  store/
  github/     repo listing via the user's OAuth token

libs/go-shared/vault/          credential_ref storage
frontend/src/routes/projects/  list, wizard (3 steps), detail, practices
```

## Contracts to honour

- **`project.repository_connections.credential_ref` stores a Vault path, never a token.**
- **The six practices fields are a minimum element**, not a settings-page nicety. A project without them cannot produce a complete compliance report, and the UI must say so at the point of entry.
- Classifications are many-to-many: a project may carry any subset of the five BOM types.
- `repo_external_id` (the provider's numeric id) is stored and keyed on — repository names change.

## Steps

1. Project CRUD with owner block (name, email, GitHub, phone) and validity window. `validity_end >= validity_start` enforced in the schema, not only the handler.
2. Classification multi-select over `{SBOM, CBOM, QBOM, AIBOM, HBOM}` and SDLC stage over the six values from the profile — **read the enum from the profile, do not hardcode the list.**
3. **Practices** (`PUT /projects/:id/practices`): frequency, depth, known unknowns, distribution, access control, errata policy. Seed `known_unknowns` as empty; Phase 8 auto-populates it from engine-coverage gaps.
4. GitHub repo listing using the user's OAuth token, paginated and searchable. Store connection with `repo_external_id` and `default_branch`; put the token in Vault and keep only the path.
5. Upload: source archive, manifest, lockfile, image ref. **Validate shape, size and type; store to MinIO with sha256. Do not extract** — extraction is untrusted-input handling and belongs in the Phase 5 sandbox.
6. Manual registration: no repo, structured metadata sufficient to drive the engines.
7. Frontend wizard: source → owner & validity → classification & practices. The practices step is **not** optional and not buried in settings.
8. Update `docs/STATE.md`.

## Test requirements

- Project creatable via GitHub connection **and** manual/upload.
- Practices persist and are returned with the project.
- **A project missing practices reports a compliance gap** — surfaced now, not discovered as a coverage surprise in Phase 9.
- Classification is genuinely multi-select and round-trips.
- Validity window rejects `end < start` at the database level.
- **Cross-tenant**: user in tenant A cannot list, read, or connect a repo to a tenant-B project (404).
- Uploaded archives are stored but **never extracted** in this phase — assert no extraction code path exists.
- Vault holds the token; the database row holds only a path. Assert the token string never appears in the projects table.

## Exit criteria

```
go test ./services/project/... -v
task verify
```

Manual E2E: connect a GitHub repo → complete all three wizard steps → project detail shows classifications, owner, validity and all six practices → the same flow via manual registration with an uploaded `package-lock.json`.

## Before you finish

Update `docs/STATE.md`: both registration paths working, GitHub scopes actually used, and whether private-repo access was included.
