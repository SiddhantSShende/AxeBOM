# Phase 0 — Foundations

**Estimated: 1 week** · Prerequisite for everything.

## Read first

1. `CLAUDE.md` — all 12 invariants
2. `docs/STATE.md`
3. `docs/00-MASTER-PLAN.md` §3 (architecture), §4 (phases)
4. `docs/ADR/0001-microservices-over-modular-monolith.md` — especially the four mitigations, which are this phase's real content
5. `docs/08-OPERATIONS.md` §1, §4

## Goal

Make the repository buildable, testable and coherent across sessions. No product features — this phase exists so that every later phase has a working gate (`task verify`) and mechanical guards that survive context loss.

The four ADR-0001 mitigations land here because each is worthless if added later: the service generator, schema-per-service discipline, the import-boundary lint, and dual-OS CI.

## Preconditions

```
task preflight     # will fail: no cmd/encorebom yet. Expected.
go version         # 1.24+
node --version     # 20+
python --version   # 3.11+
docker info        # start Docker Desktop if unreachable
```

Install go-task first: `winget install Task.Task`.

## Out of scope

Do not build: any domain logic, database schema (Phase 1), scanner integration (Phase 2), auth (Phase 3). Do not write Dockerfiles for services that have no code yet — a health endpoint and a config loader is the whole of each service in this phase.

## Deliverables

```
.git/                                   git init, initial commit
go.mod                                  module github.com/<org>/encorebom
go.work                                 if using workspaces

cmd/encorebom/
  main.go  preflight.go  version.go     # the CLI other tasks call

libs/go-shared/platform/
  config/    env + file, typed, fails fast on missing required
  errs/      the error taxonomy from 02-CONTRACTS §9
  obs/       slog JSON + OTel tracing + prometheus
  httpx/     middleware: request id, recovery, logging, timeout
  health/    /healthz (liveness) /readyz (readiness)

services/{gateway,auth,project,scan-orchestrator,report,campaign,comment,notification}/
  main.go  config.go  server.go         # health endpoints only

libs/py-shared/encorebom_shared/
  __init__.py  config.py  logging.py  errors.py
pyproject.toml

frontend/                               Vite + React + TS scaffold, one page
proto/                                  buf.yaml, buf.gen.yaml, empty
deploy/docker/                          Dockerfile per service (+ .dockerignore)

.golangci.yml                           incl. depguard boundary rules
.github/workflows/verify.yml            windows-latest AND ubuntu-latest
tools/gen-service/main.go               the service generator
```

## Contracts to honour

- **Error taxonomy** — `02-CONTRACTS.md §9`. `errs` must produce that exact JSON shape with a stable `code`. Never a bare string, never `panic` in a request path.
- **Schema-per-service** — no schema exists yet, but the config loader must give each service its own `search_path`. Establishing this now is what makes ADR-0001 mitigation 2 real.
- **No bash.** Everything through `Taskfile.yml` and `cmd/encorebom`. `make`, `task` and `cosign` are absent from the primary dev machine and PowerShell 5.1 has no `&&`.

## Steps

1. `git init`; commit `.gitattributes` **first** so line-ending normalization applies to everything after it.
2. `go mod init`. Add `libs/go-shared/platform/*` — config, errs, obs, httpx, health.
3. Write `cmd/encorebom` with `preflight` and `version`. `preflight` reports Go/Node/Python/Docker/WSL2/Java and **explicitly flags the two known gaps**: Java 1.8 (why Java tools are container-only) and a stopped Docker daemon. It reports; it does not fail on optional tooling.
4. Write `tools/gen-service` and **generate all eight services with it**. Do not hand-write the first one and generate the rest — if the generator cannot produce every service, it will not be used later, and hand-written service #9 is where drift starts.
5. Configure `depguard` in `.golangci.yml`: `services/X` may import `libs/**` and `proto/**` but **never** `services/Y`.
6. Python shared package + `pyproject.toml`; `ruff` and `pytest` configured.
7. Vite + React + TS frontend, one page hitting `/healthz`.
8. Dockerfiles: multi-stage, non-root, distroless or alpine, health check.
9. CI on **both** windows-latest and ubuntu-latest running `task verify`.
10. Update `docs/STATE.md`.

## Test requirements

- `errs` round-trips every taxonomy prefix to the right HTTP status.
- Config loader fails fast and legibly on a missing required var.
- Each service's `/healthz` returns 200 and `/readyz` reflects dependency state.
- **The boundary-lint proof**: commit a deliberate cross-service import in a `_test` fixture, assert `task lint:boundaries` **fails**, then remove it. A lint rule nobody has seen fail is a lint rule nobody trusts.

## Exit criteria

```
task preflight            # runs, reports Java 1.8 + docker state
task verify               # GREEN on Windows AND Ubuntu
go build ./...            # all 8 services
python -c "import encorebom_shared"
npm --prefix frontend run build
go run ./tools/gen-service --name example --dry-run    # generator works
```

Plus, demonstrated once: `task lint:boundaries` fails on a deliberate cross-domain import.

## Before you finish

Update `docs/STATE.md`: mark Phase 0 complete, record the module path and any deviation from this file, and set the next action to Phase 1.
