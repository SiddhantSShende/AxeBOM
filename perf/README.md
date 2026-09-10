# Load-test scenarios

⚠ **These have never been run.** They are written against the paths Phase 16
identifies as the ones that will break first, and until they execute against a
real stack the numbers in `docs/RUNBOOKS.md` are targets rather than baselines.

Recording that distinction matters: a target is what we hope for, a baseline is
what we measured. Reporting a target as a baseline is how a regression becomes
invisible — there is nothing to regress *from*.

## Running

```
k6 run perf/scan-throughput.js   -e BASE_URL=... -e API_KEY=...
k6 run perf/dependencies-page.js -e BASE_URL=... -e API_KEY=...
k6 run perf/report-render.js     -e BASE_URL=... -e API_KEY=...
k6 run perf/aibom-inventory.js   -e BASE_URL=... -e API_KEY=... \
  -e SMALL_PROJECT_ID=... -e LARGE_PROJECT_ID=...
```

Use a scoped API key (`scan:run`, `report:read`, `finding:read`) rather than a
session — the scenarios are what a CI pipeline does, and testing with an
admin session would exercise a path no client uses.

## What each one is for

| Scenario | The failure it looks for |
|---|---|
| `scan-throughput.js` | 100 concurrent scans. The orchestrator fans out one job per engine, so this is really a test of the queue and the reaper under contention. |
| `dependencies-page.js` | 200k findings, paged. **This is where `OFFSET` would have killed you** — the endpoint uses keyset pagination on a UUIDv7 id, and this scenario is what proves the deep page stays flat. |
| `report-render.js` | A Complete BOM at the component cap. The writer is a push iterator precisely so this does not hold the report in memory twice. |
| `aibom-inventory.js` | A project with many discovered models. **This is where the 1 + 3N round trips would have killed you** — the endpoint used to run three queries per model, so the page slowed in proportion to how much the customer found. |

## What has actually been run

`aibom-inventory.js`'s endpoint was exercised live against a three-model project
while the batching was written: the response is byte-identical before and after,
served in ~75 ms. That is a correctness check, **not a baseline** — three models
is exactly the size at which the bug was invisible, and nothing has yet fed the
endpoint two hundred. Everything in the table above remains a target.

## The one that matters most

`dependencies-page.js` walks to page 400 and asserts the **last page is no
slower than the first**. With `OFFSET` it would be roughly 400× slower, and the
symptom in production is not an error — it is a customer with a large monorepo
saying the product "feels slow" while every dashboard looks fine.
