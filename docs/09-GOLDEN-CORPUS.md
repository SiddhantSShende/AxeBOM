# 09 — Golden Corpus

The fixture repositories that prove the normalizer is correct, what each one proves, and the rules for changing a golden.

**Why this exists.** The normalizer produces every number a customer sees. A bug there does not crash anything — it quietly reports 240 vulnerabilities where there are 80, or 94% coverage where it is 61%. Unit tests catch logic errors; only end-to-end golden diffs over deliberately nasty inputs catch *silently wrong output*.

---

## 1. Structure

```
fixtures/
  <name>/
    repo/                     # the fixture source tree
    raw/<engine>.json         # PINNED raw scanner output — the actual test input
    expected/
      components.json         # hand-reviewed canonical output
      findings.json
      coverage.json
      graph.json
    README.md                 # what this fixture proves, and why each expectation is right
```

> **Tests replay pinned `raw/` artifacts; they do not run scanners.** This is what makes them deterministic, fast (seconds not minutes), runnable offline and in CI on both OSes, and stable when an upstream tool changes its output. Refreshing `raw/` is a deliberate, reviewed act — see §5.
>
> It also mirrors production exactly: normalization is a pure function of *(raw artifacts + ruleset + alias snapshot)* per ADR-0003, so replaying raw artifacts **is** the real code path.

---

## 2. The corpus

Fifteen fixtures. Each isolates a failure mode that has bitten real SBOM tooling.

| # | Fixture | Proves |
|---|---|---|
| 1 | `npm-simple` | Baseline. Clean `package-lock.json`, known component set, correct direct/transitive split. |
| 2 | `npm-scoped` | `@types/node` percent-encoding — `pkg:npm/%40types/node` and `pkg:npm/@types/node` are **one** component, not two. |
| 3 | `pypi-normalization` | PEP 503: `Flask_SQLAlchemy`, `flask-sqlalchemy` and `Flask.SQLAlchemy` collapse to one. |
| 4 | `maven-case` | Maven groupId/artifactId are **case-sensitive** — must *not* be lowercased like npm. |
| 5 | `golang-incompatible` | `+incompatible`, pseudo-versions, and module-proxy `!x` escaping decoded correctly. |
| 6 | `monorepo-multiroot` | **N roots, not one.** Three workspace packages → three root sets; a dep direct in one and transitive in another is reported correctly for each. |
| 7 | `cyclic-deps` | Go module cycle. Depth BFS terminates; no hang, no stack overflow. |
| 8 | `vendored-twice` | Same jar at two paths → **one component, two locations**. Counts do not double. |
| 9 | `log4shell-java` | **The alias closure.** Three engines emit `CVE-2021-44228`, `GHSA-jfh8-c2jp-5v3q`, and a distro id from three partial edge sets → **one** cluster. Also: naive dedup would report 3. |
| 10 | `alias-overmerge` | A batched GHSA aliasing several distinct CVEs. Guards hold: no CVE↔CVE merge without an authoritative edge; a >12-member cluster is flagged, not merged. |
| 11 | `cvss-conflict` | Grype says High, Trivy says Critical, NVD has v2 and v3.1. Precedence is applied, **nothing is averaged**, v2 is never max'd against v3.1, `severity_conflict = true`. |
| 12 | `license-zoo` | `NONE` present, `NOASSERTION` absent, `GPL-2.0` flagged ambiguous (never auto-resolved), `Apache 2` → `Apache-2.0`, unrecognized text → `LicenseRef-AxeBOM-*`, `MIT OR Apache-2.0` preserved unflattened. |
| 13 | `hostile-names` | Component named `=cmd\|'/c calc'!A1`; filenames with newline, NUL, 4-byte emoji, RTL override, and an 8 KB path. Sanitized before insert; **escaped in XLSX**. |
| 14 | `cpe-only` | Dependency-Check LOW-confidence CPE attaches as a **candidate identity**, does not merge into the PURL component, and its false positives do not appear as findings. |
| 15 | `deb-epoch-arch` | rpm/deb EVR ordering; `epoch` and `arch` are identity-bearing; `1.10.0` sorts after `1.9.0` (naive string sort fails this). |

### Cross-cutting expectations

Every fixture additionally asserts:

- **Both coverage numbers** — `completeness_pct` and `declaration_pct` — and that `not-provided` scores 0 for the first and 1 for the second.
- **Engine Coverage** is present, listing each engine's terminal status and any ecosystem with no available engine.
- **`certin_identifier` is derived**, distinct from `purl`, and never used as a merge key.
- Output is **byte-stable across runs** — sorted collections, no `time.Now()`, no map iteration order leaking in.

### Per-BOM-type fixtures (later phases)

| Fixture | Phase | Proves |
|---|---|---|
| `crypto-mixed` | 11 | Real `cbomkit-theia` output (not hand-built) against an openssl-generated cert: type-aware coverage, AND a certificate correctly inherits its signer's quantum verdict via a resolved `bom-ref` rather than a raw UUID a hand-built fixture's readable fake refs had been hiding. `raw/`/`expected/` committed; no `TestGolden` Go harness wired to it yet — see the fixture's own README. |
| `crypto-quantum` | 11 | RSA/ECC/DH/DSA flagged `quantum_vulnerable`; AES gets a Grover note, not a vulnerability flag. |
| `ai-langchain` | 12 | Agent frameworks, LLM providers, MCP servers, HF model metadata; valid CycloneDX ML-BOM. Not yet built as a pinned `raw/`/`expected/` fixture — the real `ai-bom` engine has been verified live against a LangChain+OpenAI test directory (real container, real detection) and `aibom-generator` against a real Hugging Face model (`workers/aibom/testdata/aibom-generator-distilbert-base-uncased.cdx.json`), but nobody has pinned that output into this corpus's shape yet. `workers/aibom/normalize/test_pipeline.py` covers the pipeline itself against synthetic fixtures in the meantime. |
| `hbom-nested` | 15 | Recursive subcomponents to depth 4; both supplier relationships distinct; §10.4.1.4 fields present. |

---

## 3. Writing an expectation

Expected files are **hand-reviewed**, never generated from current behaviour. Generating them from the code under test proves only that the code is self-consistent.

Each `fixtures/<name>/README.md` must answer, for a reader who was not there:

1. What failure mode does this fixture isolate?
2. Why is each non-obvious expected value correct? (with a citation — purl-spec, PEP 503, the CERT-In page, the CVE record)
3. What would a *wrong* implementation produce instead?

Question 3 is the one that matters. "Component count: 47" is unreviewable. "Component count: 47 — a naive implementation reports 49 because it treats `@types/node` and `%40types/node` as distinct" is reviewable, and it tells the next person what broke when the number changes.

---

## 4. Running

```
task test:golden                       # full corpus
go test ./... -run TestGolden/npm-scoped -v
go test ./... -run TestGolden -update   # regenerate — see §5 before using
```

Failures print a structured diff of expected vs actual, keyed by `component_key` and cluster id — not a raw JSON dump, which is unreadable at 1400 components.

`task test:golden` runs in CI on **both** windows-latest and ubuntu-latest. `.gitattributes` marks `*.golden` and `fixtures/**/expected/**` as `-text -diff` so Git never rewrites line endings — a CRLF-corrupted golden fails for a reason unrelated to the code, and that failure mode wastes whole sessions.

`task test:conformance` is a related but separate check: it validates `services/report/testdata/golden/fixture.spdx.json`/`fixture.cdx.json` against the OFFICIAL SPDX and CycloneDX schemas (`pip install -e ".[conformance]"` first), not against our own normalizer's expectations. It answers "will a real SPDX/CycloneDX tool accept this file", which `task test:golden` does not — that task only proves our exporter is internally consistent with itself. See `tools/conformance/test_spdx_cyclonedx.py`.

---

## 5. Changing a golden

> **A golden updated without justification is a guard removed.**

When behaviour legitimately changes, the commit message must state:

```
golden: npm-scoped component count 49 → 47

WHY: purl percent-decoding now applied before comparison, so
@types/node and %40types/node merge. Previously double-counted.
REF: docs/03-NORMALIZER-SPEC.md §1.1; purl-spec npm rules.
REVIEWED: diff inspected component-by-component; the two removed
entries are the duplicate scope-encoded forms, nothing else moved.
```

Rules:

- **Never `-update` a whole run to make CI green.** Update one fixture at a time and inspect each diff.
- If you cannot explain why the new number is right, the change is a regression until proven otherwise.
- A golden change touching more than three fixtures needs a second reviewer — that breadth usually means an identity or dedup rule moved, which is the highest-blast-radius change in the system.

---

## 6. Adding a fixture

Add one whenever a normalizer bug is found in the wild. **The regression test is the fixture**, not a unit test — unit tests verify a function, fixtures verify the pipeline, and pipeline bugs are the ones that reach customers.

1. `fixtures/<name>/repo/` — minimal tree reproducing the case. Small: this repository is cloned by every contributor.
2. Run the engines once, commit `raw/<engine>.json`. Record engine versions in the fixture README — an expectation is only meaningful against a known input.
3. Hand-write `expected/`.
4. Write the README answering the three questions in §3.
5. Add a row to §2 of this document.

**Never commit a real customer repository**, and never commit anything requiring credentials to fetch. Fixtures are public by construction.

---

## 7. Refreshing raw artifacts

Pinned `raw/` files drift from what current engines emit. Refresh when an engine version is bumped in `OSINT/tools.manifest.yaml`:

```
task osint:sync
go run ./cmd/axebom fixtures refresh --fixture npm-simple
task test:golden
```

Expect diffs, and treat them as findings rather than noise. A changed component count after an engine bump is exactly the signal the corpus exists to produce: either the engine improved, or it regressed, and **either way somebody needs to look**. Record the outcome in the fixture README.


## 2026-09-05 — every SBOM golden regenerated, for two reasons

⚠ **A golden change needs a justification, so here is the whole of it.** Nothing
about identity, dedup or the alias graph moved; no component was added or
removed in any fixture.

1. **`license_refs` is now emitted on every component**, empty unless a licence
   string could not be mapped to SPDX. Purely additive — `Resolution.raw` was
   computed and discarded, and `normalize.license_refs` (whose whole purpose is
   letting a human map it later *without re-scanning*) had no writer at all.

2. **Manifest pseudo-components moved `required` → `excluded`.** trivy emits one
   `application` component per manifest it targets, named after the file, while
   syft catalogues the same lockfile as `type: file` and was already excluded —
   so a `package-lock.json` was a dependency or not depending on which engine
   saw it. Affected exactly one component in most fixtures and **4 of
   `monorepo-multiroot`'s 16**.

   ⚠ **Completeness fell in every affected fixture** (`npm-simple` 11.49 →
   10.21, `maven-case` 12.77 → 11.70, `monorepo-multiroot` 8.78 → 7.18). An
   excluded component stays in the denominator, so the manifest's name no longer
   counts toward the numerator. The old number was flattered by counting a
   lockfile as an identified component; the new one is the truthful figure.
