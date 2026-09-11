# 03 — Normalizer Specification

> **⚑ SSOT for normalization behaviour.** Component identity, vulnerability dedup, license resolution, dependency-graph merge, coverage computation, provenance.

This is the load-bearing component of the product. Everything a customer sees — component counts, vulnerability counts, coverage percentages, the direct-vs-transitive split — is produced here. **A normalizer that is silently wrong is worse than no product at all**, because a compliance artifact converts an unknown into a false negative the customer trusts.

Read this before touching `workers/*/normalize` or `services/scan-orchestrator`.

**Related:** `01-DATA-MODEL.md` (persisted shapes), `04-OSINT-INTEGRATION.md` (what each engine emits), `09-GOLDEN-CORPUS.md` (the fixtures that prove this works).

---

## 0. The core property: replayability

> Normalization is a **deterministic pure function** of *(raw artifacts + ruleset version + alias snapshot)*.

- Raw scanner output is written once to object storage and **never mutated or deleted**.
- Fixing a normalizer bug means **re-normalizing stored artifacts into `normalization_version + 1`** — not re-running the scanners.
- Normalized data is never overwritten in place. It is versioned.

Three things follow, and they are the reason this design is worth its cost:

1. A report issued today can be defended six months from now, because the exact inputs and ruleset are recorded.
2. A dedup bug fixed in month 9 applies retroactively to every scan ever run.
3. A future CERT-In revision is a data change plus a re-normalization pass — not a re-scan of every customer project.

Consequence for implementation: **no wall-clock reads, no randomness, no network calls inside the normalizer.** The alias graph is passed in as a pinned snapshot; `generated_at` comes from the scan record, not `time.Now()`. If a function needs the current time, it takes it as an argument.

---

## 1. Component identity

### 1.1 PURL canonicalization

Every engine emits PURLs with slightly different conventions. Canonicalize before comparing:

1. Parse per purl-spec. Lowercase `type`. Lowercase `namespace` **only for case-insensitive types**.
2. Apply per-ecosystem name rules:

| Ecosystem | Rule |
|---|---|
| `pypi` | PEP 503: lowercase, collapse runs of `-`, `_`, `.` to a single `-` |
| `npm` | lowercase; `@scope/name` must be percent-decoded before comparison (`%40types/node` ≡ `@types/node`) |
| `maven` | **case-preserving.** `groupId` and `artifactId` are case-sensitive |
| `golang` | **case-preserving**, and decode module-proxy escaping (`!x` → uppercase `X`) |
| `nuget` | case-insensitive compare, preserve display case |
| `deb`/`rpm` | lowercase name; `epoch` and `arch` are identity-bearing |

3. **Qualifier handling.** Strip to typed fields, do not keep in the key: `repository_url` → `source_repo`, `download_url`, `checksum` → `hashes`, `file_name`, `vcs_url`.
   **Keep as identity:** `arch`, `distro`, `os`, `epoch`, Maven `classifier` and `type`, conda `channel`.
4. Always retain `version_raw` verbatim. Compute `version_normalized` for display and ordering only. **Never merge two components whose `version_raw` differs.**
5. Emit the canonical PURL with qualifiers sorted lexicographically and percent-encoding normalized.

### 1.2 The `component_key` fallback chain

First rule that produces a value wins. **Always record which rule fired in `identity_rule`** — it drives confidence and appears in provenance.

| # | Rule | Key form | Typical origin | Confidence |
|---|---|---|---|---|
| 1 | PURL | `purl:<canonical>` | syft, trivy, osv-scanner | high |
| 2 | CPE | `cpe:<canonical CPE 2.3>` | dependency-check | medium |
| 3 | SWID | `swid:<tagId>` | firmware, HBOM | medium |
| 4 | Hash | `hash:<sha256>` | syft binary classifier, opaque blobs | medium |
| 5 | File | `file:<normalized-rel-path>@<sha256>` | vendored source trees | low |
| 6 | Name | `name:<ecosystem>/<norm-name>@<version_raw>` | AIBOM model lists, HBOM CSV | low |
| 7 | Opaque | `opaque:<uuidv5(scan, engine + raw_id)>` | last resort | low |

Rule 7 **never merges with anything**. It emits a `NORMALIZE_IDENTITY_OPAQUE` diagnostic and increments `bom_documents.unidentified_count`.

### 1.3 Merge

Group by `component_key`, then:

- **Union** locations, hashes, licenses (kept separate by kind), CPEs, evidence.
- `scopes`: union with precedence `required > optional > excluded`.
- `is_direct`: OR across **trusted graph sources only** (see §4) — never across all engines.
- `observed_by[]`: append `{engine, engine_version, native_id, confidence}` for every engine that saw it.

### 1.4 Traps

**Never merge on name+version across ecosystems.** `name:npm/lodash@4.17.21` is not `name:maven/lodash@4.17.21`. Always prefix the ecosystem. This is the single most common dedup bug in SBOM tooling and it silently collapses unrelated components.

**Never merge a low-confidence CPE into a PURL-identified component.** Dependency-Check emits CPEs with a confidence field. A `LOW` match attaches as a **candidate identity** (`normalize.component_candidate_identities`), not a merge. Merging inherits Dependency-Check's false positives into otherwise-clean data, and the customer cannot tell which findings came from a guess.

**Identity is the package; locations are 1:N.** The same jar vendored at two paths is one component with two locations, not two components. Putting the path in the key inflates every count.

**Go module vs package.** syft reports the module; trivy sometimes reports the package. Reconcile on **module path only**.

**Container layers.** The same package in three layers is one component. Layer is a location attribute.

### 1.5 The `model_key` chain — AI models

An AI model is not a package, and identifying it as one is how `normalize.ai_models`
came to hold three rows for a single model. `component_key` rule 6 above reserves its
lowest-confidence tier for "AIBOM model lists"; this is the ladder that feeds it.

First rule that produces a value wins. **Always record which rule fired in
`identity_rule`** — it drives `identity_confidence` and appears in provenance.
Implementation: `workers/aibom/identity.py`.

| # | Rule | Key form | Typical origin | Confidence |
|---|---|---|---|---|
| 1 | HF repo + revision | `purl:pkg:huggingface/<org>/<name>@<sha>` | ai-bom, airom, cdxgen `-t ai` | high |
| 2 | Weight digest | `hash:<sha256>` | safetensors / gguf header, `model_signing` | high |
| 3 | OCI digest | `oci:<digest>` | model images, Ollama | high |
| 4 | Hosted API model | `api:<provider>/<model>@<version>` | OpenAI, Anthropic, Bedrock, Vertex | medium |
| 5 | Local checkpoint | `file:<rel-path>@<sha256>` | a committed weights file | low |
| 6 | Name | `name:<provider>/<name>@<version>` | a bare reference in source | low |
| 7 | Opaque | `opaque:<uuidv5(scan, bom_ref + purl)>` | last resort | low |

**Every tier is prefixed, and the prefix is load-bearing.** It is what stops a weight
digest from colliding with a name somebody typed.

**Rule 4 never merges across providers.** `openai/gpt-4o` and `azure/gpt-4o` are
billed, governed, versioned and deprecated separately; folding them together
attributes one provider's terms to the other — the same error class as merging
`pkg:npm/lodash` with `pkg:maven/lodash`.

**Rule 7 never merges with anything, including another opaque model.** Two models we
cannot identify are two models. Collapsing them under-reports an inventory, which is
the direction of error a compliance document must not take.

#### The classification rule that precedes the ladder

**A component whose purl is an ordinary package purl (`pkg:pypi/…`, `pkg:npm/…`,
`pkg:maven/…`) is a framework, whatever `type` the engine declared** — unless it also
carries a resolvable model reference, which is positive evidence that outranks the
purl.

This is not defensive coding; it is a measured defect. ai-bom 3.1.0 labels the
`transformers` PyPI library `type: machine-learning-model` with
`purl: pkg:pypi/transformers`. A purl minted by a package ecosystem is that
ecosystem's own assertion about what the thing *is*, and it outranks a type field a
scanner guessed. `pkg:huggingface` is excluded from the rule: that one does name a
model.

**A reclassification is always reported** (`AIBOM_MODEL_RECLASSIFIED`). A model count
that changes with no diagnostic beside it is a number nobody can account for.

**A purl is validated before it is trusted as identity.** ai-bom emits purls containing
literal spaces (`pkg:pypi/huggingface transformers`, verbatim from captured output).
Such a value is dropped, not stored: a malformed merge key matches nothing and dedups
against nothing while looking exactly like a real identifier in the report.

#### The alias fold that follows the ladder

**A `name:`-tier model folds into a stronger one asserting the same model id.**

Measured live on a real three-engine scan: `gpt-4o` was stored **twice**. ai-bom puts
the *calling framework* in its provider property — its real values are `LangChain`,
`HuggingFace`, `ChromaDB` — so its sighting keyed as `name:langchain/gpt-4o`, while
airom and cdxgen-ai both report the actual serving provider and keyed as
`api:openai/gpt-4o`. One model, two rows in a Table 10 inventory, and the row count is
a headline number a reviewer reads. Adding engines multiplied the defect the ladder was
introduced to stop.

The fold is deliberately narrow, because merging two models that are not the same model
is worse than listing one twice:

- only a **low-confidence `name:` key** is ever absorbed; a strong key is never folded
  into anything;
- the **asserted model ids** must match exactly, case-insensitively — the display name
  is never a fallback, because folding on `LangChain Model` would merge every model one
  framework loads into a single row;
- and **exactly one** strong candidate may claim it. Two candidates means the name is
  ambiguous — `gpt-4o` from two providers is two models — so nothing is folded and
  `NORMALIZE_IDENTITY_AMBIGUOUS` is reported instead.

A fold is always reported (`NORMALIZE_IDENTITY_ALIAS_FOLDED`), and it is counted
separately from ordinary duplicate-sighting merges: "one model referenced from three
files" and "two engines disagreed about a provider" are different facts, and one number
covering both would attribute the second to the first.

#### Evidence paths are relative to the repository root

Every sandboxed engine sees the tree at `/src`, because that is where the runner mounts
it. ai-bom echoes that prefix into its evidence and airom does not — so a model both
engines found came out carrying `/src/app.py:17` **and** `src/app.py:17`, which reads as
two files, the first of which reads as a path outside the repository. The mount is
stripped once, in `workers/aibom/discovery.repo_path`, so a fourth engine cannot forget.

#### AI assets have their own key, and the discriminator depends on the kind

Prompts, vector stores, RAG pipelines and inference endpoints are merged across engines
into `normalize.ai_assets` on `<asset_type>:<discriminator>`. **A prompt keys on its
location** — a prompt IS a piece of text at a place, and airom names every system prompt
`system-prompt`. **Everything else keys on its provider or name** — Chroma is one Chroma
however many files mention it. Keying both on location splits one vector store in two;
keying both on name collapses every system prompt in a repository into one.

### 1.6 The `asset_key` chain — crypto assets

A crypto asset had no identity: `crypto_assets.component_key` held the engine's own `bom-ref`, which `cbomkit-theia` mints at random on every run, so nothing could say whether two rows were the same key — and a second crypto engine could only duplicate what the first reported. `asset_key` is the crypto counterpart of `component_key` (§1.2) and `model_key` (§1.5), produced by `workers/cbom/normalize/identity.py` over the canonical algorithm identity in `libs/py-shared/axebom_shared/crypto/identity.py`. Every tier is prefixed, so two tiers never collide.

| asset_type | Tier (first that applies wins) | `identity_rule` | Confidence |
|---|---|---|---|
| algorithm | `algorithm:<family>;bits=…;digest=…;mode=…;padding=…;curve=…;param=…;scheme=…;primitive=…` (only the parts known) | `algorithm` | high when bits, digest, curve or parameter set is known; else medium |
| algorithm | `name:algorithm/<name>;primitive=…` — family not recognised | `algorithm-name` | low |
| key | `key:fp:<alg>:<hex>` — SHA-256 over a PUBLIC key's DER, or the engine's material fingerprint | `key-fingerprint` | high |
| key | `key:<material>;alg=…;size=…;path=<repository path>[:line]` — `alg` from the key's own name, else from the algorithm its engine links it to | `key-location` | medium |
| certificate | `cert:fp:<alg>:<hex>` | `certificate-fingerprint` | high |
| certificate | `cert:issuer-serial:<issuer>/<serial>` | `certificate-issuer-serial` | high |
| certificate | `cert:<subject>;issuer=…;from=…;to=…` | `certificate-subject-issuer-validity` | medium |
| protocol | `protocol:<family>;version=<v>` — the family read out of the name (`TLSv1.2` → `tls`), the version from its field or else the name | `protocol` | high with a version; else medium |
| any | `opaque:<engine>:<native ref>` — nothing better; never merges | `opaque` | low |

- **Never a name alone for a recognised algorithm.** One certificate yields two assets named `RSA` — one `signature`, one `pke` — and they are different uses; the primitive is part of the key.
- **Hash-and-sign RSA is PKCS#1 v1.5 unless it says PSS.** JCA's `SHA256withRSA` states no padding; `cbomkit-theia` labels the same algorithm `SHA256-RSA` with `padding: pkcs1v15`. The key records the scheme, not the literal padding field, so the two merge.
- **`parameterSetIdentifier` is interpreted per family** — key bits for AES, digest bits for SHA, a named set for SLH-DSA, a modulus only when no digest is present. theia's `SHA256-RSA` carries `256`, the digest; read as a modulus it would report a 256-bit RSA key.
- **Engine `bom-ref`s are never identity.** They resolve references inside the one document that minted them (a certificate's signer and public key, a key's algorithm) and are kept as provenance (`native_ref`).
- **A key's algorithm is read wherever its engine states it** — `algorithmRef`, a 1.7 `relatedCryptographicAssets` entry, or a CycloneDX `dependencies` edge to exactly one algorithm, which is the only form `cbomkit-action` uses. It feeds the key's `alg=` and its analysis: judged on its name alone (`key`), a generated RSA key was reported not quantum-vulnerable. A key depending on two algorithms is linked to neither.
- **A protocol's name is not its key.** `cbomkit-action` names TLS 1.2 `TLSv1.2`; another engine says `TLS` with version `1.2`. Both are `protocol:tls;version=1.2`.
- **Private-key material is never an input.** A private key is identified by where it was found; its bytes are never read.
- **Location is evidence, not identity (§1.4)** — except for a key with no fingerprint, where the location, line included, is the only thing that distinguishes two keys.

**Merge.** Raw assets sharing a key become one BEFORE normalization, so the analysis and the reference derivation run once over everything every engine reported. List fields are unioned. For a scalar, the engine that read the thing wins — for algorithms and protocols the source engines (`cbomkit-action`, then `cdxgen-cbom`) outrank `cbomkit-theia`; for keys and certificates `cbomkit-theia`, which reads the file, ranks first — and every disagreement is a `NORMALIZE_CRYPTO_FIELD_CONFLICT` diagnostic, never resolved silently. Evidence is kept per engine as `[{path, line, engine}]`; `normalize.crypto_asset_provenance` holds one row per (asset, engine). Only an engine that reads key FILES may mark a key as found in the source: `cbomkit-action` reports keys the code generates at runtime.

**Derived values.** When an exactly identified algorithm lacks a Table 9 field that an authoritative source states — the classical security strength (NIST SP 800-57 Part 1 Rev. 5 §5.6.1.1 Table 2; RFC 8032 §8.5 for Ed25519/Ed448) or the OID (NIST CSOR; RFC 8017, 5758, 3279, 8410, 8018) — the normalizer fills it from `libs/py-shared/axebom_shared/crypto/reference.py`. The value counts as present (§5.3); `crypto_assets.derivations` names each filled column and its source, `field_status` records `derived`, and every report footnotes it. It never overwrites an engine value; a disagreement is diagnosed. Only exact rows are used — no interpolation (RSA-4096 is not a row of Table 2), and a source that states a value only approximately (X25519's "~128") is not used. The table's digest is pinned to the CBOM ruleset version.

---

## 2. Vulnerability identity — the alias transitive closure

This is where naive implementations quietly fail. Four engines report the same vulnerability under four different namespaces:

| Engine | Emits |
|---|---|
| grype | GHSA ids primarily |
| osv-scanner | OSV-native — `GO-`, `PYSEC-`, `RUSTSEC-`, `MAL-`, `GSD-` |
| dependency-check | CVE (via NVD/CPE) |
| trivy | CVE **and** GHSA |

**Deduping on the primary id inflates counts roughly 3×.** A report claiming 240 vulnerabilities where there are 80 is not a minor cosmetic issue — it drives remediation budgets.

### 2.1 Algorithm

1. **Ingest every finding raw** into `normalize.raw_findings`. **Never dedup at ingest** — that destroys the audit trail and makes the merge unexplainable.

2. Maintain a **global, not per-scan** edge set `normalize.vuln_alias_edges(id_a, id_b, source, authoritative)`. Undirected. Ids normalized as `<NS>-<value>`, NS ∈ `CVE`, `GHSA`, `OSV`, `SNYK`, `RHSA`, `DSA`, `USN`, `ALAS`, `ELSA`, `DLA`, `NPM`.

3. Edge sources, in trust order:
   | Source | Authoritative |
   |---|---|
   | OSV.dev `aliases` / `upstream` | ✅ |
   | GHSA advisory `identifiers` | ✅ |
   | distro-advisory → CVE from grype/trivy metadata | ❌ |
   | scanner-asserted alias | ❌ |

4. **Union-find over the edge set.** The connected component is the vulnerability identity. This is the transitive closure the problem requires: `CVE-2021-44228 ↔ GHSA-jfh8-c2jp-5v3q ↔ SNYK-JAVA-…` collapse into one cluster even though no single tool asserts the full triangle.

5. Display id = lowest-rank member. Rank: `CVE < GHSA < OSV-native < vendor`.

### 2.2 Trap A — cluster identity must be durable

> **Do NOT derive the cluster id from its members** — not `uuidv5(sorted member list)`, not a hash, not anything content-derived.

Such an id **mutates the moment a new alias is discovered**. Every foreign key breaks, and every previously issued report references an id that no longer exists.

Instead:

- `normalize.vuln_clusters.id` is a **durable surrogate row**.
- Merging two clusters writes `normalize.vuln_cluster_merges(from_id, into_id, evidence_edge_id)`; a view resolves old ids forward.
- **Reports pin `display_id_at_render`.** A report issued in March still says `CVE-2021-44228` in September, even if the cluster has since absorbed more aliases.

### 2.3 Trap B — over-merge

OSV aliases are not always equivalence-safe. Some GHSAs alias several genuinely distinct CVEs (batched advisories); `MAL-` ids alias broadly. Unguarded union-find will eventually merge unrelated vulnerabilities into one cluster, under-reporting.

Three guards, all required:

1. **Refuse to merge two `CVE`-namespace ids unless an authoritative source asserts it.** A scanner-asserted CVE↔CVE edge is not sufficient.
2. **Cap cluster size.** Above 12 members, set `flagged_for_review = true` and stop auto-merging that cluster. A cluster that large is far more likely to be an over-merge than a real advisory family.
3. **Log every merge with its evidence edge.** A compliance product must be able to answer "why did these two findings become one?" If it cannot, the merge should not have happened.

### 2.4 Finding dedup and severity

Finding key: `(vuln_cluster_id, component_key)`.

| Situation | Result |
|---|---|
| Two engines, same CVE, same jar | **one** finding, `detected_by: [grype, trivy]` |
| Same CVE, two different components | **two** findings |
| Same CVE, same component, two paths | **one** finding, two locations |

**Severity is never averaged.** Precedence for `severity_effective`:

1. tenant policy override
2. CVSS **v4** vector
3. NVD CVSS **v3.1**
4. advisory CVSS v3.1
5. vendor severity string
6. max of remaining tool strings

> **CVSS v2, v3.1 and v4.0 are not comparable.** They use different formulas and different ranges. Never take a max across versions — a v2 score of 10.0 is not "worse" than a v3.1 of 9.8; they are different scales.

Store **every** source in `cvss_vectors`, and set `severity_conflict = true` when engines disagree. **Surface the conflict in the UI.** Hiding it is the wrong instinct: a reviewer will ask why Trivy said High and Grype said Critical, and the answer must be visible, not buried.

### 2.5 Fix versions

Union `fixed_versions` per ecosystem, then compute `fixed_in_min` with an **ecosystem-correct comparator**:

| Ecosystem | Comparator |
|---|---|
| npm, cargo | semver |
| pypi | PEP 440 |
| maven | Maven version order |
| rpm | EVR (epoch:version-release) |
| deb | Debian version order |
| golang | semver + `+incompatible` handling |

**Naive string sort is wrong for every one of these.** `1.10.0` sorts before `1.9.0` lexically.

If no comparator exists for the ecosystem, set `fix_version_ordering = 'unknown'` and emit `NORMALIZE_NO_VERSION_COMPARATOR`. **Do not guess.** `patch_status` then derives to `unknown` rather than a fabricated answer.

#### 2.5.1 `patch_status` (CERT-In field 9)

Derived per finding, then aggregated per component. The four values are the profile's own (`certin.sbom.09.patch_status`), not ours to extend.

| `fix_version_ordering` | Derives to | Why |
|---|---|---|
| `none` | `no-fix-available` | Engines reported **zero** fix versions. A substantive claim a reader acts on ("upstream has published nothing"), true regardless of the installed version. |
| `unknown` | `unknown` | No comparator for the ecosystem — nothing can be said either way. |
| `comparator` | `up-to-date` if installed ≥ `fixed_in_min`, else `patch-available` | The only case where a real comparison happened. |

**`no-fix-available` and `unknown` are different claims and must not be collapsed** — the first is a finding, the second is an admitted gap.

**Aggregation across a component's findings is worst-case-wins:** `no-fix-available` > `patch-available` > `unknown` > `up-to-date`. The field describes the whole component, so one unfixable vulnerability among thirteen fixed ones makes the component `no-fix-available`; reporting `up-to-date` would hide the gap the field exists to surface. `unknown` outranks `up-to-date` because claiming a component is up to date when one finding could not be evaluated asserts a verification that never happened.

**A component with no findings leaves `patch_status` unset (`not-provided`), never `up-to-date`.** "Nothing was reported against this" is ambiguous between *verified clean* and *no engine covered this ecosystem* — and the component carries no signal to tell those apart (that is the provenance manifest's `ecosystems_without_engine`). Defaulting would manufacture a substantive value out of an absence, which is exactly what §5.4's `not-provided` rule forbids.

### 2.6 VEX

VEX applies **after** dedup and **never mutates a finding**. It is a joined `normalize.vex_statements` row with a CSAF 2.0 status ∈ `not_affected`, `affected`, `fixed`, `under_investigation`, plus a justification code.

Effective status = most specific scope, then latest timestamp. VEX statements are append-only and versioned — CERT-In §6 (p.35) is explicit that VEX is an iterative process.

---

## 3. License resolution

### 3.1 Pipeline

1. Exact SPDX id match.
2. Case- and punctuation-insensitive match.
3. Curated alias table (~300 entries): `"Apache 2"`, `"ASL 2.0"`, `"Apache License, Version 2.0"` → `Apache-2.0`.
4. SPDX **expression** parse with grammar validation for `AND`, `OR`, `WITH`, parentheses.
5. Fallback: `LicenseRef-AxeBOM-<slug>`, with the raw text preserved in `normalize.license_refs` for later human mapping.

**Pin and record the SPDX license-list version** (e.g. 3.25) in `bom_documents.spdx_license_list_version`. Ids are deprecated and added over time; a report must state which list it was validated against.

### 3.2 Three kinds, kept separate

| Kind | Source |
|---|---|
| `declared` | manifest metadata (`package.json` `license` field) |
| `concluded` | license-file scan, or a human decision |
| `observed` | text found in source headers |

SPDX requires the distinction and compliance reviewers ask for it. **Never overwrite `declared` with `concluded`.** Expose `license_effective` plus `license_rule` recording which produced it.

### 3.3 Traps

**`NOASSERTION` and `NONE` are different, both valid SPDX, and neither is an error.** Do not coerce either to null.

- `NONE` — "we looked and there is no license." A **substantive assertion**. Counts as present for coverage.
- `NOASSERTION` — "we are not saying." Counts as **absent**.

**Deprecated ids are ambiguous — flag, never resolve.** `GPL-2.0` maps to either `GPL-2.0-only` or `GPL-2.0-or-later`, and the guideline gives no way to choose. Set `license_ambiguous = true` and surface it. **Choosing wrong is a legal error, not a data-quality error**, and it is not the normalizer's decision to make.

**Do not flatten `A OR B` at normalize time.** Which disjunct applies is a *policy* decision belonging to a later, configurable layer. Store the expression.

---

## 4. Dependency-graph merge

### 4.1 Model

`normalize.component_dependencies(bom_document_id, from, to, relationship, scope, owning_engine, confidence)` with relationships aligned to CycloneDX/SPDX: `depends_on`, `contains`, `describes`, `generated_from`, `variant_of`.

### 4.2 Replace, do not union

> **The critical rule.** Tools disagree *structurally*, not just in detail. syft produces a near-flat inventory with weak edges; manifest/lockfile-native resolution produces true edges.

Declare a per-ecosystem trust order (`graph_trust` in the engine registry, §7 of `02-CONTRACTS.md`). **Where a higher-trust engine supplies a graph for an ecosystem, replace that ecosystem's subgraph entirely rather than unioning.**

Unioning invents phantom transitive edges and corrupts the direct-vs-transitive counts — which is precisely the number a **Top-Level report** is built on. Record `owning_engine` per ecosystem so provenance can explain the shape of the graph.

### 4.3 Roots, depth, cycles

**Roots: one per detected package/module, not one per repository.** A monorepo has N roots. Getting this wrong makes every workspace package look like a direct dependency of one imaginary root.

**Cycles are real.** Go module graphs and npm workspaces contain them. Never assume a DAG:

- Depth = BFS from the root set with a visited set.
- Components unreachable from any root get `depth = NULL, is_orphan = true`. **Never force them to depth 1** — that silently inflates the direct-dependency count, and "direct dependencies" is a headline number.
- `is_direct` is stored **explicitly from the root set**, never inferred from depth.

Level derivation: **Top-Level** = `depth <= 1`. **Complete** = everything, orphans included and flagged.

---

## 5. Coverage

### 5.1 Formula

```
pct = 100 × Σ_c Σ_f (w_f × present(c,f)) / Σ_c Σ_f w_f
```

Computed only over in-scope components, against the **declared required-field set for that BOM type** from `reference/certin-v2.0.yaml`. **The formula is published in every report** so the number is auditable rather than magic.

### 5.2 Two numbers, always both

| Metric | `present()` counts | Meaning |
|---|---|---|
| `completeness_pct` | substantive values **only** | **The honest compliance signal.** |
| `declaration_pct` | any value, incl. explicit `not-provided` | Representation completeness. Format validity, not compliance. |

`not-provided`, `NOASSERTION`, `unknown`, `""`, `[]` → **`present = 0`** for `completeness_pct`.

> This is the crux, and where most tools mislead. A field explicitly marked `not-provided` is **reported** — which is why we store it rather than omitting it — but it is **not covered**. Publishing only `declaration_pct` and labelling it "coverage" produces a 100% score for a BOM that knows almost nothing. Both numbers, in every report, always.

**The one exception:** license `NONE` counts as **present**. It is a substantive assertion (§3.3). Document this; it will be argued about, and you want a written answer.

### 5.3 Type-aware scoring

CERT-In Table 9 is **type-discriminated**. Score a crypto asset only against the field set for its `asset_type` — `algorithm`, `key`, `protocol` or `certificate` — exactly as the compliance profile defines it (`docs/reference/certin-v2.0.yaml` → `crypto_asset`). The sizes of those sets are never restated here or anywhere else (invariant 2); every report renders them from the profile.

A list-valued canonical path is written with a trailing `[]` (`crypto_asset.cipher_suites[]`). The `[]` is notation: the scored key, and the stored `field_status` key, is the path without it. Every field of the asset's own type is scored either as its value or as an explicit `not-provided` — the same statuses `field_status` stores — so an unknown field counts toward `declaration_pct` and scores zero toward `completeness_pct` (§5.2). One module computes both (`axebom_shared.normalize.crypto_status`).

A value derived from the cited reference table (§1.6) is a real property of the named algorithm and counts as **present**; its `field_status` is `derived`, not `provided`, and the CBOM coverage breakdown carries a per-field `derived` count and a `derivation_sources` map (reference id → citation) so every report can say how much of each field's "present" came from AxeBOM's lookup rather than an engine.

Scoring a certificate against `key_size` (a Keys field) would report every CBOM at roughly 30% coverage — **falsely, in a compliance document.** The coverage checker branches on `asset_type`. This is not an optimization; it is a correctness requirement.

### 5.4 Weights and the denominator

- `w = 3` for minimum-element / identity-bearing fields; `w = 1` for enrichment. Weights come from the profile YAML and are **AxeBOM's judgement, not CERT-In's** — the guideline does not rank its fields. Every report footer says so.
- Components with `scope = excluded` or `identity_rule = opaque` go to `unidentified_count` and are **never silently dropped from the denominator.** Dropping them lets a bad scan report 100%.
- **A manifest is evidence, not a dependency.** A CycloneDX component typed `file` — or typed `application` *with no purl* — is what the inventory was derived FROM, not a part of the product: a `package-lock.json`, a `requirements.txt` or a `pom.xml` anywhere in the tree. Both are `excluded`.
  > ⚠ **The `application` half was missing, and the two engines disagreed.** syft catalogues a lockfile as `type: file` (excluded); trivy emits one `application` component per manifest it targets, named after the file, and those counted as **required dependencies**. The same lockfile was a dependency or not depending on which engine saw it. Found live: 31 such rows, and 4 of `monorepo-multiroot`'s 16 "components".
  >
  > The `no purl` condition is load-bearing: a genuinely bundled application *is* a dependency and carries a purl. Excluding every `application` would drop real components.
  >
  > ⚠ **This lowers `completeness_pct`, and that is the honest direction.** An excluded component stays in the denominator, so its name no longer counts toward the numerator — `npm-simple` moved 11.49% → 10.21%. The previous number was flattered by counting a lockfile as an identified component.
- Always render a **per-field breakdown table** and the **Engine Coverage table** — including ecosystems detected with *no* available engine. That last row is the honest denominator most tools hide, and it is a genuine differentiator.

---

## 6. The CERT-In identifier

`component.certin_identifier` is **derived, render-only, and never a merge key.** See `01-DATA-MODEL.md` and `reference/certin-v2.0.yaml` field 21.

```
certin_identifier = "pkg:supplier/" + pascal(supplier) + "/" + pascal(name)
                  + "@" + version_raw
                  + qualifiers        (sorted, "&"-joined, from the canonical purl)
                  + "#" + subpath     (if present)
```

Notes:

- CERT-In's own text says `&subpath` while its Table 6 example uses `#subpath`. **Treat `#` as canonical**, per purl-spec, and record the discrepancy in the report's methodology footnote.
- Where `supplier` is `not-provided`, emit the namespace from the ecosystem PURL and mark the field `not-provided` for coverage — do **not** fabricate an organization name.
- The pure function lives in `libs/go-shared/model/certinid.go` and is golden-tested against the exact example in Table 6.

---

## 7. Provenance

Every normalized entity carries:

```jsonc
{ "engine_id": "grype", "engine_version": "0.87.0",
  "engine_db_version": "grype-db v5 2026-08-15T00:00:00Z",
  "job_id": "…", "raw_finding_id": "…",
  "artifact_uri": "s3://…", "artifact_sha256": "…",
  "rule_id": "vuln.alias.union", "rule_version": "2026.08.1",
  "confidence": "high", "observed_at": "…" }
```

And the scan carries a `provenance_manifest`: resolved tool ids/versions/digests, SPDX license-list version, alias-graph snapshot id, `ruleset_version`, source commit sha, workspace archive sha256.

For crypto assets, per-entity provenance is `normalize.crypto_asset_provenance` — one row per (asset, engine) with the engine version, the engine's own `native_ref`, what it called the asset, the stored artifact's sha256, and where that engine saw it — alongside the merged `evidence` on the asset (§1.6). A value AxeBOM filled rather than an engine reporting it is named in `crypto_assets.derivations` with its cited source.

Together these are what let you answer, in an audit, "where did this line in this report come from?"

---

## 8. Cross-cutting traps

**Time.** All timestamps UTC RFC3339 with a literal `Z`. No local time anywhere, ever.

**Hostile filenames.** User repositories contain filenames with newlines, NUL bytes, 4-byte emoji, right-to-left overrides, and 8 KB paths. Sanitize and truncate **before** insert, not after. A NUL in a path will silently truncate a Postgres text value.

**Spreadsheet formula injection.** A component named `=cmd|'/c calc'!A1` **executes when the XLSX is opened.** Prefix any cell value beginning with `=`, `+`, `-`, `@`, TAB or CR with a single quote. This is a repeatedly-shipped vulnerability class in SBOM tooling, and this product's entire output surface is spreadsheets. The escaping belongs in the writer, applied unconditionally — not at each call site, where it will be forgotten.

**Scale.** 50k+ components and 200k+ findings per scan is normal for a large monorepo. Bulk-insert via `COPY`. Cap at ~250k components with a loud diagnostic rather than silent truncation. Paginate everything.

**Determinism.** No `time.Now()`, no `rand`, no network calls inside normalization. Sort every collection before serializing, or golden tests will flap and their failures will be ignored — which is worse than not having them.

---

## 9. Test requirements

Normalizer changes are gated on `task test:golden`. See `09-GOLDEN-CORPUS.md`.

Required unit coverage, at minimum:

- PURL canonicalization: one case per ecosystem rule in §1.1, including `@scope` percent-encoding, Go `!x` decoding, and rpm epoch/arch.
- Identity fallback: one fixture per rule 1–7, asserting `identity_rule` and `identity_confidence`.
- **Never-merge assertions**: `npm/lodash@4` vs `maven/lodash@4` stay separate; a LOW-confidence CPE does not merge into a PURL component.
- Alias union-find: the Log4Shell triangle collapses to one cluster from three partial edge sets; cluster id is stable across a subsequent merge; a >12-member cluster is flagged, not merged; a non-authoritative CVE↔CVE edge is refused.
- Severity: no averaging; v2/v3.1/v4 never max'd across versions; conflicts flagged.
- Fix versions: correct ordering per ecosystem comparator; `unknown` emitted where no comparator exists.
- License: `NONE` present, `NOASSERTION` absent, `GPL-2.0` flagged ambiguous, alias table hits.
- Graph: per-ecosystem replacement not union; cycle does not hang; orphan gets `depth = NULL`; monorepo yields N roots.
- Coverage: `not-provided` scores 0 for completeness and 1 for declaration; crypto scoring is type-aware; excluded components stay in the denominator.
- CERT-In identifier: exact match against the Table 6 worked example.

**Changing a golden file requires an explicit justification in the commit message.** Goldens are the only mechanical guard against silently wrong BOM output; a golden updated without reasoning is a guard removed.
