# Phase 12 — AIBOM

**Estimated: 2.5 weeks** · Depends on Phase 10.

## Read first

1. `docs/STATE.md`
2. `docs/reference/certin-v2.0.yaml` → `aibom` (19 elements, PDF p.54–55)
3. `docs/01-DATA-MODEL.md` §6 (`normalize.ai_models`, `ai_datasets`)
4. `docs/04-OSINT-INTEGRATION.md` — AIBOM section

## Goal

Discover AI usage in a codebase, enrich the referenced models, and produce a CERT-In Table 10 AIBOM exportable as a CycloneDX ML-BOM.

## Preconditions

MVP works. `ai-bom` and `aibom-generator` report available.

## The two-tool split

They do different jobs and both are needed:

- **`ai-bom` (Trusera)** — *code-level discovery*. What the repository actually uses: LLM providers, agent frameworks (LangChain, CrewAI, AutoGen, LlamaIndex, LangGraph), MCP servers, model references, AI containers.
- **`aibom-generator` (OWASP)** — *model enrichment*. Given a Hugging Face model id, pulls the model card, config, license and a completeness score.

Discovery finds what to enrich; enrichment fills Table 10. Both emit CycloneDX 1.6, so the merge is clean.

## Out of scope

Model behavioural evaluation, prompt-injection testing, running any model. This is inventory, not assurance.

## Deliverables

```
workers/aibom/adapters/{ai_bom.py, aibom_generator.py}
workers/aibom/merge.py        discovery + enrichment -> one AIBOM
workers/aibom/normalize/ai.py ML-BOM -> AIModelComponent

services/report/export/mlbom.go      CycloneDX ML-BOM
services/report/render/              AI sections
frontend/                            model inventory, dataset table, risk view
fixtures/ai-langchain/
```

## Contracts to honour

- **All 19 Table-10 elements** populated or explicitly `not-provided`. Several — intended usage, out-of-scope usage, environmental impact, security requirements — are rarely in tool output and will mostly be `not-provided` or user-supplied. **That is the correct outcome**, visible in the coverage number, not something to paper over with a guess.
- `risk_score` and `owasp_llm_top10` are **AxeBOM extensions, excluded from coverage scoring**.
- **`--llm-enrich` stays off by default.** It needs an LLM key and **sends code context to a third party**; enabling it is a per-project decision surfaced in the UI, not a global flag.
- Hugging Face lookups are network calls: they run in the **enrichment step outside the sandbox**, never inside a `--network=none` engine container.

## Steps

1. `ai-bom` adapter over the source archive, in the sandbox, `--format cyclonedx`.
2. Extract referenced model ids from the discovery output.
3. `aibom-generator` per model id, in a network-permitted enrichment step. Cache by model id and revision — the same base model appears across many projects.
4. Merge discovery + enrichment on model identity. Discovery wins on *usage* facts (where it is used, which framework); enrichment wins on *model* facts (license, developer, metrics).
5. Normalize to `normalize.ai_models` and `ai_datasets`; link software dependencies to existing SBOM components where the ecosystems overlap — an AI dependency is usually also a package.
6. Fields with no tool source get a **user-supplied form**: intended usage, out-of-scope usage, security requirements, environmental impact. Same `not-provided` discipline.
7. CycloneDX ML-BOM export via protobom; validate against the 1.6 ML-BOM schema.
8. Report sections: model inventory, dataset table, AI dependencies, risk and OWASP LLM Top-10 (clearly marked as an AxeBOM extension, not a CERT-In element).
9. Fixture `ai-langchain`: LangChain + an OpenAI client + a referenced HF model. Update `docs/STATE.md`.

## Test requirements

- Discovery finds frameworks, providers and MCP servers in the fixture.
- Enrichment populates model metadata for a referenced HF model.
- Merge does not duplicate a model seen by both tools.
- All 19 elements present or explicitly `not-provided`; coverage reflects reality rather than being inflated.
- ML-BOM export validates against the CycloneDX 1.6 schema.
- **`--llm-enrich` is off unless explicitly enabled per project**, and enabling it is audited.
- Enrichment network failure degrades to `partial` + diagnostic — never a failed scan.
- HF lookups are cached; a second scan of the same model does not re-fetch.

## Exit criteria

```
go test ./workers/aibom/... -v
task test:golden       # incl. ai-langchain
task verify
```

Manual: a repo using LangChain and an LLM API → AIBOM lists models, datasets and AI dependencies → ML-BOM export is schema-valid → report shows all Table-10 elements with honest coverage.

## Before you finish

Update `docs/STATE.md`: AIBOM working, tool versions, which Table-10 elements come from tools versus user input, and the typical coverage percentage — if it is low, that is information, not a defect.
