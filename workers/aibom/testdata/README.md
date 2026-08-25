# workers/aibom/testdata

Small, hand-picked fixtures for AIBOM adapter/fetcher tests. Not part of the
`fixtures/*/raw/` golden corpus (`docs/09-GOLDEN-CORPUS.md`) — that glob is
consumed by `workers/sbom/test_golden.py`'s SBOM-family normalizer pipeline
(`normalize_fixture` looks for fixed filenames like `syft.json`), and an
AIBOM-shaped file dropped into it would be silently picked up by that
suite's `AVAILABLE` discovery and fail for the wrong reason. This directory
exists so an AIBOM fixture can be captured and committed without touching
that pipeline at all.

## `aibom-generator-distilbert-base-uncased.cdx.json`

The ACTUAL response `workers.aibom.adapters.aibom_generator_fetch
.fetch_model_card("distilbert-base-uncased", "")` returned in this session,
running the real `owasp-aibom-generator==1.0.2` (commit
`9b8056a66c03d4f6cf707059b83b21f97923c27b` of `main` — no tagged release
exists, see `unpinned_reason` in `OSINT/tools.manifest.yaml`) against the
real Hugging Face API. Captured the same way `fixtures/crypto-mixed/raw/`
pins a real `cbomkit-theia` response, for the same reason: a hand-built
CycloneDX fixture cannot prove anything about what the real tool actually
emits.

`workers/aibom/test_aibom.py::test_real_upstream_output_round_trips_into_a_populated_card`
replays it offline and proves it parses into a populated `ModelCard` —
including one honest gap: `parse_model_card._developer()` only reads
`author`/`publisher`, but real aibom-generator output names the publisher via
`authors`/`supplier` instead, so `developer` comes back `""` against this
real fixture rather than a guessed value. Left as a stated limitation, not
patched — see the test's own comment.
