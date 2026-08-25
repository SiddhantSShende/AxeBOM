# crypto-mixed

## What failure mode does this fixture isolate?

Two, both found only by running `cbomkit-theia` against **real** cryptographic
material instead of the hand-built CycloneDX fixtures `workers/cbom/test_crypto_normalize.py`
already used. Neither bug is visible against a hand-built fixture, because a
hand-built fixture's `bom-ref` values are typically written as short,
human-readable strings (`"crypto/algorithm/rsa-2048"`) rather than the opaque
UUIDs the real engine actually emits — and both bugs are specifically about
what happens when a `bom-ref` is an opaque UUID.

1. **A certificate's `signature_algo_ref`/`subject_public_key_ref` were left
   as raw, opaque `bom-ref` UUIDs** (e.g. `"b21f7408-6344-4ea2-a317-541fa2579d3e"`)
   instead of the referenced asset's readable name. Meaningless to a reader
   compiling a CERT-In Table 9 report by hand.
2. **The bigger one: a certificate's own quantum-vulnerability verdict was
   silently wrong.** `crypto.py:analyse()`'s own comment says "for a
   certificate, the interesting primitive is what SIGNED it" — but it built
   that assessment by pattern-matching the *raw, unresolved* `signature_algo_ref`
   as if it were an algorithm name. Against a hand-built fixture using a
   readable fake ref (`"crypto/algorithm/sha256-rsa"`), the regex happened to
   match `rsa` by accident and the bug was invisible. Against this fixture's
   real, opaque UUID ref, the regex matches nothing, and the certificate came
   back `quantum_vulnerable: false`, `deprecation_status: "current"` — a
   **false negative** for a certificate signed with RSA, in a compliance
   document. Fixed by `workers/cbom/normalize/pipeline.py`'s
   `_resolve_certificate_analysis`: a document-level pass, run once
   `normalize_all` has produced every sibling asset, that looks up the
   asset the certificate's *raw* ref actually points to and copies its
   already-correct verdict — before the ref field itself is rewritten to a
   display name.

## Why is each non-obvious expected value correct?

- **Four algorithms, one key, one certificate — six assets from one
  self-signed cert.** `openssl req -x509 -newkey rsa:2048 ...` produces one
  RSA-2048 key pair and one self-signed certificate; `cbomkit-theia`'s
  Certificate File Plugin decomposes that single `.pem` into its constituent
  cryptographic primitives (the key-generation algorithm, the digest
  algorithm, the composite signature algorithm, and the public key material
  itself) plus the certificate wrapper — six rows from one file is the
  engine's own documented behaviour (`repo/certs/server.pem`), not a fixture
  artifact.
- **The certificate's `quantum_vulnerable` is `true`, inherited from
  `SHA256-RSA`.** `openssl req -x509` defaults to a SHA-256-with-RSA
  signature; RSA is Shor-broken (`quantum_family: "rsa"`), so the certificate
  it signs is vulnerable too — see failure mode 2 above.
- **`SHA256` (the digest algorithm) is `grover_note`, never `vulnerable`.**
  It is a hash, not an asymmetric primitive — Grover's algorithm gives a
  quadratic speed-up, not a break, and CLAUDE.md invariant 5's sibling rule
  (Shor breaks; Grover resizes) is exactly what keeps a hash off the
  migration list. `effective_quantum_bits: 128` is `256 // 2`, comfortably
  above the 128-bit quantum-security threshold, so the note says "no action"
  (see `quantum_rules.py:_grover_verdict`).
- **The four RSA-family algorithm rows are NOT deduplicated into one.**
  `cbomkit-theia` reports "RSA" (key generation, `pke`), "RSA" again (public
  key use, distinct `bom-ref`, distinct `cryptoFunctions`), and
  "SHA256-RSA" (the composite signature algorithm) as three separate
  algorithm assets plus one `RSA-2048` key asset — `normalize_all` does not
  merge same-named crypto assets the way the SBOM pipeline merges same-purl
  components, because two same-named crypto assets are not necessarily the
  same asset (a signing key and a key-exchange key can both be called "RSA").
  A wrong implementation collapsing them by name would under-report the
  actual cryptographic surface.
- **`deprecation_reference: "NIST SP 800-131A Rev. 2"` for every RSA-family
  row, and `""` for SHA256.** `assess_deprecation` cites its source only when
  it has a specific, sourced verdict to attach one to (an unsized RSA key's
  "disallowed below 2048 bits" claim); SHA-256's "no known weakness" is a
  default absence-of-finding, not a cited standard, so it correctly carries
  no reference — a wrong implementation inventing a citation for the second
  case would be indistinguishable from a real one without checking this file.
- **`completeness_pct` and `declaration_pct` are both `61.07`.** Every
  field this fixture's assets could carry, they do carry (no user ever typed
  `not-provided` here — the values either came from the engine or genuinely
  do not apply to that asset type), so the two coverage numbers coincide.
  They would diverge the moment a real project's data contained an explicit
  `not-provided` declaration CLAUDE.md invariant 3 requires distinguishing
  from silent absence — this fixture does not exercise that split; see
  `workers/cbom/test_crypto_normalize.py`'s unit tests for that case instead.
- **No `key_size` on the certificate row, no `cert_subject` on the algorithm
  rows.** The type-discrimination invariant (CLAUDE.md 5) through the full
  pipeline, on real engine output rather than a hand-built one.

## What would a wrong implementation produce instead?

- Left `signature_algo_ref`/`subject_public_key_ref` as raw UUIDs (the bug
  this fixture was built to catch).
- Reported the certificate `quantum_vulnerable: false` — the false negative
  that made this fixture worth committing in the first place. A regression
  here is not cosmetic: it is a compliance document asserting an RSA-signed
  certificate needs no quantum migration plan.
- Merged the three RSA-family algorithm rows into one, understating the
  document's cryptographic surface.
- Scored the certificate against `key_size` or the key against `cert_subject`
  (invariant 5's classic failure), inflating or deflating coverage.

## Provenance

- `repo/` — `openssl req -x509 -newkey rsa:2048 -days 365 -nodes` against a
  fresh key (discarded, never committed), plus one Java source file exercising
  `javax.crypto`/`java.security` APIs that `cbomkit-theia` did **not** pick up
  in this run (it disables the Java-source check entirely when no existing
  BOM is supplied as input — an enrichment mode, not a from-scratch scan; see
  its own stderr output). Kept in the fixture anyway as a documented negative
  case: a future engine version or invocation mode that *does* start picking
  up source-level Java crypto API usage should change this fixture's expected
  output, and that diff is itself the signal something upstream changed.
- `raw/cbomkit-theia.json` — pinned output of
  `ghcr.io/cbomkit/cbomkit-theia:1.1.2` (`digest` not pinned in this
  manifest entry per `OSINT/tools.manifest.yaml`'s own note that v1.1.2
  ships no binary assets), run as `cbomkit-theia dir <repo>` with `HOME` set
  to a writable directory (see `workers/cbom/adapters/cbomkit_theia.py`'s
  `extra_env`) so its startup warning does not print to stdout ahead of the
  JSON.
- `expected/crypto_assets.json`, `expected/coverage.json` — generated by
  `workers/cbom/normalize/pipeline.py:build_canonical_cbom` against the
  pinned raw file, hand-reviewed against the reasoning above, with
  `provenance.alias_snapshot_id` (fresh and meaningless for every CBOM call —
  see that function's own docstring) excluded from the pinned expectation.

## Not yet wired

There is no `TestGolden/crypto-mixed` Go test consuming this fixture yet —
the corpus's existing golden-diff harness (`docs/09-GOLDEN-CORPUS.md` §4)
is built for the SBOM pipeline's shape (`components.json`/`findings.json`/
`graph.json`). A CBOM-shaped harness reading `expected/crypto_assets.json`/
`coverage.json` is follow-up work, tracked alongside the rest of Milestone 4
finishing CBOM/QBOM (`docs/STATE.md`). Until then, this fixture is validated
by direct, manual replay (see the session log) — the pinned files are real
and correct, only the automated harness pointing at them is missing.
