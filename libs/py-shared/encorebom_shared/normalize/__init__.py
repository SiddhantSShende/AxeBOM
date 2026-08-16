"""Normalization: raw engine output to the canonical model.

⚠ THIS PACKAGE PRODUCES EVERY NUMBER A CUSTOMER SEES.

Component counts, vulnerability counts, coverage percentages, the
direct-vs-transitive split. A bug here does not crash anything — it quietly
reports 240 vulnerabilities where there are 80, or 94% coverage where it is 61%.

⚠ NORMALIZATION IS A DETERMINISTIC PURE FUNCTION of
*(raw artifacts + ruleset version + alias snapshot)*.

No wall-clock reads, no randomness, no network calls anywhere in this package.
A function that needs the current time takes it as an argument. This is what
makes a report defensible six months later, makes a dedup fix retroactive across
all history, and turns a future CERT-In revision into a data change plus a
re-normalization pass (ADR-0003).

Collections are sorted before serializing. Golden tests that flap get ignored,
which is worse than not having them.

See `docs/03-NORMALIZER-SPEC.md`.
"""

#: Bumped whenever a rule change alters output for unchanged input.
#:
#: Recorded on every `bom_document` so a report states which rules produced it,
#: and so `renormalize` can replay stored artifacts into a new version without
#: touching the old one.
RULESET_VERSION = "2026.08.1"
