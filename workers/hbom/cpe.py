"""Building a CPE from what a hardware component actually states.

⚠ EVERY CPE THIS MODULE PRODUCES IS A GUESS, AND THE POINT IS TO MAKE THE GUESS
LEGIBLE RATHER THAN TO HIDE IT.

An SBOM finding is keyed on a purl the ecosystem itself minted: `pkg:npm/lodash
@4.17.21` is not an inference, it is the package's own name. A hardware
component has no such thing. It has a manufacturer string a person typed and a
model number off a datasheet, and NVD has its own vendor and product vocabulary
that was never reconciled with either. "STMicroelectronics", "ST
Microelectronics" and "stmicroelectronics" are one company and three CPE
vendors.

So this module:

  - normalizes both halves the way the CPE spec's own binding rules do,
  - emits SEVERAL candidates rather than one, because the vendor half is the
    unreliable half and a product-only search still finds real CVEs,
  - labels each with the basis it was built on, so a reader can see that a
    `vendor+product` hit is weaker evidence than a `vendor+product+version` one,
  - and returns NOTHING when the component states too little, rather than
    inventing a wildcard that matches half of NVD.

⚠ IT NEVER GUESSES A VENDOR FROM A PRODUCT NAME, and that restraint is the
whole difference between an advisory and a fabrication. `RC0402FR-0710KL` is a
Yageo part number; a matcher that inferred "yageo" from the prefix would be
right often enough to be trusted and wrong often enough to matter.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

#: Characters CPE 2.3 requires escaped inside a component value.
_SPECIAL = re.compile(r"([\\*?!\"#$%&'()+,/:;<=>@\[\]^`{|}~])")

#: Anything that is not alphanumeric, dot, hyphen or underscore becomes an
#: underscore, which is the CPE convention for a space.
_SEPARATORS = re.compile(r"[\s]+")
_DISALLOWED = re.compile(r"[^a-z0-9._\-]")

#: LEGAL-FORM suffixes only. Stripped so "Yageo Corporation" and "Yageo"
#: produce one candidate rather than searching twice and matching once.
#:
#: ⚠ THIS LIST ONCE CONTAINED "microelectronics", "semiconductor",
#: "electronics" AND "technologies", AND THE FIRST TEST RUN CAUGHT IT:
#: "ST Microelectronics" folded to `st`, which is not a CPE vendor and matches
#: nothing. Those words are DESCRIPTIVE, not legal forms, and they belong to
#: the distinguishing name far more often than they are noise — STMicro-
#: electronics, Vishay Semiconductor, Murata Electronics, Cypress Semiconductor.
#:
#: The rule that survives: strip only what names a company's INCORPORATION,
#: never what names the company. If a suffix could plausibly be the memorable
#: half of a firm's name, it does not belong in this tuple.
_CORPORATE_SUFFIXES = (
    "inc",
    "inc.",
    "incorporated",
    "corp",
    "corp.",
    "corporation",
    "co",
    "co.",
    "company",
    "ltd",
    "ltd.",
    "limited",
    "llc",
    "llc.",
    "gmbh",
    "ag",
    "sa",
    "s.a.",
    "nv",
    "n.v.",
    "bv",
    "b.v.",
    "plc",
    "pvt",
    "pvt.",
    "private",
    "kk",
    "k.k.",
    "oy",
    "ab",
    "as",
    "asa",
    "a/s",
    "spa",
    "s.p.a.",
)

#: How many candidates one component may produce. A component that generated
#: dozens would turn one parts list into thousands of lookups.
MAX_CANDIDATES = 4


@dataclass(frozen=True)
class Candidate:
    """One CPE to search with, and how much it is worth."""

    cpe23: str
    #: vendor+product+version | vendor+product | firmware-version
    basis: str
    #: high | medium | low. Mirrors the column's CHECK.
    confidence: str


def normalize_value(raw: str) -> str:
    """Fold a free-text value into a CPE component value.

    Lower-cased, spaces to underscores, CPE special characters escaped. Returns
    "" when nothing usable survives — which is a real answer, not a failure.
    """
    text = raw.strip().lower()
    if not text:
        return ""
    text = _SEPARATORS.sub("_", text)
    text = _DISALLOWED.sub("_", text)
    text = re.sub(r"_+", "_", text).strip("_")
    return _SPECIAL.sub(r"\\\1", text)


def normalize_vendor(raw: str) -> str:
    """Fold a manufacturer name into a CPE vendor.

    ⚠ CORPORATE SUFFIXES ARE STRIPPED, THE DISTINGUISHING WORD NEVER IS.
    "Yageo Corporation" and "Yageo" must produce one candidate, or the same
    part sourced from two spreadsheets searches twice and matches once.
    """
    text = raw.strip().lower()
    if not text:
        return ""
    tokens = [t for t in re.split(r"[\s,]+", text) if t]
    while len(tokens) > 1 and tokens[-1].strip(".") in {s.strip(".") for s in _CORPORATE_SUFFIXES}:
        tokens.pop()
    return normalize_value(" ".join(tokens))


def candidates(
    *,
    manufacturer: str,
    model_number: str,
    product_name: str = "",
    version: str = "",
    firmware_version: str = "",
) -> list[Candidate]:
    """Every CPE worth searching for one component, best evidence first.

    ⚠ RETURNS AN EMPTY LIST RATHER THAN A WILDCARD when there is no product to
    search on. `cpe:2.3:h:yageo:*:*:...` matches every Yageo part ever
    published; reporting those against one resistor would bury a real finding
    under a hundred irrelevant ones, which is worse than reporting none.

    ⚠ `h` FOR HARDWARE, NOT `a`. The CPE part attribute distinguishes hardware
    from application, and searching the wrong one silently misses every entry.
    Firmware is the exception — NVD files firmware under `o` (operating system)
    far more often than `h`, so a firmware candidate searches that instead.
    """
    vendor = normalize_vendor(manufacturer)
    product = normalize_value(model_number) or normalize_value(product_name)

    out: list[Candidate] = []
    if product:
        version_value = normalize_value(version)
        if vendor and version_value:
            out.append(
                Candidate(
                    _cpe("h", vendor, product, version_value),
                    "vendor+product+version",
                    # ⚠ STILL NOT "high". All three parts agreeing makes this
                    # the best evidence available for hardware, and it is still
                    # a string match against a vocabulary nobody reconciled.
                    "medium",
                )
            )
        if vendor:
            out.append(Candidate(_cpe("h", vendor, product, "*"), "vendor+product", "low"))
        else:
            # ⚠ A PRODUCT-ONLY SEARCH, WITH THE VENDOR WILDCARDED, IS STILL
            # WORTH RUNNING. A part number like STM32H753ZI is distinctive
            # enough to find real entries, and refusing to look because the
            # spreadsheet omitted a manufacturer would lose findings over a
            # missing column. It is `low` because a short or generic product
            # value can collide across vendors.
            out.append(Candidate(_cpe("h", "*", product, "*"), "vendor+product", "low"))

    firmware = normalize_value(firmware_version)
    if firmware and (vendor or product):
        out.append(
            Candidate(
                _cpe("o", vendor or "*", product or "*", firmware),
                "firmware-version",
                "low",
            )
        )

    # Deduplicate while preserving the best-evidence-first order.
    seen: set[str] = set()
    unique: list[Candidate] = []
    for candidate in out:
        if candidate.cpe23 in seen:
            continue
        seen.add(candidate.cpe23)
        unique.append(candidate)
    return unique[:MAX_CANDIDATES]


def _cpe(part: str, vendor: str, product: str, version: str) -> str:
    """A CPE 2.3 formatted string with every remaining attribute wildcarded."""
    return f"cpe:2.3:{part}:{vendor}:{product}:{version}:*:*:*:*:*:*:*"
