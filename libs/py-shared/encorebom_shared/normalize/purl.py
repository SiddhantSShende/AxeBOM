"""PURL canonicalization — the merge key.

⚠ EVERY DEDUP DECISION IN THE PRODUCT RUNS THROUGH THIS MODULE.

Each engine emits PURLs with slightly different conventions. If two engines
describe the same package and this module produces two different strings, that
package is counted twice; if it produces one string for two different packages,
one of them disappears from the report along with its vulnerabilities. The
second failure is worse and quieter.

The rules are per-ecosystem and they genuinely differ — this is the part that a
single `.lower()` gets wrong:

    pypi     PEP 503: lowercase, collapse runs of - _ . into one -
    npm      lowercase; %40scope must be decoded before comparison
    maven    CASE-SENSITIVE. commons-lang3 is not Commons-Lang3
    golang   CASE-PRESERVING, and !x proxy-escaping decodes to X
    nuget    compare case-insensitively, display the original case
    deb/rpm  lowercase name; epoch and arch are part of the identity

See `docs/03-NORMALIZER-SPEC.md` §1.1. This module implements that table and
nothing else; policy decisions live elsewhere.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import quote, unquote

#: Types whose namespace/name compare case-insensitively.
#:
#: The inverse — the case-SENSITIVE set — is the one that matters: lowercasing a
#: Maven groupId or a Go module path silently merges components that are
#: genuinely distinct, producing a component count that is too LOW. A missing
#: component is a missing vulnerability, and nothing in the report says so.
_CASE_INSENSITIVE_TYPES = frozenset(
    {"npm", "pypi", "deb", "rpm", "alpine", "apk", "gem", "cargo", "composer", "hex"}
)

#: Types where the namespace is case-insensitive but the name is not, or the
#: reverse. Kept explicit rather than inferred.
_CASE_SENSITIVE_TYPES = frozenset({"maven", "golang", "github", "bitbucket", "generic"})

#: Qualifiers that are part of WHAT THE COMPONENT IS. Two components differing
#: in any of these are different components.
IDENTITY_QUALIFIERS = frozenset(
    {"arch", "distro", "os", "epoch", "classifier", "type", "channel", "platform"}
)

#: Qualifiers that describe WHERE IT CAME FROM. These are lifted to typed fields
#: and dropped from the key: two engines fetching the same package from
#: different mirrors must not produce two components.
_METADATA_QUALIFIERS = {
    "repository_url": "source_repo",
    "download_url": "download_url",
    "checksum": "hashes",
    "file_name": "file_name",
    "vcs_url": "vcs_url",
}

_PEP503 = re.compile(r"[-_.]+")
_GO_ESCAPE = re.compile(r"![a-z]")


class PurlError(ValueError):
    """A PURL that cannot be parsed.

    Raised rather than returned as a sentinel because the caller must decide
    between the identity fallback chain and a diagnostic — silently substituting
    a made-up key would put a fabricated component in the report.
    """


@dataclass
class Purl:
    """A parsed, canonicalized Package URL."""

    type: str
    name: str
    namespace: str = ""
    version: str = ""
    #: Identity-bearing qualifiers only.
    qualifiers: dict[str, str] = field(default_factory=dict)
    subpath: str = ""

    #: Qualifiers lifted out of the PURL into typed fields. Not part of identity.
    metadata: dict[str, str] = field(default_factory=dict)

    #: The name exactly as the engine emitted it, before normalization. Kept for
    #: display: nuget compares case-insensitively but must still render the
    #: publisher's capitalisation.
    name_display: str = ""

    def canonical(self) -> str:
        """Render the canonical PURL string.

        Qualifiers are sorted so that two engines emitting the same qualifiers
        in different orders produce the same key. Without the sort, dedup
        depends on dictionary iteration order, which is a bug that appears only
        on some inputs.
        """
        out = f"pkg:{self.type}"
        if self.namespace:
            out += "/" + _encode_segment(self.namespace, allow_slash=True)
        out += "/" + _encode_segment(self.name)
        if self.version:
            out += "@" + _encode_segment(self.version)
        if self.qualifiers:
            pairs = "&".join(
                f"{k}={_encode_segment(self.qualifiers[k])}" for k in sorted(self.qualifiers)
            )
            out += "?" + pairs
        if self.subpath:
            out += "#" + _encode_segment(self.subpath, allow_slash=True)
        return out

    @property
    def ecosystem(self) -> str:
        """The ecosystem name used throughout the product.

        `golang` and `go` both appear in the wild — syft emits one, osv-scanner
        the other — and they must not become two ecosystems in the coverage
        table.
        """
        return _ECOSYSTEM_ALIASES.get(self.type, self.type)


#: Engines disagree on the type string for the same ecosystem. Normalizing here
#: rather than at each call site keeps the Engine Coverage table honest: `go`
#: and `golang` as separate rows would imply a gap that does not exist.
_ECOSYSTEM_ALIASES = {
    "go": "golang",
    "apk": "alpine",
    "crates": "cargo",
    "pip": "pypi",
    "python": "pypi",
}


def parse(raw: str) -> Purl:
    """Parse and canonicalize a PURL string.

    Deliberately strict about the `pkg:` scheme — a bare `lodash@4.17.21` is not
    a PURL, and treating it as one would put an unqualified name into the merge
    key where it could collide across ecosystems.
    """
    if not isinstance(raw, str) or not raw.strip():
        raise PurlError("empty purl")

    text = raw.strip()
    if not text.lower().startswith("pkg:"):
        raise PurlError(f"not a purl (no pkg: scheme): {text[:80]!r}")

    text = text[4:].lstrip("/")

    subpath = ""
    if "#" in text:
        text, _, subpath = text.partition("#")
        subpath = _normalize_subpath(unquote(subpath))

    qualifier_text = ""
    if "?" in text:
        text, _, qualifier_text = text.partition("?")

    version = ""
    # ⚠ rpartition, not partition. An npm scope contains no @, but a Maven
    # classifier or a Go pseudo-version can, and splitting on the FIRST @ would
    # cut the name in half.
    if "@" in text:
        text, _, version = text.rpartition("@")
        version = unquote(version)

    parts = [p for p in text.split("/") if p]
    if len(parts) < 2:
        raise PurlError(f"purl has no name: {raw[:80]!r}")

    ptype = parts[0].lower()
    name_raw = unquote(parts[-1])
    namespace_raw = "/".join(unquote(p) for p in parts[1:-1])

    qualifiers, metadata = _split_qualifiers(qualifier_text)

    namespace, name = _apply_ecosystem_rules(ptype, namespace_raw, name_raw)
    version = _canonical_version(_ECOSYSTEM_ALIASES.get(ptype, ptype), version)

    return Purl(
        type=ptype,
        namespace=namespace,
        name=name,
        name_display=name_raw,
        version=version,
        qualifiers=qualifiers,
        metadata=metadata,
        subpath=subpath,
    )


def _canonical_version(ecosystem: str, version: str) -> str:
    """Normalize the SYNTAX of a version, never its value.

    ⚠ THE ONLY RULE HERE IS GO'S `v` PREFIX, AND IT IS SYNTAX.

    Go module versions are canonically `vX.Y.Z`. Engines disagree: one emits
    `v24.0.5+incompatible`, another `24.0.5+incompatible`. They are the same
    published module version — the `v` is part of Go's version grammar, not part
    of the number — so leaving them unnormalized splits one component into two
    and double-counts it along with all of its vulnerabilities.

    This is canonicalization in the same sense as PEP 503 lowercasing, NOT a
    merge across different versions. `version_raw` is still stored verbatim; the
    normalization applies to the comparison key only.
    """
    if not version:
        return version

    if ecosystem == "golang" and not version.startswith("v"):
        # Only when what follows actually looks like a version number. A
        # pseudo-version or a commit sha must not acquire a prefix it never had.
        if version[0].isdigit():
            return "v" + version

    return version


def canonicalize(raw: str) -> str:
    """Parse and re-render. The common case."""
    return parse(raw).canonical()


def _apply_ecosystem_rules(ptype: str, namespace: str, name: str) -> tuple[str, str]:
    """The per-ecosystem name table from the spec.

    Every branch here corresponds to a real published rule, not a preference.
    """
    ecosystem = _ECOSYSTEM_ALIASES.get(ptype, ptype)

    if ecosystem == "pypi":
        # PEP 503. `zope.interface`, `zope_interface` and `Zope-Interface` are
        # ONE project — the dot is a separator, not part of the name.
        return _pep503(namespace), _pep503(name)

    if ecosystem == "npm":
        # The scope arrives percent-encoded from some engines (%40types/node)
        # and bare from others (@types/node). unquote() in parse() already
        # decoded it; lowercasing completes the comparison.
        return namespace.lower(), name.lower()

    if ecosystem == "maven":
        # ⚠ CASE-PRESERVING. Maven coordinates are case-sensitive: lowercasing
        # merges genuinely distinct artifacts and under-reports.
        return namespace, name

    if ecosystem == "golang":
        # ⚠ CASE-PRESERVING, plus proxy escaping. The module proxy encodes an
        # uppercase letter as !x, so github.com/!masterminds/semver IS
        # github.com/Masterminds/semver. Decoding it wrong yields a module that
        # does not exist.
        return _decode_go_escape(namespace), _decode_go_escape(name)

    if ecosystem == "nuget":
        # Compared case-insensitively; `name_display` keeps the original for
        # rendering.
        return namespace.lower(), name.lower()

    if ecosystem in _CASE_INSENSITIVE_TYPES:
        return namespace.lower(), name.lower()

    if ecosystem in _CASE_SENSITIVE_TYPES:
        return namespace, name

    # Unknown ecosystem: preserve case. Preserving is the conservative
    # direction — it can leave a duplicate (visible, countable, fixable) where
    # lowercasing could merge two real components (invisible).
    return namespace, name


def _pep503(value: str) -> str:
    """PEP 503 normalization: lowercase, collapse -_. runs into a single -."""
    if not value:
        return ""
    return _PEP503.sub("-", value).lower()


def _decode_go_escape(value: str) -> str:
    """Decode Go module-proxy escaping: `!m` → `M`."""
    if not value:
        return ""
    return _GO_ESCAPE.sub(lambda m: m.group(0)[1].upper(), value)


def _split_qualifiers(text: str) -> tuple[dict[str, str], dict[str, str]]:
    """Separate identity-bearing qualifiers from provenance metadata.

    ⚠ Getting this backwards inflates counts. `repository_url` differs between
    a package fetched from npmjs and the same package from an internal mirror;
    keeping it in the key makes those two components.

    Conversely `arch` and `epoch` genuinely distinguish packages: an x86_64 and
    an aarch64 build of the same rpm are different artifacts with different
    hashes.
    """
    identity: dict[str, str] = {}
    metadata: dict[str, str] = {}

    for pair in text.split("&"):
        if not pair or "=" not in pair:
            continue
        key, _, value = pair.partition("=")
        key = key.strip().lower()
        value = unquote(value.strip())
        if not key or not value:
            # An empty qualifier value is equivalent to the qualifier being
            # absent, per purl-spec. Keeping it would make `?arch=` and no arch
            # at all into two different keys.
            continue

        if key in _METADATA_QUALIFIERS:
            metadata[_METADATA_QUALIFIERS[key]] = value
        elif key in IDENTITY_QUALIFIERS:
            identity[key] = value
        else:
            # Unknown qualifiers are treated as metadata, not identity.
            #
            # This is the safe direction: an unknown qualifier kept in the key
            # would split one component into several as soon as an engine
            # started emitting a new annotation. Splitting is the failure that
            # inflates counts, and a new qualifier appearing is far more likely
            # than a new identity dimension.
            metadata[key] = value

    return identity, metadata


def _normalize_subpath(value: str) -> str:
    """Normalize a subpath: no leading/trailing slash, no . or .. segments."""
    segments = []
    for segment in value.split("/"):
        if not segment or segment == ".":
            continue
        if segment == "..":
            # Refused rather than resolved: a subpath is a location inside an
            # archive, and `..` there is either meaningless or an attempt to
            # escape it. See the zip-slip defence in the fetcher.
            continue
        segments.append(segment)
    return "/".join(segments)


def _encode_segment(value: str, *, allow_slash: bool = False) -> str:
    """Percent-encode one PURL segment consistently.

    Consistency matters more than the exact character set: the canonical string
    is a comparison key, so two inputs that mean the same thing must encode
    identically.
    """
    safe = "-._~!$&'()*+,;=:@"
    if allow_slash:
        safe += "/"
    return quote(value, safe=safe)


def version_is_identity_bearing(a: str, b: str) -> bool:
    """Whether two raw versions may be treated as the same component.

    ⚠ NEVER MERGE COMPONENTS WHOSE `version_raw` DIFFERS — including when they
    normalize to the same thing. `v24.0.5+incompatible` and `24.0.5` normalize
    alike and are not the same published artifact; one of them does not exist.
    Normalized versions are for display and ordering only.
    """
    return a == b
