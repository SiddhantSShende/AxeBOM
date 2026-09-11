"""The canonical identity of a cryptographic algorithm, parsed from what engines report.

⚠ ONE PARSER, SEVERAL READERS. The reference table (reference.py) must know that
`SHA256withRSA` (JCA), `sha256WithRSAEncryption` (X.509) and cbomkit-theia's
`SHA256-RSA` are one algorithm; the crypto-asset identity key (03 §1.6) needs the
same fact to merge two engines' reports of it. Two parsers would disagree on the
first name only one of them knew.

⚠ UNKNOWN STAYS UNKNOWN. A property this cannot establish is left empty, never
filled with a plausible default. An empty key size is how reference.py knows NOT
to derive a security level; a guessed one would put a confident wrong number into
a compliance document.

⚠ `parameterSetIdentifier` MEANS DIFFERENT THINGS FOR DIFFERENT FAMILIES, and the
CycloneDX spec says so: the key length for AES128, the digest length for SHA256,
the security level for SHAKE128, a named set for SLH-DSA. cbomkit-theia reports
`SHA256-RSA` with `parameterSetIdentifier: "256"` — the digest. Reading that as an
RSA modulus would report a 256-bit RSA key, i.e. "broken", on every certificate.
So the parameter set is interpreted per family, below, and nowhere else.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from ._text import search_text
from .quantum_rules import pqc_family


@dataclass(frozen=True)
class Canonical:
    """What an engine's name + fields establish about one algorithm."""

    #: e.g. `aes`, `rsa`, `ecdsa`, `sha2`, `ml-kem`. Empty = not recognised.
    family: str = ""
    #: Key, modulus or group size in bits — only where the number means that.
    bits: int | None = None
    #: Hash output length in bits: the hash itself, or the hash inside an HMAC,
    #: a KDF or a hash-and-sign algorithm.
    digest: int | None = None
    #: `sha1`, `sha2`, `sha3`, `shake`, `md5` — the family of `digest`.
    digest_family: str = ""
    #: `pss`, `oaep`, `pkcs1v15`, `poly1305`, `sha512/256`, `argon2id`, ...
    scheme: str = ""
    #: Block-cipher mode only: ecb, cbc, ofb, cfb, ctr, gcm, ccm, xts, kw, ...
    mode: str = ""
    #: Normalised padding: pkcs5, pkcs7, pkcs1v15, oaep, none.
    padding: str = ""
    #: Canonical curve: p-192 … p-521, secp256k1, brainpoolp256r1, x25519, ed25519, …
    curve: str = ""
    #: Post-quantum parameter set: 512/768/1024, 44/65/87, sha2-128s, …
    parameter: str = ""
    #: The engine's primitive, lower-cased (signature, pke, hash, ae, …).
    primitive: str = ""

    @property
    def recognised(self) -> bool:
        return bool(self.family)


_CURVES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("p-192", re.compile(r"\bp-?192\b|\bsecp192r1\b|\bprime192v1\b|\bnistp192\b")),
    ("p-224", re.compile(r"\bp-?224\b|\bsecp224r1\b|\bnistp224\b")),
    ("p-256", re.compile(r"\bp-?256\b|\bsecp256r1\b|\bprime256v1\b|\bnistp256\b")),
    ("p-384", re.compile(r"\bp-?384\b|\bsecp384r1\b|\bnistp384\b")),
    ("p-521", re.compile(r"\bp-?521\b|\bsecp521r1\b|\bnistp521\b")),
    ("secp256k1", re.compile(r"\bsecp256k1\b")),
    ("brainpoolp256r1", re.compile(r"\bbrainpoolp256r1\b")),
    ("brainpoolp384r1", re.compile(r"\bbrainpoolp384r1\b")),
    ("brainpoolp512r1", re.compile(r"\bbrainpoolp512r1\b")),
    ("x25519", re.compile(r"\bx25519\b|\bcurve25519\b")),
    ("x448", re.compile(r"\bx448\b|\bcurve448\b")),
    ("ed25519", re.compile(r"\bed25519\b")),
    ("ed448", re.compile(r"\bed448\b")),
)

_SHAKE = re.compile(r"\bshake-?(128|256)\b")
_SHA3 = re.compile(r"\bsha-?3-?(224|256|384|512)\b")
_SHA512_T = re.compile(r"\bsha-?512/(224|256)\b")
#: No trailing \b: `sha256` is followed by `with` in `sha256WithRSA`. The
#: lookahead only refuses a longer number (`sha2560` is not a thing we accept).
_SHA2 = re.compile(r"\bsha-?(224|256|384|512)(?![0-9])")
_SHA1 = re.compile(r"\bsha-?1(?![0-9])")
_MD5 = re.compile(r"\bmd5(?![0-9])")

_MODE = re.compile(r"[-/\s](ecb|cbc|ofb|cfb(?:8|64|128)?|ctr|gcm|ccm|xts|siv|kwp|kw)(?![a-z0-9])")
_PADDING = re.compile(r"(nopadding|pkcs5padding|pkcs7padding|pkcs1padding|oaep|pkcs1v15)")

_AES_BITS = frozenset({128, 192, 256})


def canonicalize(
    name: str,
    primitive: str = "",
    *,
    mode: str = "",
    padding: str = "",
    curve: str = "",
    parameter_set: str = "",
    key_size: int | None = None,
) -> Canonical:
    """Parse one algorithm. Returns an unrecognised `Canonical()` rather than guessing."""
    # Raw AND tokenized forms (see _text.search_text), lower-cased, with `_`
    # read as `-` so `AES_256_GCM` and `ECDH_P256` get the boundaries the
    # patterns assume.
    text = search_text(name, primitive, curve).lower().replace("_", "-")
    param = str(parameter_set or "").strip().lower()
    prim = str(primitive or "").strip().lower()
    if not text and not param:
        return Canonical()

    field_mode = str(mode or "").strip().lower()
    field_padding = _normalise_padding(str(padding or ""))

    # --- post-quantum first: `ML-DSA` must never be read as DSA -----------
    family = pqc_family(name, primitive, param)
    if family is not None:
        return Canonical(
            family=family, parameter=_pqc_parameter(family, f"{text} {param}"), primitive=prim
        )

    digest_family, digest, sha_scheme = _digest(f"{text} {param}")

    # ⚠ KDFs BEFORE HMAC: `PBKDF2WithHmacSHA256` names its PRF, and read the
    # other way round the KDF was reported as a bare HMAC.
    kdf = _kdf(text)
    if kdf:
        family_name, scheme = kdf
        return Canonical(
            family=family_name,
            scheme=scheme,
            digest=digest,
            digest_family=digest_family,
            primitive=prim,
        )

    if re.search(r"\bhmac", text):
        return Canonical(family="hmac", digest=digest, digest_family=digest_family, primitive=prim)

    found_curve = _curve(f"{text} {param}")

    # --- asymmetric --------------------------------------------------------
    if re.search(r"\brsa|rsaencryption|\bpkcs#?1\b", text):
        scheme = ""
        if re.search(r"\bpss\b|rsassa-?pss", text):
            scheme = "pss"
        elif re.search(r"oaep", text) or field_padding == "oaep":
            scheme = "oaep"
        elif (
            re.search(r"pkcs1padding|pkcs1v15|\bpkcs#?1[ -]?v?1\.5\b", text)
            or field_padding == "pkcs1v15"
        ):
            scheme = "pkcs1v15"
        bits = _size(r"rsa-?\s?(\d{3,5})", text)
        if bits is None and digest is None:
            # With a digest present the parameter set is the DIGEST (theia's
            # `SHA256-RSA` / `256`) and must never become a modulus.
            bits = _modulus(param)
        if bits is None and _plausible_modulus(key_size):
            bits = key_size
        return Canonical(
            family="rsa",
            bits=bits,
            digest=digest,
            digest_family=digest_family,
            scheme=scheme,
            padding=field_padding or _normalise_padding(_first(_PADDING, text)),
            primitive=prim,
        )

    if re.search(r"\beddsa\b|\bed25519\b|\bed448\b", text):
        return Canonical(
            family="eddsa",
            curve=found_curve if found_curve in {"ed25519", "ed448"} else "",
            primitive=prim,
        )
    if re.search(r"\bx25519\b|\bx448\b|\bcurve25519\b|\bcurve448\b", text):
        return Canonical(family="xdh", curve=found_curve, primitive=prim)
    if re.search(r"\becdsa", text):
        return Canonical(
            family="ecdsa",
            curve=found_curve,
            digest=digest,
            digest_family=digest_family,
            primitive=prim,
        )
    if re.search(r"\becdh|\becies|\becmqv", text):
        return Canonical(family="ecdh", curve=found_curve, primitive=prim)

    if re.search(r"\bdiffie-?\s?hellman\b|\bdhe?\b(?![a-z])|\bmodp|\bffdhe", text):
        group = _first(re.compile(r"\b(ffdhe\d{4,5})\b"), text)
        bits = _size(r"(?:ffdhe|modp|\bdh)-?\s?(\d{3,5})", text) or _modulus(param)
        if bits is None and _plausible_modulus(key_size):
            bits = key_size
        return Canonical(family="dh", bits=bits, scheme=group, primitive=prim)

    if re.search(r"\bdsa\b(?![a-z])", text):
        bits = _size(r"\bdsa-?\s?(\d{3,5})", text) or (None if digest else _modulus(param))
        return Canonical(
            family="dsa", bits=bits, digest=digest, digest_family=digest_family, primitive=prim
        )

    if found_curve:
        # A bare curve name with no algorithm: elliptic-curve, use unknown.
        return Canonical(family="ec", curve=found_curve, primitive=prim)

    # --- symmetric ---------------------------------------------------------
    block_mode = field_mode or _first(_MODE, text)
    block_padding = field_padding or _normalise_padding(_first(_PADDING, text))

    if re.search(r"\baes", text):
        bits = _size(r"\baes-?\s?(128|192|256)(?![0-9])", text)
        if bits is None and param.isdigit() and int(param) in _AES_BITS:
            bits = int(param)
        if bits is None and key_size in _AES_BITS:
            bits = key_size
        if re.search(r"aeswrap|aes-?kw\b|keywrap", text) and not block_mode:
            block_mode = "kw"
        return Canonical(
            family="aes", bits=bits, mode=_mode(block_mode), padding=block_padding, primitive=prim
        )

    if re.search(r"\bchacha20?", text):
        return Canonical(
            family="chacha20",
            bits=256,
            scheme="poly1305" if "poly1305" in text else "",
            primitive=prim,
        )

    if re.search(r"\b3des\b|\btriple-?\s?des\b|\bdes-?ede3?\b|\bdesede\b|\b3?tdea\b", text):
        # Only the three-key option has a single, citable strength; `DESede`
        # alone does not say which option it is.
        three_key = bool(re.search(r"\bdes-?ede3\b|\b3tdea\b", text)) or key_size in {168, 192}
        return Canonical(
            family="3des",
            bits=168 if three_key else None,
            mode=_mode(block_mode),
            padding=block_padding,
            primitive=prim,
        )
    if re.search(r"\bdes\b", text):
        return Canonical(
            family="des", bits=56, mode=_mode(block_mode), padding=block_padding, primitive=prim
        )

    for symmetric in (
        "camellia",
        "aria",
        "sm4",
        "seed",
        "idea",
        "blowfish",
        "rc2",
        "rc4",
        "arcfour",
    ):
        if re.search(rf"\b{symmetric}", text):
            family_name = "rc4" if symmetric == "arcfour" else symmetric
            bits = _size(rf"\b{symmetric}-?\s?(128|192|256)(?![0-9])", text)
            return Canonical(
                family=family_name,
                bits=bits,
                mode=_mode(block_mode),
                padding=block_padding,
                primitive=prim,
            )

    # --- hashes ------------------------------------------------------------
    if digest_family:
        return Canonical(
            family=digest_family,
            digest=digest,
            digest_family=digest_family,
            scheme=sha_scheme,
            primitive=prim,
        )
    if re.search(r"\bmd4\b|\bmd2\b", text):
        return Canonical(family="md4" if "md4" in text else "md2", primitive=prim)
    if re.search(r"\bripemd-?160\b", text):
        return Canonical(family="ripemd160", digest=160, primitive=prim)
    if re.search(r"\bblake2|\bblake3\b", text):
        return Canonical(family="blake3" if "blake3" in text else "blake2", primitive=prim)

    return Canonical(primitive=prim)


def _digest(text: str) -> tuple[str, int | None, str]:
    """(digest family, digest bits, scheme) for the first hash named in `text`."""
    if match := _SHAKE.search(text):
        return "shake", int(match.group(1)), ""
    if match := _SHA3.search(text):
        return "sha3", int(match.group(1)), ""
    if match := _SHA512_T.search(text):
        return "sha2", int(match.group(1)), f"sha512/{match.group(1)}"
    if match := _SHA2.search(text):
        return "sha2", int(match.group(1)), ""
    if _SHA1.search(text):
        return "sha1", 160, ""
    if _MD5.search(text):
        return "md5", 128, ""
    return "", None, ""


def _kdf(text: str) -> tuple[str, str] | None:
    if re.search(r"\bpbkdf2", text):
        return "pbkdf2", ""
    if match := re.search(r"\bargon2(id|i|d)?\b", text):
        return "argon2", f"argon2{match.group(1) or ''}"
    for kdf in ("bcrypt", "scrypt", "hkdf"):
        if re.search(rf"\b{kdf}\b", text):
            return kdf, ""
    return None


def _curve(text: str) -> str:
    for canonical, pattern in _CURVES:
        if pattern.search(text):
            return canonical
    return ""


def _pqc_parameter(family: str, text: str) -> str:
    patterns = {
        "ml-kem": r"(?:ml-?kem|kyber)[-\s]?(512|768|1024)\b",
        "ml-dsa": r"ml-?dsa[-\s]?(44|65|87)\b",
        "slh-dsa": r"slh-?dsa[-\s]?((?:sha2|shake)-?(?:128|192|256)[sf])\b",
        "falcon": r"(?:falcon|fn-?dsa)[-\s]?(512|1024)\b",
        "hqc": r"hqc[-\s]?(128|192|256)\b",
    }
    pattern = patterns.get(family)
    if pattern and (match := re.search(pattern, text)):
        return match.group(1)
    if family == "ml-dsa" and (match := re.search(r"\bdilithium[-\s]?([235])\b", text)):
        # Round-3 Dilithium levels 2/3/5 became ML-DSA-44/65/87 (FIPS 204).
        return {"2": "44", "3": "65", "5": "87"}[match.group(1)]
    return ""


def _normalise_padding(value: str) -> str:
    text = value.strip().lower().replace("-", "").replace("_", "").replace(" ", "")
    if not text:
        return ""
    if text in {"nopadding", "none"}:
        return "none"
    if text.startswith("pkcs5"):
        return "pkcs5"
    if text.startswith("pkcs7"):
        return "pkcs7"
    if text in {"pkcs1padding", "pkcs1v15", "pkcs1v1.5", "pkcs1"}:
        return "pkcs1v15"
    if text.startswith("oaep"):
        return "oaep"
    return text


def _mode(value: str) -> str:
    return "cfb" if value == "cfb128" else value


def _first(pattern: re.Pattern[str], text: str) -> str:
    match = pattern.search(text)
    return match.group(1) if match else ""


def _size(pattern: str, text: str) -> int | None:
    match = re.search(pattern, text)
    return int(match.group(1)) if match else None


def _modulus(param: str) -> int | None:
    """A parameter set read as a modulus/group size only when it looks like one."""
    return int(param) if param.isdigit() and 512 <= int(param) <= 16384 else None


def _plausible_modulus(value: int | None) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and 512 <= value <= 16384
