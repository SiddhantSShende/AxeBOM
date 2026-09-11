# crypto-mixed

One self-signed certificate and one Java source file, scanned by all three CBOM
engines. Every raw file is real engine output, never hand-built: hand-built
CycloneDX writes readable `bom-ref`s (`"crypto/algorithm/rsa-2048"`), and several
of the bugs below exist only because real engines mint opaque UUIDs.

## What failure mode does this fixture isolate?

1. **Crypto used in source code was invisible.** `repo/src/main/java/com/example/CryptoConfig.java`
   calls JCA five times. `cbomkit-theia` reads files (certificates, keys, crypto
   configuration) and found none of them; from 2026-08-25, when it was committed,
   this fixture pinned that absence as the expected output. `cbomkit-action` reads the source and finds all five, with
   lines: `SSLContext.getInstance("TLSv1.2")` (11),
   `KeyPairGenerator.getInstance("RSA")` + `initialize(2048)` (15),
   `KeyGenerator.getInstance("AES")` + `init(256)` (21),
   `Cipher.getInstance("AES/CBC/PKCS5Padding")` (23), and
   `MessageDigest.getInstance("SHA-256")` (27).
2. **A second engine could only duplicate the first.** Crypto assets had no
   identity: `component_key` held the engine's random per-run `bom-ref`. theia's
   `SHA256` (the certificate's digest) and cbomkit-action's `SHA-256` (line 27) are
   one algorithm. They are now one asset, `algorithm:sha2;digest=sha2-256;primitive=hash`,
   with two locations and one provenance row per engine (03 §1.6).
3. **Coverage was wrong in two ways at once.** The old golden pinned
   `completeness_pct == declaration_pct == 61.07`:
   - list-valued fields (`crypto_functions[]`, the algorithm list, cipher
     suites) scored zero on every CBOM, because the profile's `[]` notation was
     used as a lookup key;
   - `declaration_pct` could never differ from `completeness_pct`, because the
     scorer never saw the fields the writer stored as `not-provided`.
4. **A certificate inherits its signer's verdict.** theia's certificate points at
   its signature algorithm through an opaque UUID. When the certificate was matched
   on that raw reference, it came back `quantum_vulnerable: false`, a false
   negative for an RSA-signed certificate. It is resolved to the signer's
   `asset_key` and the signer's verdict is copied.
5. **A key named for nothing was judged on its name.** cbomkit-action names the
   key from line 15 just `key` and states that it belongs to RSA-2048 only as a
   CycloneDX `dependencies` edge. The edge was never read, so an RSA key was
   reported as not quantum-vulnerable.
6. **cdxgen classifies every `.pem` as a certificate**, private keys included,
   with absolute `/src` paths. Its file findings are dropped and left to theia.

## Why is each non-obvious expected value correct?

**Twelve assets** — seven algorithms, three keys, one certificate, one protocol:

| Asset | `asset_key` (abridged) | Engines, evidence | Why |
|---|---|---|---|
| `AES-128-CBC-PKCS5` | `algorithm:aes;bits=128;mode=cbc;padding=pkcs5;…` | action, `CryptoConfig.java:23` | See the AES-128 bullet below |
| `AES-256` | `algorithm:aes;bits=256;primitive=block-cipher` | action, `:21` | The key generator's algorithm; no mode is stated there |
| `RSA-2048` | `algorithm:rsa;bits=2048;primitive=pke` | action, `:15` | The key-pair generator's algorithm |
| `SHA256-RSA` | `algorithm:rsa;digest=sha2-256;scheme=pkcs1v15;primitive=signature` | theia, `certs/server.pem` | The certificate's signature. `parameterSetIdentifier: 256` is the digest, never a 256-bit modulus |
| `RSA` (pke) | `algorithm:rsa;primitive=pke` | theia, `server.pem` | See the RSA bullet below |
| `RSA` (signature) | `algorithm:rsa;primitive=signature` | theia, `server.pem` | A different use of RSA from the one above, so a different asset |
| `SHA-256` | `algorithm:sha2;digest=sha2-256;primitive=hash` | **both**, `server.pem` + `:27` | Failure mode 2 |
| `example.com` | `cert:example.com;issuer=example.com;from=…;to=…` | theia, `server.pem` | theia 1.1.2 reports no serial or fingerprint, so subject+issuer+validity is the best tier (medium) |
| `RSA-2048` key | `key:fp:sha256:8f3a7d5e…` | theia, `server.pem` | The certificate's public key, keyed by the SHA-256 of its DER. The key bytes are hashed; they are never stored |
| `key` | `key:secret-key;alg=rsa;size=2048;path=…CryptoConfig.java:15` | action, `:15` | Failure mode 5 |
| `secret-key` | `key:secret-key;alg=aes;size=256;path=…:21` | action, `:21` | The generated AES key |
| `TLSv1.2` | `protocol:tls;version=1.2` | action, `:11` | The family is read out of the name, so `TLS` + `1.2` from another engine is the same asset |

- **The bare `RSA` (pke) does NOT merge into `RSA-2048`.** Here theia's RSA really
  is 2048 bits, because the certificate's key says so. But the algorithm asset
  states no modulus, and folding an unsized asset into the only sized one in a
  document is a guess that happens to be right in this case. The two stay apart.
- **`SHA256-RSA`, both bare `RSA` rows and the certificate are `unassessed`, not
  `current`.** No modulus is stated, and NIST SP 800-131A Rev. 2 decides RSA on its
  modulus (2048 bits and above acceptable, below disallowed). The old golden called
  them `current` with that same citation, a verdict the cited source does not
  support without a size. The certificate is still `quantum_vulnerable: true`,
  because RSA is broken by Shor's algorithm at any size.
- **The generated RSA key is `quantum_vulnerable: true`**, with
  `attributes.algorithm_key` = `algorithm:rsa;bits=2048;primitive=pke`. Its
  `name` stays `key`, because that is what the engine said; nothing is invented.
- **Both generated keys have `material_type: secret-key`**, including the RSA key
  pair. That is cbomkit-action's classification, kept as reported. They are keys
  the code generates at runtime, so neither is `private_key_in_source` and there
  is no `CBOM_PRIVATE_KEY_IN_SOURCE`. Only an engine that reads key files may say
  a key is in the source (03 §1.6).
- **AES-128 is the engine's default, not the source's.** `Cipher.getInstance("AES/CBC/PKCS5Padding")`
  states no key size; cbomkit-action reports `AES-128`. Its OID is the engine's
  `2.16.840.1.101.3.4.1`, the AES arc, where the reference table has
  `2.16.840.1.101.3.4.1.2` (aes128-CBC, NIST CSOR). The engine's value is kept and
  the disagreement is recorded as `NORMALIZE_CRYPTO_REFERENCE_CONFLICT` in the
  asset's `analysis_diagnostics`. A reference value never overwrites an engine value.
- **Three classical security levels are derived, and counted.** AES-128 → 128,
  AES-256 → 256 and RSA-2048 → 112 come from NIST SP 800-57 Part 1 Rev. 5 §5.6.1.1
  Table 2 (pp. 54-55). Each asset records the source in `derivations`, and
  `coverage.json` counts it under `derived` and cites it in
  `derivation_sources` (user decision 2026-09-11: derive + count, labelled). No
  level is derived for SHA-256, because a hash's strength depends on its use, or
  for an unsized RSA.
- **`completeness_pct` 72.13, `declaration_pct` 100.0.** Completeness counts
  substantive values only. What the engines did not report stays a gap: no
  algorithm list, a mode only for the cipher, no key id, state or dates, and no
  cipher suites or OID for TLS. Without the three derived values completeness
  would be 70.90. Declaration reaches 100 because the normalizer states every
  field of every asset's type, either with a value or with an explicit
  `not-provided`. That is a representation check, not compliance (invariant 3).
- **`NORMALIZE_CRYPTO_FILE_FINDING_DEFERRED` (info)**: cdxgen reported
  `certs/server.pem` as a certificate. The certificate appears once, from theia.

## What would a wrong implementation produce instead?

- **No source engine or a broken adapter:** six assets, all from `server.pem`,
  and none of lines 11–27.
- **Merge by name, not identity:** the two `RSA` rows collapse into one,
  under-reporting the surface.
- **No merge:** `SHA-256` listed twice, with two verdicts.
- **A raw engine name as the protocol key:** `TLSv1.2` and `TLS 1.2` listed twice.
- **Unresolved references:** the certificate comes back `quantum_vulnerable: false`,
  or its `signature_algo_ref` is a UUID.
- **Dependency edges ignored:** the key on line 15 comes back
  `quantum_vulnerable: false` with `alg` missing from its key.
- **`[]` kept in the scored path, or the scorer blind to `not-provided`:** the
  old 61.07 / 61.07.
- **`parameterSetIdentifier` read as a modulus:** a 256-bit RSA key, `broken`.
- **cdxgen's file findings kept:** a second `server.pem` certificate with an
  absolute path.
- **Key material read:** the public key's base64 `value` in the output.
  `workers/cbom/test_golden.py` checks that no raw `value` reaches the canonical model.

## Provenance

- `repo/certs/server.pem`: `openssl req -x509 -newkey rsa:2048 -days 365 -nodes`
  against a fresh key. The private key was discarded and never committed.
- `repo/src/main/java/com/example/CryptoConfig.java`: hand-written JCA calls.
  The repository has no Python, Go or JavaScript.
- `raw/cbomkit-theia.json` (sha256 `153293d0bee18b9f0ba1dd3e010079ffb15ed43130b28b01c8757da08d8a381e`):
  `ghcr.io/cbomkit/cbomkit-theia:1.1.2`, run as `cbomkit-theia dir <repo>` with
  `HOME` writable (see `workers/cbom/adapters/cbomkit_theia.py`). The manifest pins
  no digest for this image; see `OSINT/tools.manifest.yaml`.
- `raw/cbomkit-action.json` (sha256 `36f81b6cbcc37570e72615ee0544922355ff585f90743a64d0ee734807ae1aa5`):
  `ghcr.io/cbomkit/cbomkit-action:v2.3.0@sha256:47c2505267dc5f055152616ffa0d0076b7d0824fe9e0de670b572d1ebad2fc4b`.
  The un-prefixed `2.3.0` tag is a different image. Captured on 2026-09-11 by the
  engine probe under the sandbox flags (`--network=none`, `--read-only`,
  `--user 65534`, tmpfs workspace, `--cap-drop ALL`), with entrypoint `sh` and
  `-c 'mkdir -p … && java -Xmx3g -XX:-UsePerfData -Djava.io.tmpdir=… -jar /cbomkit-action/CBOMkit-action.jar 1>&2 && cat /workspace/cbom/cbom.json'`,
  env `GITHUB_WORKSPACE=/src CBOMKIT_JAVA_REQUIRE_BUILD=false CBOMKIT_GENERATE_MODULE_CBOMS=false CBOMKIT_OUTPUT_DIR=/workspace/cbom`.
  The probe ran `CBOMKIT_LANGUAGES=java,python,go`; the adapter runs `java,python`
  (04 §5: Go fails silently under the sandbox). Neither difference changes the
  output here, because the repository has no Python or Go.
- `raw/cdxgen-cbom.json` (sha256 `d35bb36d546823a2944a7454a6d9c03dc9f7fcdef5d7a1aea2567d5f1ed77026`):
  `ghcr.io/cdxgen/cdxgen:13.0.1@sha256:0be75639a833b59d1ba29b3c8ac00dfd2e41e7568d56b6c039007caadebebc0d`,
  entrypoint `cbom`, argv `-r /src -o - --spec-version 1.6 --no-banner --no-install-deps`,
  the SBOM adapter's offline env plus `SEARCH_MAVEN_ORG=false`: exactly the
  invocation `workers/cbom/adapters/cdxgen_cbom.py` uses. ⚠ Since 2026-09-11 the
  adapter does not start cdxgen at all on a tree with no JavaScript or
  TypeScript (it hangs on Maven repositories; 04 §5), so a live scan of this
  repository stores no cdxgen artifact. The file stays because it pins the
  extractor's handling of cdxgen's `.pem`-as-certificate finding.
- `expected/crypto_assets.json`, `coverage.json`, `diagnostics.json`: written by
  `python -m workers.cbom.normalize_runner fixtures/crypto-mixed --write-expected`
  at CBOM ruleset `2026.09.1`, then reviewed value by value against this README.
  The runner reads each raw file through the same extractor and pipeline as
  `workers/cbom/normalize_consumer.py`. `workers/cbom/test_golden.py` replays
  them under `task test:golden`.
