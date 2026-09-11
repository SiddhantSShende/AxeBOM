# crypto-quantum

Crypto calls in three languages whose verdicts differ: broken, weak, deprecated,
current, and post-quantum. The source is JCA, pyca/cryptography and node:crypto.
Every raw file is real output from the three CBOM engines, run as their adapters
run them. None of it is hand-built.

## What failure mode does this fixture isolate?

**The verdicts.** crypto-mixed proves discovery and identity. This fixture
proves that each asset gets the right classical verdict, the right quantum flag
and the right migration advice, and that each of those cites its source. A wrong
answer here does not crash anything. It shows up as a migration list with the
wrong algorithms on it.

Building the fixture found three wrong answers. Each was fixed with a unit test
before the expected output was pinned:

1. **Signature schemes were told to migrate to ML-KEM.** `recommend_pqc`
   counted the `keygen` function as key establishment. cbomkit-action reports
   every key-pair generator as `keygen`, so Ed25519 and DSA (both signature
   schemes) got "Replace key establishment with ML-KEM". Generating a key is
   not a use. The engine's primitive, or a single-purpose name, now decides it:
   `signature` → ML-DSA; `kem`, `key-agree` or `pke` → ML-KEM
   (`libs/py-shared/axebom_shared/crypto/pqc.py`).
2. **An elliptic-curve key was reported NOT quantum-vulnerable.**
   `KeyPairGenerator.getInstance("EC")` reaches the rules named just `EC`, and no
   rule matched that name. The algorithm on line 23 and the key generated there
   both came back `quantum_vulnerable: false`. A name or primitive that *is* `EC`
   now reads as elliptic-curve. It is matched only as a whole field, because `ec`
   is two hex digits and a bom-ref UUID must never read as a curve. Its classical
   verdict is `unassessed`, because the curve decides it
   (`quantum_rules.is_bare_ec`).
3. **A reported key size never reached the Grover rule.** pyca's
   `Cipher(algorithms.AES(key), modes.ECB())` comes back as `AES-ECB` with
   `parameterSetIdentifier: 128`. The asset key and the derived security level
   both used the 128, but the Grover note said "no key size was reported". An
   algorithm with no size field now takes its size from the canonicalizer, the
   same per-family reader the identity uses (`workers/cbom/normalize/crypto.py`).

None of these fixes changes `fixtures/crypto-mixed/expected/`. That was checked
by replaying it.

## Why is each non-obvious expected value correct?

### The verdict table

Every row below is one `crypto_assets` entry. Its lines are the call sites the
engine reported; each one is checked against the source.

| Asset (engine name) | Where | Classical verdict | Cited by the rule | Quantum | Migration advice |
|---|---|---|---|---|---|
| `AES-128-ECB-PKCS5` / `AES-ECB` | Java 11, Python 9 | **broken** | NIST SP 800-38A (ECB maps equal plaintext blocks to equal ciphertext blocks; the cipher is irrelevant) | Grover: 128-bit key → ~64 bits | none (Grover only) |
| `MD5` | Java 12, Python 10, JS 4 | **broken** | RFC 6151 | Grover note defers to the classical verdict | none |
| `SHA-1` | Java 13, Python 11, JS 5 | **broken** | NIST SP 800-131A Rev. 2 (collisions demonstrated, SHAttered 2017) | as MD5 | none |
| `3DES-CBC` ×2 | Java 14 (`PKCS5`), Python 12 | **weak** | NIST SP 800-131A Rev. 2 (three-key TDEA encryption disallowed after 2023; 64-bit block, Sweet32) | as MD5 | none |
| `RSA-1024` | Java 16–17, Python 13 | **weak** | NIST SP 800-131A Rev. 2 (below 2048 bits disallowed) | **vulnerable** (Shor) | ML-KEM: the engine says `pke` |
| `DSA-2048` | Java 27–28 | **deprecated** | FIPS 186-5 (withdrawn for new signatures; verification only) | **vulnerable** | **ML-DSA** (fix 1) |
| `Ed25519` | Java 20, Python 14 | current | RFC 8032 / RFC 7748 | **vulnerable** | **ML-DSA** (fix 1) |
| `x25519` | Python 15 | current | RFC 8032 / RFC 7748 | **vulnerable** | ML-KEM (`key-agree`) |
| `EC-secp256r1` | Java 24 | current | (curves of 224 bits and more) | **vulnerable** | ML-KEM: the engine says `pke` |
| `EC` | Java 23 | **unassessed**: no curve | NIST SP 800-131A Rev. 2 (below 224 bits disallowed) | **vulnerable** (fix 2) | ML-KEM (`pke`) |
| `rsa` (cdxgen) | JS 6 | **unassessed**: no size | NIST SP 800-131A Rev. 2 | **vulnerable** | "ML-KEM or ML-DSA": use unknown |
| `ML-KEM-768` | Java 32 | current | FIPS 203 | not vulnerable, `post_quantum` | none |
| `ML-DSA-65` | Java 34 | current | FIPS 204 | not vulnerable, `post_quantum` | none |
| `SHA-512` | Java 20, Python 14 | current | none: no finding means no citation | Grover: 512-bit digest → ~256 bits | none |

- **`weak` and `broken` name different problems.** `broken` means a practical
  attack exists: ECB leaks structure, and MD5 and SHA-1 have demonstrated
  collisions. `weak` means below NIST's security floor and disallowed, with no
  practical public break. Both mean "migrate", and the rationale says which.
- **Post-quantum is checked before the DSA rule.** Otherwise the `-DSA` in
  `ML-DSA-65` fires the legacy DSA rule and reports the replacement algorithm as
  deprecated (`test_crypto.py`).
- **Two `3DES-CBC` rows and two AES-ECB rows, not one each.** Java's
  `DESede/CBC/PKCS5Padding` states a padding, but pyca's `modes.CBC` does not
  (pyca pads separately). The asset key includes the padding, and the two calls
  are different transformations. The same applies to `AES/ECB/PKCS5Padding`
  versus `modes.ECB()`.
- **3DES has no derived security level.** cbomkit-action reports
  `parameterSetIdentifier: 64` for DESede, which is the block size. The
  canonicalizer does not read it as a key size, and `DESede` does not say whether
  it is two-key or three-key TDEA. Only three-key TDEA has one citable strength.
- **Five security levels are derived and counted** (`coverage.json`,
  `derived`):
  - AES-128 → 128 (twice), DSA-2048 → 112 and P-256 → 128, from NIST SP 800-57
    Part 1 Rev. 5 §5.6.1.1 Table 2 (pp. 54-55);
  - Ed25519 → 128, from RFC 8032 §8.5.

  Nothing is derived for these, because none is an exact row of either source:
  - RSA-1024 (its row is "≤ 80");
  - X25519 (RFC 7748 says "~128");
  - the post-quantum sets.
- **One hash from three files and two engines is one asset.** `MD5` has three
  locations: `LegacyAndPqc.java:12` and `legacy_and_pqc.py:10` from
  cbomkit-action, and `legacy.js:4` from cdxgen-cbom. `SHA-1` has the same shape.
- **`NORMALIZE_CRYPTO_FIELD_CONFLICT` on SHA-1's OID.** cdxgen reports
  `2.16.840.1.113719.1.2.8.82`, while cbomkit-action reports `1.3.14.3.2.26`
  (the SHA-1 OID). For algorithms, the engine that read the code ranks first,
  so cbomkit-action's value is kept, and the disagreement is reported.
- **The AES OID conflict stays per asset.** cbomkit-action gives the AES arc
  `2.16.840.1.101.3.4.1`, but aes128-ECB is `…1.1` (NIST CSOR). The engine
  value is kept, and `analysis_diagnostics` records
  `NORMALIZE_CRYPTO_REFERENCE_CONFLICT`.
- **No `CBOM_PRIVATE_KEY_IN_SOURCE`**, even though cbomkit-action reports pyca's
  `rsa.generate_private_key` (13) and `Ed25519PrivateKey.generate()` (14) as
  `private-key` material. These are keys the code generates at runtime. Only
  an engine that reads key files may say a key is in the source (03 §1.6).
- **Keys are judged as their algorithm.** cbomkit-action names every generated
  key `key`, `private-key` or `secret-key` and links it to its algorithm only
  through `dependencies`. Each key carries `alg=` in its `asset_key` and the
  algorithm's verdict. The DSA and Ed25519 keys get ML-DSA. An RSA or EC key
  gets "ML-KEM or ML-DSA", because a key does not state its use.
- **`completeness_pct` 60.0, `declaration_pct` 100.0.** Source engines report
  no key ids, states or dates, and no algorithm list. The normalizer declares
  every field of every asset's type, with a value or with `not-provided`
  (invariant 3).

### What the engines saw, and what they did not

| Engine | Found | Did not find |
|---|---|---|
| `cbomkit-action` | Every Java call (11, 12, 13, 14, 16, 20, 23, 24, 27, 32, 34) and every Python call (9 to 15), with lines. Also `SHA-512` beside each Ed25519, which is the hash Ed25519 uses internally (RFC 8032 §5.1); the source never names it | The JS file, which is not its language. **Sizes the source does not state are engine defaults:** AES-128 on both ECB calls (the code passes no size, or a variable), and ML-KEM-768 and ML-DSA-65 for `getInstance("ML-KEM")` and `("ML-DSA")`, which name no parameter set. For one `EC` generator initialised with `secp256r1`, it reports two algorithms (`EC` on 23, `EC-secp256r1` on 24) and two keys on line 23 |
| `cdxgen-cbom` | `md5` (4), `sha-1` (5) and `rsa` (6) in `web/legacy.js` | `modulusLength: 1024`: its `rsa` has no size and no primitive, so it stays **unassessed**, not `weak`. It also finds nothing in Java or Python, which the adapter never asks it to read. Its SHA-1 OID is not SHA-1's, and its RSA OID `2.5.8.1.1` is X.500's obsolete `id-ea-rsa` |
| `cbomkit-theia` | Nothing. Its output is `"components": null` | Nothing to find: the fixture has no certificate, key or crypto-configuration file. theia reads files, never code |

## What would a wrong implementation produce instead?

- **`keygen` read as key establishment:** Ed25519, DSA, and the Ed25519 and
  DSA keys tell a customer to replace their signatures with a KEM.
- **Bare `EC` unmatched:** `EC` on line 23 and its key are
  `quantum_vulnerable: false`, so an elliptic-curve key is missing from the
  migration list.
- **`EC` matched as a word in the haystack:** an unresolved reference like
  `…-a3ec-…` is sometimes read as a curve.
- **DSA rule before post-quantum:** `ML-DSA-65` comes back `deprecated`.
- **ECB judged by the cipher name:** `AES-128-ECB-PKCS5` comes back `current`.
- **Unsized RSA assumed safe:** cdxgen's `rsa` comes back `current`, when the
  code generates a 1024-bit key.
- **DESede's `64` read as a key size:** 3DES is judged as a 64-bit cipher.
- **A merge by name:** the two 3DES transformations, or the two AES-ECB ones,
  collapse into one.
- **No merge:** MD5 and SHA-1 are each listed three times.

## Provenance

Captured 2026-09-11. All three engines ran concurrently under the sandbox policy
of `libs/go-shared/sandbox/runner.go` `buildConfig`:
`--network=none --read-only --cap-drop ALL --security-opt no-new-privileges:true --user 65534:65534 --memory 4096m --memory-swap 4096m --pids-limit 512 --cpus 2 --tmpfs /workspace:rw,noexec,nosuid,nodev,size=2048m,uid=65534,gid=65534,mode=0700 -w /workspace -v <repo>:/src:ro`.
Only stdout was captured. Each engine exited 0.

| raw file | sha256 | image (by digest) | entrypoint + argv | env | wall clock |
|---|---|---|---|---|---|
| `cbomkit-theia.json` | `7be662cef16bc30794022510567f41628979f6451dc520b47ccc5877604bfc4b` | `ghcr.io/cbomkit/cbomkit-theia@sha256:46a72eadc9849b919fc4c72e1c851f9783e03c35db8fad49ba99341ac97f8dea` (tag `1.1.2`) | image default `/app/cbomkit-theia`, `dir /src` | `HOME=/workspace TMPDIR=/workspace` | 0.4 s |
| `cbomkit-action.json` | `f1b624e1c2a19bd24d30be85bf6a3d77fc475a1248a372a702bff76c39a11bd3` | `ghcr.io/cbomkit/cbomkit-action@sha256:47c2505267dc5f055152616ffa0d0076b7d0824fe9e0de670b572d1ebad2fc4b` (tag `v2.3.0`) | `sh -c 'mkdir -p /workspace/cbom /workspace/home /workspace/jvm-temp && java -Xmx3g -XX:-UsePerfData -Djava.io.tmpdir=/workspace/jvm-temp -jar /cbomkit-action/CBOMkit-action.jar 1>&2 && cat /workspace/cbom/cbom.json'` | `GITHUB_WORKSPACE=/src CBOMKIT_LANGUAGES=java,python CBOMKIT_JAVA_REQUIRE_BUILD=false CBOMKIT_GENERATE_MODULE_CBOMS=false CBOMKIT_OUTPUT_DIR=/workspace/cbom HOME=/workspace/home` | 5.7 s |
| `cdxgen-cbom.json` | `a9c5b158b0a21f75413dbea063da476447b8aed3659d2d0d36849b2325fb5a6d` | `ghcr.io/cdxgen/cdxgen@sha256:0be75639a833b59d1ba29b3c8ac00dfd2e41e7568d56b6c039007caadebebc0d` (tag `13.0.1`) | `cbom -r /src -o - --spec-version 1.6 --no-banner --no-install-deps` | `FETCH_LICENSE=false CDXGEN_DEBUG_MODE=quiet TMPDIR=/workspace CDXGEN_TEMP_DIR=/workspace/cdxgen-temp CDXGEN_TMP_DIR=/workspace/cdxgen-temp CDXGEN_CACHE_DIR=/workspace/cdxgen-cache SEARCH_MAVEN_ORG=false` | 15.1 s |

These are exactly the entrypoints, argv and environments in
`workers/cbom/adapters/cbomkit_theia.py` (a git source runs `dir` mode),
`cbomkit_action.py` and `cdxgen_cbom.py`. cbomkit-action's stderr reports
`Scanned 1 java projects`, `Scanned 1 python projects` and
`Wrote cbom … with 29 findings`.

- `repo/`: hand-written call sites. It holds no keys and no secrets, and the
  code is never run.
- `expected/`: written by
  `python -m workers.cbom.normalize_runner fixtures/crypto-quantum --write-expected`
  at CBOM ruleset `2026.09.1`, after the three fixes above. Each asset was then
  reviewed against the table in this README. `workers/cbom/test_golden.py`
  replays it under `task test:golden`.
