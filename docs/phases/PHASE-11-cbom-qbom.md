# Phase 11 — CBOM and QBOM

**Estimated: 3 weeks** · Depends on Phase 10.

## Read first

1. `docs/STATE.md`
2. `docs/reference/certin-v2.0.yaml` → `crypto_asset` (**note the discriminator**) and `qbom`
3. `docs/01-DATA-MODEL.md` §6 (crypto, quantum)
4. **`docs/03-NORMALIZER-SPEC.md` §5.3 (type-aware coverage)**
5. `docs/04-OSINT-INTEGRATION.md` — CBOM/QBOM section

## Goal

Cryptographic inventories from real discovery, and quantum bills of materials as a derivation plus device metadata.

## Preconditions

MVP works end to end. `cbomkit-theia` reports available.

## Two honest labels

**QBOM is not a scan.** No open-source tool discovers quantum hardware. QBOM = crypto assets from CBOM discovery with quantum-vulnerability rules applied, **plus** Table 8 device metadata captured by form or import. The UI must say this. Pretending otherwise burns the phase and produces something undemoable.

**`sonar-cryptography` is deferred.** It is a SonarQube plugin needing a running server. `cbomkit-theia` covers directory and image discovery. Do not add SonarQube to the critical path for this phase.

## Out of scope

`sonar-cryptography`, the `cbomkit` service, PQC migration *planning* (flagging and recommending is in scope; project planning is not).

## Deliverables

```
workers/cbom/adapters/cbomkit_theia.py
workers/cbom/normalize/crypto.py         cryptoProperties -> CryptoAsset
workers/qbom/derive.py                   quantum-vulnerability rules
workers/qbom/metadata.py                 Table 8 device capture

libs/py-shared/axebom_shared/crypto/
  quantum_rules.py    Shor / Grover applicability
  pqc.py              NIST PQC recommendations
  deprecation.py      weak / deprecated / broken

services/report/render/  crypto sections
frontend/  crypto inventory, quantum readiness, QBOM device form
fixtures/{crypto-mixed,crypto-quantum}/
```

## Contracts to honour

- **Coverage is type-aware.** Score each asset only against the field set for its `asset_type`, as the profile defines it (never restate the sizes — invariant 2). Scoring a certificate against `key_size` reports every CBOM at roughly 30%, falsely, in a compliance document.
- `quantum_vulnerable`, `pqc_recommendation` and `deprecation_status` are **AxeBOM extensions, excluded from coverage scoring**. They are analysis, not CERT-In fields.
- QBOM `crypto_assets` reference the CBOM-derived assets — a QBOM does not re-discover them.
- `cbomkit-theia`'s output schema is early and moving: **parse defensively**, ignore unknown fields, diagnose missing ones, never panic.

## Steps

1. `cbomkit-theia` adapter for `dir` and `image` modes, in the sandbox.
2. Map CycloneDX `cryptoProperties` → `normalize.crypto_assets`, **branching on `assetType`** to populate the right columns.
3. **Type-aware coverage** in `coverage.py`. This is the correctness requirement of the phase; write the test before the implementation.
4. Quantum rules: RSA, ECC/ECDSA/ECDH, DH, DSA → `quantum_vulnerable = true` (Shor). Symmetric primitives get a **Grover note on effective key strength, not a vulnerability flag** — halving effective strength is a sizing concern, not a break, and flagging AES-256 as quantum-vulnerable would be wrong.
5. PQC recommendations per family: lattice, code-based, hash-based, multivariate. Cite NIST standards; do not invent guidance.
6. Deprecation: MD5, SHA-1, DES, 3DES, RC4, small RSA/DH → `weak` or `broken`.
7. QBOM device metadata form for Table 8's eleven elements, with the same `not-provided` discipline as everywhere else.
8. Report sections: crypto inventory with OID/mode/security level, quantum-readiness view, migration guidance.
9. Frontend: inventory table grouped by asset type, readiness dashboard, device form.
10. Fixtures `crypto-mixed` (all four types, proving type-aware coverage) and `crypto-quantum`. Update `docs/STATE.md`.

## Test requirements

- All four asset types normalize from one scan with the right columns populated.
- **Type-aware coverage**: a certificate is not scored against `key_size`; each type's denominator is its own profile field set.
- RSA/ECC/DH/DSA flagged; **AES-256 is not flagged** but carries a Grover note.
- Deprecated algorithms marked.
- QBOM references CBOM assets rather than duplicating them.
- Device metadata persists with explicit `not-provided`.
- Defensive parsing survives a mutated `cbomkit-theia` fixture.
- Reports render crypto sections with correct coverage.

## Exit criteria

```
go test ./workers/cbom/... ./workers/qbom/... -v
task test:golden      # incl. crypto-mixed, crypto-quantum
task verify
```

Manual: repo with TLS config and certificates → CBOM with algorithms, keys, protocols and certificates → QBOM adds device metadata → report shows quantum readiness with migration guidance.

## Before you finish

Update `docs/STATE.md`: CBOM/QBOM working, `cbomkit-theia` version, and confirm the UI honestly labels QBOM as derivation-plus-metadata rather than discovery.
