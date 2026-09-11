import { describe, expect, it } from 'vitest';
import {
  assetEngines,
  assetRowKey,
  deprecationLabel,
  deprecationTone,
  derivedFrom,
  formatEvidence,
  pqcSummary,
  privateKeyInSource,
  summarizeLocations,
  type CryptoAsset,
} from './crypto';

describe('pqcSummary', () => {
  it('shows the migration target and keeps the whole recommendation for the tooltip', () => {
    const full = 'ML-KEM (FIPS 203, lattice): Replace key establishment with ML-KEM; hybrid first.';
    expect(pqcSummary(full)).toEqual({ label: 'ML-KEM (FIPS 203, lattice)', full });
  });

  it('keeps a recommendation with no target prefix whole, and says nothing for none', () => {
    expect(pqcSummary('Migrate to a post-quantum scheme.')?.label).toBe(
      'Migrate to a post-quantum scheme.',
    );
    expect(pqcSummary('')).toBeNull();
    expect(pqcSummary(undefined)).toBeNull();
  });
});

function asset(overrides: Partial<CryptoAsset> = {}): CryptoAsset {
  return { asset_type: 'algorithm', name: 'AES-256-GCM', quantum_vulnerable: false, ...overrides };
}

describe('locations', () => {
  it('renders path:line, and the bare path when no line was reported', () => {
    expect(formatEvidence({ path: 'src/Sign.java', line: 12, engine: 'cbomkit-action' })).toBe(
      'src/Sign.java:12',
    );
    // theia reports key files with no line; "key.pem:null" or ":0" would be invented.
    expect(formatEvidence({ path: 'key.pem', line: null, engine: 'cbomkit-theia' })).toBe(
      'key.pem',
    );
  });

  it('shows the first location and counts the rest', () => {
    const summary = summarizeLocations([
      { path: 'src/Sign.java', line: 12, engine: 'cbomkit-action' },
      { path: 'certs/server.pem', line: null, engine: 'cbomkit-theia' },
      { path: 'src/Other.java', line: 3, engine: 'cbomkit-action' },
    ]);
    expect(summary?.label).toBe('src/Sign.java:12 +2 more');
    expect(summary?.rest).toEqual(['certs/server.pem', 'src/Other.java:3']);
  });

  it('counts one place once when two engines saw it', () => {
    const summary = summarizeLocations([
      { path: 'a.py', line: 4, engine: 'cbomkit-action' },
      { path: 'a.py', line: 4, engine: 'cdxgen-cbom' },
    ]);
    expect(summary?.label).toBe('a.py:4');
  });

  it('is null — never a made-up place — when there is no evidence', () => {
    // An older backend sends no evidence at all.
    expect(summarizeLocations(undefined)).toBeNull();
    expect(summarizeLocations([])).toBeNull();
  });
});

describe('derived values', () => {
  it('names the reference a column was derived from', () => {
    const derived = asset({ derivations: { oid: 'nist-csor-aes' } });
    expect(derivedFrom(derived, 'oid')).toBe('nist-csor-aes');
    expect(derivedFrom(derived, 'classical_security_level')).toBeUndefined();
    expect(derivedFrom(asset(), 'oid')).toBeUndefined();
  });
});

describe('deprecation', () => {
  it('never renders unassessed as current', () => {
    // ⚠ An unsized RSA key is the likeliest legacy 1024-bit key; calling it
    // current would hide exactly the asset a reviewer is looking for.
    expect(deprecationLabel('unassessed')).toBe('Unassessed');
    expect(deprecationLabel('unassessed')).not.toMatch(/current/i);
    expect(deprecationTone('unassessed')).not.toBe('ok');
  });

  it('keeps weak and broken apart from deprecated', () => {
    expect(deprecationTone('current')).toBe('ok');
    expect(deprecationTone('deprecated')).toBe('warn');
    expect(deprecationTone('weak')).toBe('down');
    expect(deprecationTone('broken')).toBe('down');
    expect(deprecationLabel(undefined)).toBe('Not assessed');
  });
});

describe('engines', () => {
  it("uses the backend's list, sorted and distinct", () => {
    expect(
      assetEngines(asset({ engines: ['cbomkit-theia', 'cbomkit-action', 'cbomkit-theia'] })),
    ).toEqual(['cbomkit-action', 'cbomkit-theia']);
  });

  it('falls back to the engines named in the evidence', () => {
    expect(
      assetEngines(
        asset({
          evidence: [
            { path: 'a', line: 1, engine: 'cdxgen-cbom' },
            { path: 'b', line: null, engine: 'cbomkit-theia' },
          ],
        }),
      ),
    ).toEqual(['cbomkit-theia', 'cdxgen-cbom']);
    expect(assetEngines(asset())).toEqual([]);
  });
});

describe('private key in source', () => {
  it('is true only when the normalizer said so', () => {
    expect(privateKeyInSource(asset({ attributes: { private_key_in_source: true } }))).toBe(true);
    // A string is not the flag; a key the code generates carries no flag at all.
    expect(privateKeyInSource(asset({ attributes: { private_key_in_source: 'true' } }))).toBe(
      false,
    );
    expect(privateKeyInSource(asset())).toBe(false);
  });
});

describe('row keys', () => {
  it('prefers the stable asset key', () => {
    expect(assetRowKey(asset({ asset_key: 'algorithm:aes;bits=256' }), 3)).toBe(
      'algorithm:aes;bits=256',
    );
    // component_key is empty for every current engine; the fallback still
    // distinguishes two same-named rows by position.
    expect(assetRowKey(asset({ component_key: '' }), 0)).not.toBe(
      assetRowKey(asset({ component_key: '' }), 1),
    );
  });
});
