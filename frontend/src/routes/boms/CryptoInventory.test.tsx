import { describe, expect, it } from 'vitest';
import { render, screen, within } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter, Route, Routes } from 'react-router';
import { CryptoInventory, DERIVED_NOTE } from './CryptoInventory';
import type { CryptoAsset } from '../../lib/crypto';

const derivedAES: CryptoAsset = {
  asset_key: 'algorithm:aes;bits=256;mode=gcm;primitive=ae',
  asset_type: 'algorithm',
  name: 'AES-256-GCM',
  primitive: 'ae',
  oid: '2.16.840.1.101.3.4.1.46',
  classical_security_level: 256,
  derivations: {
    classical_security_level: 'nist-sp800-57p1r5-table2',
    oid: 'nist-csor-aes',
  },
  evidence: [
    { path: 'src/Crypto.java', line: 23, engine: 'cbomkit-action' },
    { path: 'src/Other.java', line: 9, engine: 'cbomkit-action' },
  ],
  engines: ['cbomkit-action'],
  quantum_vulnerable: false,
  quantum_readiness_group: 'grover_note',
  deprecation_status: 'current',
};

const unsizedRSA: CryptoAsset = {
  asset_key: 'algorithm:rsa;primitive=pke',
  asset_type: 'algorithm',
  name: 'RSA',
  primitive: 'pke',
  quantum_vulnerable: true,
  quantum_readiness_group: 'vulnerable',
  pqc_recommendation: 'ML-KEM (FIPS 203, lattice): replace key establishment',
  deprecation_status: 'unassessed',
  deprecation_rationale: 'RSA key size was not reported, so its strength could not be assessed.',
  evidence: [{ path: 'certs/server.pem', line: null, engine: 'cbomkit-theia' }],
  engines: ['cbomkit-theia'],
};

const committedKey: CryptoAsset = {
  asset_key: 'key:private-key;alg=rsa;size=2048;path=key.pem',
  asset_type: 'key',
  name: 'RSA-2048',
  key_size: 2048,
  attributes: { private_key_in_source: true, material_type: 'private-key' },
  evidence: [{ path: 'key.pem', line: null, engine: 'cbomkit-theia' }],
  engines: ['cbomkit-theia'],
  quantum_vulnerable: true,
  deprecation_status: 'current',
};

const generatedKey: CryptoAsset = {
  asset_key: 'key:secret-key;size=2048;path=src/Keys.java:15',
  asset_type: 'key',
  name: 'secret-key',
  key_size: 2048,
  attributes: { material_type: 'secret-key' },
  evidence: [{ path: 'src/Keys.java', line: 15, engine: 'cbomkit-action' }],
  quantum_vulnerable: false,
};

// What an older backend sends: none of the identity, evidence or provenance fields.
const legacy: CryptoAsset = {
  asset_type: 'protocol',
  name: 'TLS',
  protocol_version: '1.2',
  quantum_vulnerable: false,
};

function renderInventory(assets: CryptoAsset[]) {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false, staleTime: Infinity } },
  });
  client.setQueryData(['crypto-assets', 'p1'], { crypto_assets: assets });

  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={['/projects/p1/crypto']}>
        <Routes>
          <Route path="/projects/:id/crypto" element={<CryptoInventory />} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

function rowFor(name: string): HTMLElement {
  const cell = screen.getAllByRole('cell').find((c) => c.textContent?.startsWith(name));
  if (!cell) throw new Error(`no row for ${name}`);
  return cell.closest('tr') as HTMLElement;
}

describe('derived values', () => {
  it('are marked with a dagger naming their source, and footnoted', () => {
    renderInventory([derivedAES]);
    const row = rowFor('AES-256-GCM');

    const marks = within(row).getAllByText('†');
    expect(marks).toHaveLength(2);
    expect(marks[0]).toHaveAttribute('title', expect.stringContaining('not reported by an engine'));
    expect(marks.map((m) => m.getAttribute('title')).join(' ')).toContain(
      'nist-sp800-57p1r5-table2',
    );
    expect(screen.getByText(new RegExp(DERIVED_NOTE.slice(2, 40)))).toBeInTheDocument();
  });

  it('are not marked when the engine reported the value', () => {
    renderInventory([{ ...derivedAES, derivations: {} }]);
    expect(within(rowFor('AES-256-GCM')).queryByText('†')).toBeNull();
  });
});

describe('deprecation', () => {
  it('shows unassessed as Unassessed, never as Current', () => {
    renderInventory([unsizedRSA]);
    const row = rowFor('RSA');

    const pill = within(row).getAllByText('Unassessed')[0]!;
    expect(pill).toHaveAttribute('data-status', 'warn');
    expect(within(row).queryByText('Current')).toBeNull();
  });

  it('shows the PQC recommendation for a quantum-vulnerable asset only', () => {
    renderInventory([unsizedRSA, derivedAES]);
    expect(within(rowFor('RSA')).getByText(/ML-KEM/)).toBeInTheDocument();
    expect(within(rowFor('AES-256-GCM')).queryByText(/ML-KEM/)).toBeNull();
  });
});

describe('keys', () => {
  it('warn when a private key file was found in the source', () => {
    renderInventory([committedKey]);
    const badge = within(rowFor('RSA-2048')).getByText(/private key found in source/i);
    expect(badge).toHaveAttribute('data-status', 'down');
  });

  it('do not warn about a key the code generates at runtime', () => {
    renderInventory([generatedKey]);
    expect(within(rowFor('secret-key')).queryByText(/private key found in source/i)).toBeNull();
  });
});

describe('location and engines', () => {
  it('shows the first location and counts the rest', () => {
    renderInventory([derivedAES]);
    const row = rowFor('AES-256-GCM');
    const location = within(row).getByText('src/Crypto.java:23 +1 more');
    expect(location).toHaveAttribute('title', 'src/Crypto.java:23\nsrc/Other.java:9');
    expect(within(row).getByText('cbomkit-action')).toBeInTheDocument();
  });

  it('shows a key file with no line as just its path', () => {
    renderInventory([committedKey]);
    expect(within(rowFor('RSA-2048')).getByText('key.pem')).toBeInTheDocument();
  });

  it('still renders a row from an older backend, with the gaps shown as gaps', () => {
    renderInventory([legacy]);
    const row = rowFor('TLS');
    expect(within(row).getByText('Not assessed')).toBeInTheDocument();
    // Location, engines and PQC recommendation are all absent, and say so.
    expect(within(row).getAllByText('—').length).toBeGreaterThanOrEqual(3);
  });
});

describe('type discrimination', () => {
  it('keeps each asset type in its own table', () => {
    renderInventory([derivedAES, committedKey, legacy]);
    expect(screen.getByRole('heading', { name: 'Algorithms' })).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: 'Keys' })).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: 'Protocols' })).toBeInTheDocument();
    // A key's table asks for no OID; an algorithm's asks for no key size.
    const keyTable = screen.getByRole('heading', { name: 'Keys' }).closest('section')!;
    expect(within(keyTable).queryByRole('columnheader', { name: 'OID' })).toBeNull();
  });
});
