/**
 * CBOM crypto-asset inventory — one project's discovered algorithms, keys,
 * protocols and certificates.
 *
 * ⚠ FOUR TABLES, NEVER ONE. CERT-In Table 9 scores each asset type against
 * its own field set (CLAUDE.md invariant 5) — a single table with every
 * column for every row is exactly the shape that makes a certificate look
 * scored against `key_size`. `services/report/internal/render/cbom.go`
 * draws the same four-way split for the downloadable workbook; this is the
 * live equivalent for the sidebar's CBOM section.
 *
 * ⚠ EVERY ROW SAYS WHERE IT WAS SEEN AND WHO SAW IT. The location column and the
 * engine chips are what let a reviewer check a row against the code rather than
 * take it on trust; a value AxeBOM filled from a cited reference table carries a
 * † so it is never mistaken for something an engine measured; and `unassessed`
 * is its own pill, never "Current".
 */

import type { ReactNode } from 'react';
import { useParams } from 'react-router';
import { ProvenanceChips } from '../../components/Chips';
import { EmptyState, ErrorState, SkeletonRows } from '../../components/States';
import {
  CRYPTO_ASSET_TYPES,
  assetEngines,
  assetRowKey,
  deprecationLabel,
  deprecationTone,
  derivedFrom,
  pqcSummary,
  privateKeyInSource,
  readinessLabel,
  summarizeLocations,
  useCryptoAssets,
  type CryptoAsset,
} from '../../lib/crypto';

const TYPE_LABELS: Record<(typeof CRYPTO_ASSET_TYPES)[number], string> = {
  algorithm: 'Algorithms',
  key: 'Keys',
  protocol: 'Protocols',
  certificate: 'Certificates',
};

/** The footnote a † points at. Rendered only when a table has a derived value. */
export const DERIVED_NOTE = '† Derived from a cited reference table, not reported by an engine.';

export function CryptoInventory() {
  const { id = '' } = useParams();
  const { data, isPending, isError, error } = useCryptoAssets(id);

  if (isPending) return <SkeletonRows rows={8} columns={4} />;
  if (isError) return <ErrorState error={error} action="load the crypto inventory" />;

  const assets = data?.crypto_assets ?? [];

  return (
    <div className="page">
      <header className="page-header">
        <div>
          <h1>Crypto inventory</h1>
          {/* The project name is carried by the crumb above the tabs (App.tsx's
              ProjectCrumb); repeating it here printed it twice in one header. */}
        </div>
      </header>

      {assets.length === 0 ? (
        <EmptyState
          title="No cryptographic assets discovered yet"
          guidance="Run a CBOM scan from Generate. Crypto assets appear here once the scan's CBOM engines have run; the scan's Engine Coverage shows what each engine examined and what it could not see."
        />
      ) : (
        CRYPTO_ASSET_TYPES.map((type) => {
          const rows = assets.filter((a) => a.asset_type === type);
          if (rows.length === 0) return null;
          return <TypeTable key={type} type={type} rows={rows} />;
        })
      )}
    </div>
  );
}

function TypeTable({
  type,
  rows,
}: {
  type: (typeof CRYPTO_ASSET_TYPES)[number];
  rows: CryptoAsset[];
}) {
  const columns = typeColumns(type);
  const anyDerived = rows.some((a) => Object.keys(a.derivations ?? {}).length > 0);

  return (
    <section className="panel" aria-labelledby={`crypto-${type}-heading`}>
      <h2 id={`crypto-${type}-heading`}>{TYPE_LABELS[type]}</h2>
      <div className="table-wrap">
        <table className="table">
          <caption className="table-caption">
            {type === 'certificate'
              ? "Only this type's own fields — CERT-In Table 9 does not ask a certificate for a key size."
              : `${rows.length} ${TYPE_LABELS[type].toLowerCase()}.`}
            {anyDerived && ` ${DERIVED_NOTE}`}
          </caption>
          <thead>
            <tr>
              <th scope="col">Name</th>
              {columns.map((c) => (
                <th key={c.key} scope="col">
                  {c.label}
                </th>
              ))}
              <th scope="col">Location</th>
              <th scope="col">Engines</th>
              <th scope="col">Deprecation</th>
              <th scope="col">PQC recommendation</th>
              <th scope="col">Quantum readiness</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((a, i) => (
              <tr key={assetRowKey(a, i)}>
                <td>
                  <NameCell asset={a} />
                </td>
                {columns.map((c) => (
                  <td key={c.key}>{c.render(a)}</td>
                ))}
                <td>
                  <LocationCell asset={a} />
                </td>
                <td>
                  <EnginesCell asset={a} />
                </td>
                <td>
                  <span
                    className="pill"
                    data-status={deprecationTone(a.deprecation_status)}
                    title={
                      [a.deprecation_rationale, a.deprecation_reference]
                        .filter(Boolean)
                        .join(' — ') || undefined
                    }
                  >
                    {deprecationLabel(a.deprecation_status)}
                  </span>
                </td>
                <td>
                  <PqcCell asset={a} />
                </td>
                <td>
                  <span
                    className="pill"
                    data-status={readinessTone(a.quantum_readiness_group)}
                    title={a.quantum_rationale || a.grover_note || undefined}
                  >
                    {readinessLabel(a.quantum_readiness_group)}
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}

/**
 * The asset's name, and — for a private key an engine read out of a FILE in the
 * scanned source — the warning that it is exposed. A key the code merely
 * generates at runtime never carries it.
 */
function NameCell({ asset }: { asset: CryptoAsset }) {
  return (
    <>
      {asset.name}
      {privateKeyInSource(asset) && (
        <>
          {' '}
          <span
            className="pill"
            data-status="down"
            title="A private key file was found in the scanned source. Anyone who can read the source can read the key. AxeBOM never reads or stores the key material itself."
          >
            Private key found in source — rotate and remove
          </span>
        </>
      )}
    </>
  );
}

/** The first location an engine reported, with every other one in the tooltip. */
function LocationCell({ asset }: { asset: CryptoAsset }) {
  const summary = summarizeLocations(asset.evidence);
  if (!summary) return <>—</>;
  const all = [summary.primary, ...summary.rest];
  return (
    <span className="mono" title={all.join('\n')}>
      {summary.label}
    </span>
  );
}

/**
 * The migration target for a quantum-vulnerable asset, with the full
 * recommendation in the tooltip — whole, it made every such row several times
 * taller than the rest.
 */
function PqcCell({ asset }: { asset: CryptoAsset }) {
  const summary = asset.quantum_vulnerable ? pqcSummary(asset.pqc_recommendation) : null;
  if (!summary) return <>—</>;
  return <span title={summary.full}>{summary.label}</span>;
}

function EnginesCell({ asset }: { asset: CryptoAsset }) {
  const engines = assetEngines(asset);
  return engines.length > 0 ? <ProvenanceChips engines={engines} /> : <>—</>;
}

/**
 * A column value, marked with † when AxeBOM filled it from a cited reference
 * table rather than an engine reporting it (derive + count, labelled).
 */
function Derived({
  asset,
  column,
  children,
}: {
  asset: CryptoAsset;
  column: string;
  children: string;
}) {
  const reference = derivedFrom(asset, column);
  if (!reference || children === '—') return <>{children}</>;
  const note = `Derived from ${reference}, not reported by an engine`;
  return (
    <>
      {children}
      <sup className="derived-mark" title={note} aria-label={note}>
        †
      </sup>
    </>
  );
}

interface Column {
  key: string;
  label: string;
  render: (a: CryptoAsset) => ReactNode;
}

function typeColumns(type: (typeof CRYPTO_ASSET_TYPES)[number]): Column[] {
  switch (type) {
    case 'algorithm':
      return [
        { key: 'primitive', label: 'Primitive', render: (a) => a.primitive || '—' },
        {
          key: 'oid',
          label: 'OID',
          render: (a) => (
            <Derived asset={a} column="oid">
              {a.oid || '—'}
            </Derived>
          ),
        },
        {
          key: 'security',
          label: 'Security (bits)',
          render: (a) => (
            <Derived asset={a} column="classical_security_level">
              {a.classical_security_level != null ? String(a.classical_security_level) : '—'}
            </Derived>
          ),
        },
        {
          key: 'functions',
          label: 'Functions',
          render: (a) => (a.crypto_functions ?? []).join(', ') || '—',
        },
      ];
    case 'key':
      return [
        { key: 'state', label: 'State', render: (a) => a.key_state || '—' },
        {
          key: 'size',
          label: 'Size (bits)',
          render: (a) => (a.key_size != null ? String(a.key_size) : '—'),
        },
        { key: 'created', label: 'Created', render: (a) => a.creation_date || '—' },
      ];
    case 'protocol':
      return [
        { key: 'version', label: 'Version', render: (a) => a.protocol_version || '—' },
        {
          key: 'suites',
          label: 'Cipher suites',
          render: (a) => (a.cipher_suites ?? []).join(', ') || '—',
        },
      ];
    case 'certificate':
      return [
        { key: 'issuer', label: 'Issuer', render: (a) => a.cert_issuer || '—' },
        { key: 'valid_until', label: 'Valid until', render: (a) => a.not_valid_after || '—' },
        {
          key: 'signature',
          label: 'Signature algorithm',
          render: (a) => a.signature_algo_ref || '—',
        },
      ];
  }
}

function readinessTone(
  group: CryptoAsset['quantum_readiness_group'],
): 'ok' | 'warn' | 'down' | 'info' {
  switch (group) {
    case 'post_quantum':
      return 'ok';
    case 'grover_note':
    case 'unassessed':
      return 'warn';
    case 'vulnerable':
      return 'down';
    default:
      return 'info';
  }
}
