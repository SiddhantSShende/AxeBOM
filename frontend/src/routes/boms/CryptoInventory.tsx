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
 */

import { useParams } from 'react-router';
import { EmptyState, ErrorState, SkeletonRows } from '../../components/States';
import { useProject } from '../../lib/projects';
import {
  CRYPTO_ASSET_TYPES,
  readinessLabel,
  useCryptoAssets,
  type CryptoAsset,
} from '../../lib/crypto';

const TYPE_LABELS: Record<(typeof CRYPTO_ASSET_TYPES)[number], string> = {
  algorithm: 'Algorithms',
  key: 'Keys',
  protocol: 'Protocols',
  certificate: 'Certificates',
};

export function CryptoInventory() {
  const { id = '' } = useParams();
  const project = useProject(id);
  const { data, isPending, isError, error } = useCryptoAssets(id);

  if (isPending) return <SkeletonRows rows={8} columns={4} />;
  if (isError) return <ErrorState error={error} action="load the crypto inventory" />;

  const assets = data?.crypto_assets ?? [];

  return (
    <div className="page">
      <header className="page-header">
        <div>
          <h1>Crypto inventory</h1>
          <p className="tagline">{project.data?.name ?? 'Project'}</p>
        </div>
      </header>

      {assets.length === 0 ? (
        <EmptyState
          title="No cryptographic assets discovered yet"
          guidance="Run a CBOM scan from Generate. cbomkit-theia discovers algorithms, keys, protocols and certificates from source, container images and configuration."
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
  return (
    <section className="panel" aria-labelledby={`crypto-${type}-heading`}>
      <h2 id={`crypto-${type}-heading`}>{TYPE_LABELS[type]}</h2>
      <div className="table-wrap">
        <table className="table">
          <caption className="table-caption">
            {type === 'certificate'
              ? "Only this type's own fields — CERT-In Table 9 does not ask a certificate for a key size."
              : `${rows.length} ${TYPE_LABELS[type].toLowerCase()}.`}
          </caption>
          <thead>
            <tr>
              <th scope="col">Name</th>
              {typeColumns(type).map((c) => (
                <th key={c.key} scope="col">
                  {c.label}
                </th>
              ))}
              <th scope="col">Quantum readiness</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((a, i) => (
              <tr key={a.component_key ?? `${a.name}-${i}`}>
                <td>{a.name}</td>
                {typeColumns(type).map((c) => (
                  <td key={c.key}>{c.render(a)}</td>
                ))}
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

interface Column {
  key: string;
  label: string;
  render: (a: CryptoAsset) => string;
}

function typeColumns(type: (typeof CRYPTO_ASSET_TYPES)[number]): Column[] {
  switch (type) {
    case 'algorithm':
      return [
        { key: 'primitive', label: 'Primitive', render: (a) => a.primitive || '—' },
        { key: 'oid', label: 'OID', render: (a) => a.oid || '—' },
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

function readinessTone(group: CryptoAsset['quantum_readiness_group']): 'ok' | 'warn' | 'down' | 'info' {
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
