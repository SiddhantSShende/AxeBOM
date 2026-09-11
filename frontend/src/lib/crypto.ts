/**
 * CBOM crypto-asset inventory — GET /v1/projects/{id}/crypto-assets.
 *
 * ⚠ TYPE-DISCRIMINATED, MIRRORING services/project/internal/store/crypto.go.
 * CERT-In Table 9 gives Algorithms/Keys/Protocols/Certificates different
 * field sets (CLAUDE.md invariant 5) — a field absent from a row means "not
 * applicable to this asset type", not "not provided". `CryptoInventory.tsx`
 * must render each type's own columns, never one flat table with every
 * field for every row.
 *
 * ⚠ EVERY IDENTITY, EVIDENCE AND PROVENANCE FIELD IS OPTIONAL. An older backend
 * returns none of them, and the page must still render — a missing location is
 * shown as missing, never invented.
 */

import { useQuery } from '@tanstack/react-query';
import { request } from './api';

/** Where one engine saw an asset: repository-relative path, line when known. */
export interface CryptoEvidence {
  path: string;
  line: number | null;
  engine: string;
}

export interface CryptoAsset {
  // ---- identity (docs/03-NORMALIZER-SPEC.md §1.6) ----
  /** The stable merge key — the same asset across scans and re-normalizations. */
  asset_key?: string;
  identity_rule?: string;
  identity_confidence?: 'high' | 'medium' | 'low';
  /** A link to an SBOM component. Empty for every current engine. */
  component_key?: string;

  asset_type: 'algorithm' | 'key' | 'protocol' | 'certificate';
  name: string;

  // ---- algorithm ----
  primitive?: string;
  mode?: string;
  crypto_functions?: string[];
  classical_security_level?: number;
  algorithm_list?: string[];

  // ---- key ----
  key_id?: string;
  key_state?: string;
  key_size?: number;
  creation_date?: string;
  activation_date?: string;

  // ---- protocol ----
  protocol_version?: string;
  cipher_suites?: string[];

  // ---- shared by algorithm and protocol ----
  oid?: string;

  // ---- certificate ----
  cert_subject?: string;
  cert_issuer?: string;
  not_valid_before?: string;
  not_valid_after?: string;
  signature_algo_ref?: string;
  subject_public_key_ref?: string;
  cert_format?: string;
  cert_extension?: string;

  // ---- evidence and provenance — never scored ----
  /** Every location every engine saw this asset at. */
  evidence?: CryptoEvidence[];
  /** The distinct engines that found it (cbomkit-theia, cbomkit-action, cdxgen-cbom). */
  engines?: string[];
  /**
   * Non-CERT-In facts: padding, curve, material type, surfaces, NIST quantum
   * category, and `private_key_in_source` / `secret_key_in_source`.
   */
  attributes?: Record<string, unknown>;
  /**
   * `{column: reference_id}` — CERT-In values AxeBOM filled from a cited
   * reference table rather than an engine reporting them. They count as
   * present and are always labelled as derived.
   */
  derivations?: Record<string, string>;

  // ---- AxeBOM analysis — not CERT-In fields, excluded from coverage ----
  quantum_vulnerable: boolean;
  quantum_family?: string;
  quantum_readiness_group?: 'vulnerable' | 'grover_note' | 'post_quantum' | 'unassessed';
  quantum_rationale?: string;
  grover_note?: string;
  effective_quantum_bits?: number;
  pqc_recommendation?: string;
  // `unassessed`: no verdict could be reached — never to be shown as current.
  deprecation_status?: 'current' | 'deprecated' | 'weak' | 'broken' | 'unassessed';
  deprecation_rationale?: string;
  deprecation_reference?: string;
}

export function useCryptoAssets(projectId: string | undefined) {
  return useQuery({
    queryKey: ['crypto-assets', projectId],
    queryFn: ({ signal }) =>
      request<{ crypto_assets: CryptoAsset[] }>(`/v1/projects/${projectId}/crypto-assets`, {
        signal,
      }),
    enabled: Boolean(projectId),
    staleTime: 30_000,
  });
}

/** The four CERT-In Table 9 asset types, in the order the inventory groups them. */
export const CRYPTO_ASSET_TYPES = ['algorithm', 'key', 'protocol', 'certificate'] as const;

/** readinessLabel names a quantum_readiness_group bucket for display. */
export function readinessLabel(group: CryptoAsset['quantum_readiness_group']): string {
  switch (group) {
    case 'vulnerable':
      return 'Quantum-vulnerable';
    case 'grover_note':
      return 'Grover note (sizing, not a break)';
    case 'post_quantum':
      return 'Already post-quantum';
    case 'unassessed':
      return 'Unassessed';
    default:
      return 'Not classified';
  }
}

/**
 * deprecationLabel names a deprecation verdict for display.
 *
 * ⚠ `unassessed` IS ITS OWN WORD, NEVER "Current". It means no verdict could be
 * reached — an RSA key whose size nobody reported is the likeliest legacy
 * 1024-bit key — and a reader filtering for problems must still see it.
 */
export function deprecationLabel(status: CryptoAsset['deprecation_status']): string {
  switch (status) {
    case 'current':
      return 'Current';
    case 'deprecated':
      return 'Deprecated';
    case 'weak':
      return 'Weak';
    case 'broken':
      return 'Broken';
    case 'unassessed':
      return 'Unassessed';
    default:
      return 'Not assessed';
  }
}

/** deprecationTone maps a verdict onto the pill palette. Only `current` is ok. */
export function deprecationTone(
  status: CryptoAsset['deprecation_status'],
): 'ok' | 'warn' | 'down' | 'info' {
  switch (status) {
    case 'current':
      return 'ok';
    case 'deprecated':
    case 'unassessed':
      return 'warn';
    case 'weak':
    case 'broken':
      return 'down';
    default:
      return 'info';
  }
}

/** formatEvidence renders one location as `path:line`, or `path` with no line. */
export function formatEvidence(evidence: CryptoEvidence): string {
  return evidence.line ? `${evidence.path}:${evidence.line}` : evidence.path;
}

export interface LocationSummary {
  /** The first distinct location. */
  primary: string;
  /** Every other distinct location, in order. */
  rest: string[];
  /** What the cell shows: the primary, plus "+N more" when there are others. */
  label: string;
}

/**
 * summarizeLocations reduces an asset's evidence to what one table cell can
 * show, keeping the rest for a tooltip. Two engines reporting the same
 * `path:line` are one location. Returns null when there is no evidence at all
 * — an older backend, or an engine that reported none — so the caller shows
 * the gap rather than a made-up place.
 */
export function summarizeLocations(
  evidence: readonly CryptoEvidence[] | undefined,
): LocationSummary | null {
  const seen: string[] = [];
  for (const item of evidence ?? []) {
    if (!item?.path) continue;
    const formatted = formatEvidence(item);
    if (!seen.includes(formatted)) seen.push(formatted);
  }
  if (seen.length === 0) return null;
  const [primary, ...rest] = seen as [string, ...string[]];
  return {
    primary,
    rest,
    label: rest.length > 0 ? `${primary} +${rest.length} more` : primary,
  };
}

/** derivedFrom says which cited reference a column's value came from, if any. */
export function derivedFrom(asset: CryptoAsset, column: string): string | undefined {
  const reference = asset.derivations?.[column];
  return typeof reference === 'string' && reference !== '' ? reference : undefined;
}

/**
 * assetEngines lists the engines that found an asset: the backend's list when
 * it sends one, otherwise the engines named in its evidence. Sorted, distinct.
 */
export function assetEngines(asset: CryptoAsset): string[] {
  const named = asset.engines?.length
    ? asset.engines
    : (asset.evidence ?? []).map((e) => e?.engine).filter(Boolean);
  return [...new Set(named)].sort();
}

/**
 * privateKeyInSource is true only when the normalizer said so — an engine that
 * reads key FILES found a private key in the scanned source. A key the code
 * merely generates at runtime never sets it.
 */
export function privateKeyInSource(asset: CryptoAsset): boolean {
  return asset.attributes?.private_key_in_source === true;
}

/** assetRowKey is a stable React key: the asset key when the backend sends one. */
export function assetRowKey(asset: CryptoAsset, index: number): string {
  return asset.asset_key || asset.component_key || `${asset.asset_type}:${asset.name}:${index}`;
}

export interface PqcSummary {
  /** What the cell shows: the migration target, e.g. `ML-KEM (FIPS 203, lattice)`. */
  label: string;
  /** The whole recommendation, for the tooltip. */
  full: string;
}

/**
 * pqcSummary splits a recommendation into the migration target a reader scans
 * the column for and the explanation behind it. The analysis writes
 * `<target>: <explanation>`; rendered whole, the explanation made every
 * quantum-vulnerable row several times taller than the rest (live, 2026-09-11).
 * Nothing is dropped — the full text stays one hover away.
 */
export function pqcSummary(text: string | null | undefined): PqcSummary | null {
  const full = (text ?? '').trim();
  if (!full) return null;
  const cut = full.indexOf(': ');
  return { label: cut > 0 ? full.slice(0, cut) : full, full };
}
