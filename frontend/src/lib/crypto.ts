/**
 * CBOM crypto-asset inventory — GET /v1/projects/{id}/crypto-assets.
 *
 * ⚠ TYPE-DISCRIMINATED, MIRRORING services/project/internal/store/crypto.go.
 * CERT-In Table 9 gives Algorithms/Keys/Protocols/Certificates different
 * field sets (CLAUDE.md invariant 5) — a field absent from a row means "not
 * applicable to this asset type", not "not provided". `CryptoInventory.tsx`
 * must render each type's own columns, never one flat table with every
 * field for every row.
 */

import { useQuery } from '@tanstack/react-query';
import { request } from './api';

export interface CryptoAsset {
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

  // ---- AxeBOM analysis — not CERT-In fields, excluded from coverage ----
  quantum_vulnerable: boolean;
  quantum_family?: string;
  quantum_readiness_group?: 'vulnerable' | 'grover_note' | 'post_quantum' | 'unassessed';
  quantum_rationale?: string;
  grover_note?: string;
  effective_quantum_bits?: number;
  pqc_recommendation?: string;
  deprecation_status?: 'current' | 'deprecated' | 'weak' | 'broken';
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
