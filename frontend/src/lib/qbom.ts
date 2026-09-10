/**
 * QBOM Table 8 device metadata — GET/POST /v1/qbom/{projectId}.
 *
 * ⚠ CAPTURED, NEVER SCANNED. Mirrors services/project/internal/qbom's own
 * warning: there is no quantum-hardware scanner. `disclosure` is served by
 * the API, not hardcoded here, so the honesty statement can never drift from
 * what the backend actually asserts.
 */

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { api, request } from './api';

export interface QBOMFormField {
  field_id: string;
  name: string;
  canonical_path: string;
  type: string;
  source_page: number;
  derived: boolean;
}

export interface QBOMGap {
  field_id: string;
  name: string;
  reason: string;
}

export interface QuantumDevice {
  model_name: string;
  version: string;
  vendor_origin: string;
  license_info: string;
  communication_protocol: string;
  hardware: string;
  software_dependencies: string[];
  environmental_impact: string;
  attestation_signature: string;
  crypto_asset_refs: string[];
  finding_refs: string[];
  field_status: Record<string, string>;
  gaps: QBOMGap[];
}

export interface QuantumDeviceValues {
  model_name: string;
  version: string;
  vendor_origin: string;
  license_info: string;
  communication_protocol: string;
  hardware: string;
  software_dependencies: string[];
  environmental_impact: string;
  attestation_signature: string;
}

export function useQBOMForm(projectId: string | undefined) {
  return useQuery({
    queryKey: ['qbom-form', projectId],
    queryFn: ({ signal }) =>
      request<{ fields: QBOMFormField[]; disclosure: string }>(
        `/v1/qbom/${projectId}/form`,
        { signal },
      ),
    enabled: Boolean(projectId),
    staleTime: Infinity,
  });
}

/**
 * useQBOMRegistrationForm is the same field list, before a project exists.
 *
 * ⚠ FOR THE WIZARD, WHICH HAS NO PROJECT ID TO PUT IN A PATH. Table 8's
 * elements are the one part of a QBOM no scan can produce, and they were
 * reachable only from a screen that needs a created project — so registering a
 * QBOM asked exactly the same questions as registering an SBOM, and the form it
 * cannot do without became a task discovered later.
 *
 * A separate cache key from useQBOMForm's on purpose: same body, different
 * lifetime. This one is fetched while a form is being filled in and the other
 * on a project screen, and sharing a key would make one screen's staleness the
 * other's problem.
 */
export function useQBOMRegistrationForm(enabled: boolean) {
  return useQuery({
    queryKey: ['qbom-registration-form'],
    queryFn: ({ signal }) =>
      request<{ fields: QBOMFormField[]; disclosure: string }>('/v1/qbom/form', { signal }),
    enabled,
    staleTime: Infinity,
  });
}

/** EMPTY_QUANTUM_DEVICE is the wizard's starting draft. */
export const EMPTY_QUANTUM_DEVICE: QuantumDeviceValues = {
  model_name: '',
  version: '',
  vendor_origin: '',
  license_info: '',
  communication_protocol: '',
  hardware: '',
  software_dependencies: [],
  environmental_impact: '',
  attestation_signature: '',
};

/**
 * hasQuantumValues reports whether anything was actually typed.
 *
 * ⚠ SUBSTANTIVE VALUES ONLY, WHICH IS INVARIANT 3's RULE APPLIED AT THE POINT
 * OF ENTRY. Posting a device of nine empty strings would create a QBOM document
 * whose every element is not-provided — a `declaration_pct` of 100 and a
 * `completeness_pct` of 0 — which reads as "recorded" on every screen that
 * counts documents. An untouched form must stay untouched.
 */
export function hasQuantumValues(v: QuantumDeviceValues): boolean {
  return (
    v.software_dependencies.length > 0 ||
    [
      v.model_name,
      v.version,
      v.vendor_origin,
      v.license_info,
      v.communication_protocol,
      v.hardware,
      v.environmental_impact,
      v.attestation_signature,
    ].some((s) => s.trim() !== '')
  );
}

/**
 * useRegisterQuantumDevice saves Table 8 metadata for a project created moments
 * ago, so the id arrives with the variables rather than at hook-creation time —
 * the same shape useSetPractices and useConnectRepo use, and for the same
 * reason: there is no project id when the wizard renders.
 */
export function useRegisterQuantumDevice() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ projectId, values }: { projectId: string; values: QuantumDeviceValues }) =>
      api.post<{ bom_document_id: string; device: QuantumDevice }>(
        `/v1/qbom/${projectId}/device`,
        values,
      ),
    onSuccess: (_data, { projectId }) => {
      void qc.invalidateQueries({ queryKey: ['qbom-device', projectId] });
    },
  });
}

export function useQuantumDevice(projectId: string | undefined) {
  return useQuery({
    queryKey: ['qbom-device', projectId],
    queryFn: ({ signal }) => request<QuantumDevice>(`/v1/qbom/${projectId}`, { signal }),
    enabled: Boolean(projectId),
  });
}

export function useSaveQuantumDevice(projectId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (values: QuantumDeviceValues) =>
      api.post<{ bom_document_id: string; device: QuantumDevice }>(
        `/v1/qbom/${projectId}/device`,
        values,
      ),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ['qbom-device', projectId] });
    },
  });
}
