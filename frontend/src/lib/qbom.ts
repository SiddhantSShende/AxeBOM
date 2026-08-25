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
    queryFn: () =>
      request<{ fields: QBOMFormField[]; disclosure: string }>(
        `/v1/qbom/${projectId}/form`,
      ),
    enabled: Boolean(projectId),
    staleTime: Infinity,
  });
}

export function useQuantumDevice(projectId: string | undefined) {
  return useQuery({
    queryKey: ['qbom-device', projectId],
    queryFn: () => request<QuantumDevice>(`/v1/qbom/${projectId}`),
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
