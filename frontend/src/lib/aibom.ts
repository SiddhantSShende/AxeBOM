/**
 * AIBOM model inventory — GET /v1/projects/{id}/ai-models, and the four
 * user-supplied Table 10 elements no tool can ever report.
 *
 * ⚠ MOSTLY DISCOVERED, NOT CAPTURED — the opposite emphasis from qbom.ts.
 * Sixteen of Table 10's nineteen elements come from workers/aibom's
 * discovery + enrichment pipeline; only intended_usage, out_of_scope_usage,
 * security_requirements and attestation_signature are ever user-editable
 * (services/project/internal/aibom's IsUserSupplied). AIModelInventory.tsx
 * must never offer an edit control for anything else.
 */

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { api, request } from './api';

export interface AIDataset {
  name: string;
  version?: string;
  format?: string;
  limitations?: string;
  license?: string;
  source?: string;
}

export interface AIModel {
  id: string;
  model_name: string;
  model_version?: string;
  model_type?: string;
  model_developer?: string;
  licensing?: string;
  ml_models_algorithms?: string[];
  performance_metrics?: Record<string, unknown>;
  data_source?: string;
  hardware?: string;
  security_requirements?: string;
  input?: string;
  output?: string;
  intended_usage?: string;
  out_of_scope_usage?: string;
  environmental_impact?: string;
  attestation_signature?: string;
  // ⚠ AXEBOM EXTENSIONS FROM TRUSERA ai-bom — NOT CERT-In Table 10 fields,
  // excluded from both coverage numbers. Render clearly labelled as such.
  risk_score?: number;
  owasp_llm_top10?: string[];
  field_status: Record<string, string>;
  datasets: AIDataset[];
  dependencies: string[];
}

export interface AIModelFormField {
  field_id: string;
  name: string;
  canonical_path: string;
  source_page: number;
}

export interface AIModelUserFields {
  security_requirements: string;
  intended_usage: string;
  out_of_scope_usage: string;
  attestation_signature: string;
}

export function useAIModels(projectId: string | undefined) {
  return useQuery({
    queryKey: ['ai-models', projectId],
    queryFn: ({ signal }) =>
      request<{ ai_models: AIModel[] }>(`/v1/projects/${projectId}/ai-models`, { signal }),
    enabled: Boolean(projectId),
    staleTime: 30_000,
  });
}

export function useAIModelForm(projectId: string | undefined) {
  return useQuery({
    queryKey: ['ai-model-form', projectId],
    queryFn: ({ signal }) =>
      request<{ fields: AIModelFormField[] }>(`/v1/aibom/${projectId}/form`, { signal }),
    enabled: Boolean(projectId),
    staleTime: Infinity,
  });
}

export function useUpdateAIModelUserFields(projectId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ modelId, fields }: { modelId: string; fields: AIModelUserFields }) =>
      api.post<{ ai_model: AIModel }>(
        `/v1/projects/${projectId}/ai-models/${modelId}/fields`,
        fields,
      ),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ['ai-models', projectId] });
    },
  });
}
