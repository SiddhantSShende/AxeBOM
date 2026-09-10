/**
 * AIBOM — the discovered inventory, and the elements no tool can ever report.
 *
 * ⚠ MOSTLY DISCOVERED, NOT CAPTURED — the opposite emphasis from qbom.ts. Most
 * of Table 10 comes from workers/aibom's discovery + enrichment pipeline; only
 * the elements the profile marks `user_supplied` are ever editable, and the
 * server renders that set from the profile (`GET /v1/aibom/{id}/form`).
 * AIModelInventory.tsx must never offer an edit control for anything else, and
 * must never hardcode which ones they are.
 *
 * ⚠ EVERY PATH MOVED TO `/v1/aibom/*`, SERVED BY services/aibom. The inventory
 * used to be `GET /v1/projects/{id}/ai-models` and the write was `POST
 * /v1/projects/{id}/ai-models/{modelId}/fields` — the latter ran an UPDATE
 * against `normalize.ai_models`, a mutation of normalized data. Operator input
 * now lives in the `aibom` schema and the normalizer reads it.
 *
 * ⚠ AND THE WRITE IS KEYED BY `model_key`, NOT BY THE ROW ID. Every
 * re-normalization writes new rows, so a row id is valid for exactly one
 * document and an answer attached to one is orphaned by the next scan.
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

export interface AIAsset {
  /** prompt | vector_store | rag_pipeline | embedding | agent | tool | mcp_server | endpoint | dataset */
  asset_type: string;
  asset_key: string;
  name: string;
  provider?: string;
  evidence: string[];
  serves_model_key?: string;
  attributes?: Record<string, unknown>;
}

export interface AIModel {
  id: string;
  /**
   * The merge key, stable across normalizations — see 03-NORMALIZER-SPEC §1.5.
   * It is what an operator's answers are stored against, so the edit form
   * addresses a model by this and never by `id`.
   */
  model_key: string;
  identity_rule?: string;
  identity_confidence?: string;
  /**
   * Which AIBOM engines reported this model. One engine or three is the most
   * useful single fact on the row — three agreeing and one alone are different
   * degrees of evidence, and a reviewer is entitled to see which they have.
   */
  found_by: string[];
  /** Where it was referenced, as `path:line`. Empty when no engine said. */
  evidence: string[];
  /** True only when an engine confirmed the model resolves upstream. */
  verified: boolean;
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
  /**
   * ⚠ ADDED IN M2, AND ITS ABSENCE WAS A REAL GAP. The compliance profile marks
   * `certin.aibom.17.environmental_impact` user-supplied and the Python
   * normalizer always agreed; the Go service and this form did not, so the
   * element sat in the coverage denominator with no way for anyone to fill it.
   */
  environmental_impact: string;
  attestation_signature: string;
}

export function useAIModels(projectId: string | undefined) {
  return useQuery({
    queryKey: ['ai-models', projectId],
    queryFn: ({ signal }) =>
      request<{ ai_models: AIModel[]; ai_assets: AIAsset[] }>(
        `/v1/aibom/${projectId}/models`,
        { signal },
      ),
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
    mutationFn: ({ modelKey, fields }: { modelKey: string; fields: AIModelUserFields }) =>
      // ⚠ ENCODED, AND THAT MATTERS. A model key is `purl:pkg:huggingface/org/name`
      // — colons and slashes. The gateway preserves the escaping (see its
      // Rewrite hook, and the bug where it did not), so the upstream sees one
      // path segment rather than four.
      api.put<{ saved: boolean }>(
        `/v1/aibom/${projectId}/models/${encodeURIComponent(modelKey)}/fields`,
        fields,
      ),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ['ai-models', projectId] });
    },
  });
}

// ---------------------------------------------------------------------------
// Governance — consent, classification, attestation
// ---------------------------------------------------------------------------

export interface AIPolicy {
  llm_enrich_enabled: boolean;
  cisco_enabled: boolean;
  consent_recorded_by?: string;
  consent_recorded_at?: string;
  /**
   * ⚠ WHETHER THE CONSENT ACTUALLY CHANGES ANYTHING. Both engines need network
   * egress the scan sandbox does not have, so today consent is recorded and the
   * engines stay off. A toggle rendered without this would tell a customer
   * something started that did not.
   */
  effective: boolean;
  blocker?: string;
}

export interface ComplianceTag {
  model_key: string;
  eu_ai_act_tier?: string;
  nist_ai_rmf: string[];
  iso_42001: string[];
  rationale?: string;
  declared_by: string;
  updated_at: string;
}

export interface AIAttestation {
  model_key: string;
  verified: boolean;
  method: string;
  signer_identity?: string;
  signer_issuer?: string;
  digest?: string;
  failure_reason?: string;
  verified_at: string;
  recorded_by: string;
}

export function useAIPolicy(projectId: string | undefined) {
  return useQuery({
    queryKey: ['ai-policy', projectId],
    queryFn: ({ signal }) => request<AIPolicy>(`/v1/aibom/${projectId}/policy`, { signal }),
    enabled: Boolean(projectId),
  });
}

export function useSetAIPolicy(projectId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (policy: { llm_enrich_enabled: boolean; cisco_enabled: boolean }) =>
      api.put<AIPolicy>(`/v1/aibom/${projectId}/policy`, policy),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ['ai-policy', projectId] });
    },
  });
}

export function useComplianceTags(projectId: string | undefined) {
  return useQuery({
    queryKey: ['ai-tags', projectId],
    queryFn: ({ signal }) =>
      request<{
        tags: ComplianceTag[];
        vocabulary: { eu_ai_act_tier: string[]; nist_ai_rmf: string[]; iso_42001: string[] };
      }>(`/v1/aibom/${projectId}/tags`, { signal }),
    enabled: Boolean(projectId),
  });
}

export function useSaveComplianceTag(projectId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (tag: Partial<ComplianceTag> & { model_key: string }) =>
      api.put<{ saved: boolean }>(`/v1/aibom/${projectId}/tags`, tag),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ['ai-tags', projectId] });
    },
  });
}

export function useAIAttestations(projectId: string | undefined) {
  return useQuery({
    queryKey: ['ai-attestations', projectId],
    queryFn: ({ signal }) =>
      request<{ attestations: AIAttestation[] }>(`/v1/aibom/${projectId}/attestations`, { signal }),
    enabled: Boolean(projectId),
  });
}
