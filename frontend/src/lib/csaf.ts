/**
 * CSAF 2.0 advisories — POST/GET /v1/csaf/{projectId}/advisories.
 *
 * ⚠ CSAF FOLLOWS VEX. A generate request names an EXISTING vex_statement_id
 * — there is no way to publish an advisory that was not already triaged,
 * matching CERT-In's own discovery -> VEX -> CSAF sequence (p.35 Figure 7).
 * Generating twice for the same statement returns the same advisory rather
 * than publishing a duplicate.
 */

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { api, request } from './api';

export interface CSAFAdvisory {
  id: string;
  vex_statement_id: string;
  tracking_id: string;
  description?: string;
  severity?: string;
  mitigation_steps?: string;
  published_at?: string;
  document: Record<string, unknown>;
  created_at: string;
}

export interface GenerateCSAFAdvisoryInput {
  vex_statement_id: string;
  cluster_display_id: string;
  cluster_aliases: string[];
  component_name: string;
  component_purl: string;
}

export function useCSAFAdvisories(projectId: string | undefined) {
  return useQuery({
    queryKey: ['csaf-advisories', projectId],
    queryFn: ({ signal }) =>
      request<{ advisories: CSAFAdvisory[] }>(`/v1/csaf/${projectId}/advisories`, { signal }),
    enabled: Boolean(projectId),
  });
}

export function useGenerateCSAFAdvisory(projectId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (input: GenerateCSAFAdvisoryInput) =>
      api.post<CSAFAdvisory>(`/v1/csaf/${projectId}/advisories`, input),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ['csaf-advisories', projectId] });
    },
  });
}
