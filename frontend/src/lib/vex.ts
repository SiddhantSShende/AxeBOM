/**
 * VEX triage — POST/GET /v1/vex/{projectId}/statements.
 *
 * ⚠ PROJECT-SCOPED, NOT REPORT-SCOPED. A triage decision is a fact about a
 * project's vulnerability landscape that survives across re-scans — see
 * services/scan-orchestrator/internal/orchestr/vex_store.go's own doc
 * comment for why the write path is designed this way.
 *
 * ⚠ SUPERSESSION IS AUTOMATIC. There is no "supersedes" field to fill in —
 * the server finds whichever statement is currently in force for the exact
 * (cluster, component, scope) tuple and supersedes it. Submitting a new
 * statement for the same tuple is how a decision changes.
 */

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { api, request } from './api';

export const VEX_STATUSES = ['affected', 'not_affected', 'fixed', 'under_investigation'] as const;
export type VEXStatus = (typeof VEX_STATUSES)[number];

export const VEX_SCOPES = ['project', 'component', 'version'] as const;
export type VEXScope = (typeof VEX_SCOPES)[number];

export const VEX_JUSTIFICATIONS = [
  'component_not_present',
  'vulnerable_code_not_present',
  'vulnerable_code_not_in_execute_path',
  'vulnerable_code_cannot_be_controlled_by_adversary',
  'inline_mitigations_already_exist',
] as const;

export interface VEXStatement {
  id: string;
  component_key?: string;
  cluster_id: string;
  status: VEXStatus;
  scope: VEXScope;
  justification?: string;
  remediation?: string;
  workarounds?: string;
  downtime?: string;
  version: number;
  superseded_by?: string;
  author_user_id?: string;
  created_at: string;
}

export interface CreateVEXStatementInput {
  component_key?: string;
  cluster_id: string;
  status: VEXStatus;
  scope: VEXScope;
  justification?: string;
  remediation?: string;
  workarounds?: string;
  downtime?: string;
}

export function useVEXHistory(projectId: string, clusterId: string, componentKey: string) {
  return useQuery({
    queryKey: ['vex-history', projectId, clusterId, componentKey],
    queryFn: ({ signal }) =>
      request<{ statements: VEXStatement[] }>(
        `/v1/vex/${projectId}/statements?cluster_id=${encodeURIComponent(clusterId)}` +
          `&component_key=${encodeURIComponent(componentKey)}`,
        { signal },
      ),
    enabled: Boolean(projectId && clusterId),
  });
}

export function useCreateVEXStatement(projectId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (input: CreateVEXStatementInput) =>
      api.post<VEXStatement>(`/v1/vex/${projectId}/statements`, input),
    onSuccess: (_data, variables) => {
      void qc.invalidateQueries({ queryKey: ['findings', projectId] });
      void qc.invalidateQueries({
        queryKey: ['vex-history', projectId, variables.cluster_id, variables.component_key ?? ''],
      });
    },
  });
}
