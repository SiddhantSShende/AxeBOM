/**
 * The engine registry — what can run, and (given a project) what has.
 *
 * ⚠ THIS IS THE HONEST-LABEL SOURCE, NOT UI COPY. `requires_import` and
 * `is_derived` come from `services/scan-orchestrator/internal/policy/registry.go`
 * as data, the same discipline `design/theme.ts`'s BOM_TYPES follows — a label
 * hand-typed twice drifts once.
 */

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { api, request } from './api';
import type { BomType } from '../design/theme';

export interface EngineLastRun {
  scan_id: string;
  status: string;
  started_at?: string | undefined;
  finished_at?: string | undefined;
  error_code?: string | undefined;
}

export interface EngineInfo {
  engine_id: string;
  /** "container" | "pip" | "internal". */
  mode: string;
  families: string[];
  source_kinds: string[];
  ecosystems: string[];
  produces: string[];
  db_backed: boolean;
  default_weight: number;
  requires_import?: boolean | undefined;
  is_derived?: boolean | undefined;
  /**
   * Present only when the request named a project. Absent means "no request
   * was scoped to a project" — a DIFFERENT fact from `never run`, which is a
   * project scoped correctly but with no matching row (see
   * EngineCoveragePanel, which is the one place this distinction matters).
   */
  last_run?: EngineLastRun | undefined;
  /**
   * What a PERSON has to do for this engine to have anything to read.
   *
   * ⚠ ABSENT FOR EVERY ENGINE THAT JUST RUNS, and present for the ones that
   * parse a file the customer produces on the device they want documented.
   * Until this existed the instruction lived only in a YAML file no browser
   * reads and in an adapter hint shown AFTER a scan had already found nothing —
   * so nobody could learn the feature existed, let alone how to use it.
   */
  operator_action?: string | undefined;
}

/**
 * useEngines lists the registry, optionally enriched with one project's most
 * recent run of each engine.
 *
 * `family` filters client-side rather than adding a server parameter: the
 * registry is small (a dozen engines) and static for the lifetime of a page
 * view, so a second round trip per BOM type would cost more than it saves.
 */
export function useEngines(projectId?: string, family?: BomType) {
  const query = useQuery({
    queryKey: ['engines', projectId ?? null],
    queryFn: ({ signal }) => {
      const q = projectId ? `?project_id=${encodeURIComponent(projectId)}` : '';
      return request<{ engines: EngineInfo[] }>(`/v1/scans/engines${q}`, { signal });
    },
    staleTime: 30_000,
  });

  const engines = family
    ? query.data?.engines.filter((e) => e.families.includes(family.toLowerCase()))
    : query.data?.engines;

  return { ...query, engines };
}

// ---------------------------------------------------------------------------
// Engine policy — configurable tool management (Admin only; the server is
// the real gate, RoleEngine:configure_engines in libs/go-shared/authz).
// ---------------------------------------------------------------------------

export interface EnginePolicy {
  family: string;
  engine_ids: string[];
  weights: Record<string, number>;
  enabled: boolean;
  note?: string | undefined;
}

/**
 * useEnginePolicies lists only the families this tenant has customised.
 *
 * ⚠ AN ABSENT FAMILY MEANS "USE THE BUILT-IN DEFAULT", NOT "NOTHING RUNS".
 * The settings screen must render all five BOM types from BOM_TYPES and treat
 * one missing from this list as "default", matching
 * `scan.engine_policy`'s own documented convention — never as a blank/broken
 * row.
 */
export function useEnginePolicies() {
  return useQuery({
    queryKey: ['engine-policies'],
    queryFn: ({ signal }) =>
      request<{ engine_policies: EnginePolicy[] }>('/v1/scans/engine-policy', { signal }),
    staleTime: 10_000,
  });
}

export interface EnginePolicyInput {
  family: string;
  engine_ids: string[];
  weights?: Record<string, number>;
  enabled: boolean;
  note?: string;
}

export function useUpsertEnginePolicy() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (input: EnginePolicyInput) =>
      api.put<EnginePolicy>(`/v1/scans/engine-policy/${input.family.toLowerCase()}`, {
        engine_ids: input.engine_ids,
        weights: input.weights ?? {},
        enabled: input.enabled,
        note: input.note ?? '',
      }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ['engine-policies'] });
    },
  });
}

/** useResetEnginePolicy removes a tenant's override, reverting to default. */
export function useResetEnginePolicy() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (family: string) =>
      api.del<void>(`/v1/scans/engine-policy/${family.toLowerCase()}`),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ['engine-policies'] });
    },
  });
}
