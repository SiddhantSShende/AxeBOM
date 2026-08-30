/**
 * Scan API types and queries.
 *
 * `GET /v1/scans` is keyset-paginated and returns `next_cursor` (see
 * services/scan-orchestrator/internal/handler/handler.go) — so this is an
 * infinite query, not a page-number one. `OFFSET` is a table scan at these
 * volumes (docs/07-FRONTEND-SPEC.md §8).
 */

import { useInfiniteQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { request } from './api';

export interface EngineRun {
  engine: string;
  status: string;
  ecosystems?: string[] | undefined;
  duration_ms?: number | undefined;
  note?: string | undefined;
}

/**
 * ⚠ THERE IS NO `findings_count` ON A LIST ROW, AND THAT IS DELIBERATE.
 *
 * The server leaves the key out rather than sending a zero it never computed —
 * a zero here would read as "nothing wrong" for a scan that simply has not
 * been counted, which is the false negative CLAUDE.md invariant 12 exists to
 * prevent. `GET /v1/scans/{id}/findings-summary` is where the real answer is.
 */
export interface ScanListItem {
  id: string;
  project_id: string;
  status: string;
  source_kind: string;
  commit_sha?: string | undefined;
  families: string[];
  engines_requested: string[];
  progress_pct: number;
  engine_runs: EngineRun[];
  created_at: string;
  started_at?: string | undefined;
  finished_at?: string | undefined;
}

interface ScanPage {
  scans: ScanListItem[];
  next_cursor?: string | undefined;
}

export function useScans(projectId: string | undefined, limit = 50) {
  return useInfiniteQuery({
    queryKey: ['scans', projectId ?? null],
    enabled: Boolean(projectId),
    initialPageParam: '',
    queryFn: ({ pageParam, signal }) => {
      const q = new URLSearchParams({ limit: String(limit) });
      if (projectId) q.set('project_id', projectId);
      if (pageParam) q.set('cursor', pageParam);
      return request<ScanPage>(`/v1/scans?${q.toString()}`, { signal });
    },
    // An empty string and an absent key both mean "no more pages"; returning
    // either as a cursor would make the query fetch the first page forever.
    getNextPageParam: (last) => last.next_cursor || undefined,
  });
}

/**
 * A running scan can be stopped.
 *
 * The endpoint has existed since Phase 6 with no caller. Wiring it here is the
 * difference between a user waiting out a scan they know is wrong and one they
 * can abandon.
 */
export function useCancelScan(projectId: string | undefined) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (scanId: string) => request<void>(`/v1/scans/${scanId}/cancel`, { method: 'POST' }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ['scans', projectId ?? null] });
    },
  });
}

/**
 * Terminal scans never change again, so they are safe to treat as immutable.
 *
 * ⚠ MUST MATCH scan.scans' real status vocabulary — `scans_status_check` in
 * the migrations, and `isTerminal` in
 * services/scan-orchestrator/internal/handler/handler.go. This previously
 * checked 'succeeded'/'partial', neither of which is a status this system
 * ever produces (the real values are 'completed'/'completed_with_errors'),
 * so it silently returned false — "still running" — for the two most common
 * terminal outcomes, forever. ProjectScans.tsx's "running" indicator never
 * cleared for a scan that had already finished.
 */
export function isTerminal(status: string): boolean {
  return ['completed', 'completed_with_errors', 'failed', 'cancelled'].includes(status);
}
