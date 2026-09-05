/**
 * Report API types and queries.
 *
 * ⚠ TWO LIMITS IN THE SERVER CONTRACT THAT THIS MODULE DOES NOT HIDE.
 *
 * 1. `GET /v1/reports` returns `{"reports": [...]}` with NO `next_cursor`
 *    (services/report/internal/handler/handler.go). It accepts a `cursor`
 *    parameter that a client has no way to learn, so the list is effectively
 *    single-page. `useReports` exposes `truncated` rather than paginating a
 *    cursor it cannot obtain — a list that silently stops at N looks complete.
 *
 * 2. `reportResponse` carries `scan_id` but no `project_id` and no project
 *    name, so reports cannot be grouped by project from this endpoint alone.
 *    `useReportsWithProject` joins through the scan list to recover it. That
 *    join belongs on the server; until it moves there, doing it here is honest
 *    and doing it nowhere would ship a reports screen that cannot say which
 *    project a report belongs to.
 */

import { useQuery } from '@tanstack/react-query';
import { request } from './api';
import { useScans } from './scans';
import { useProjects } from './projects';

export interface FieldCoverage {
  field_id: string;
  name: string;
  present: number;
  declared: number;
  total: number;
  weight: number;
  source_page: number;
}

export interface EngineCoverage {
  engine_id: string;
  version: string;
  status: string;
  database_version: string;
  ecosystems: string[];
  diagnostic: string;
}

export interface ReportSibling {
  id: string;
  format: string;
  status: string;
}

export interface Report {
  id: string;
  scan_id: string;
  bom_type: string;
  level: string;
  standard: string;
  format: string;
  visibility: 'public' | 'private';
  status: 'queued' | 'rendering' | 'ready' | 'failed';
  sha256?: string | undefined;
  size_bytes?: number | undefined;
  signing_key_id?: string | undefined;
  truncated: boolean;
  truncation_note?: string | undefined;
  error_code?: string | undefined;
  created_at: string;
  updated_at: string;

  // ⚠ ALL OPTIONAL, AND ABSENT — NEVER 0/false/[] — UNTIL THIS REPORT REACHES
  // `ready`. Captured once at render completion from the exact BOM that
  // produced the artifact (services/report/internal/worker's Completion);
  // a queued or rendering report has none of it yet. See
  // migrations/report/0003_report_summary.sql.
  project_name?: string | undefined;
  generated_at?: string | undefined;
  level_note?: string | undefined;
  completeness_pct?: number | undefined;
  declaration_pct?: number | undefined;
  coverage_formula?: string | undefined;
  coverage_fields?: FieldCoverage[] | undefined;
  engines?: EngineCoverage[] | undefined;
  ecosystems_with_no_engine?: string[] | undefined;
  /** Populated only by GET /v1/reports/{id}, never by the list endpoint. */
  siblings?: ReportSibling[] | undefined;
}

const PAGE = 100;

export function useReports(scanId?: string) {
  return useQuery({
    queryKey: ['reports', scanId ?? null],
    queryFn: async ({ signal }) => {
      const q = new URLSearchParams({ limit: String(PAGE) });
      if (scanId) q.set('scan_id', scanId);
      const data = await request<{ reports: Report[]; next_cursor?: string }>(
        `/v1/reports?${q.toString()}`,
        { signal },
      );
      return {
        reports: data.reports,
        // ⚠ THE SERVER CAN TELL US NOW. It always paged correctly but never
        // returned next_cursor, so this had to infer "there is more" from a
        // full page — which is wrong in both directions: a listing of exactly
        // PAGE reports claimed truncation, and there was no way to fetch the
        // rest even when it was right.
        truncated: Boolean(data.next_cursor) || data.reports.length >= PAGE,
      };
    },
    // ⚠ SAME REASONING AS useReport's OWN INTERVAL, APPLIED TO A LIST. A
    // report queued right after its scan can finish rendering seconds later
    // (worker.go resolves the normalized BOM at render time, not scan time) —
    // a caller watching a scan's reports for a download link to appear needs
    // this to actually refetch, not just be correct on first load. Stops the
    // moment every report in the page is terminal, so a finished list never
    // polls forever.
    refetchInterval: (q) => {
      const reports = q.state.data?.reports;
      if (!reports) return 3000;
      const stillWorking = reports.some((r) => r.status === 'queued' || r.status === 'rendering');
      return stillWorking ? 3000 : false;
    },
  });
}

export function useReport(id: string | undefined) {
  return useQuery({
    queryKey: ['report', id],
    enabled: Boolean(id),
    queryFn: ({ signal }) => request<Report>(`/v1/reports/${id}`, { signal }),
    // ⚠ POLL WHILE RENDERING, THEN STOP FOREVER. A finished report is
    // immutable, so refetching one costs a request and can never change an
    // answer; an unfinished one has to be watched or the viewer lies about
    // its state.
    refetchInterval: (q) =>
      q.state.data?.status === 'ready' || q.state.data?.status === 'failed' ? false : 3000,
    staleTime: 0,
  });
}

export interface ReportWithProject extends Report {
  project_id?: string | undefined;
  project_name?: string | undefined;
}

/**
 * Reports, with the owning project recovered by joining through scans.
 *
 * The join is best-effort by construction: a report whose scan is older than
 * the scan page we fetched keeps `project_id` undefined, and the UI renders
 * that as unknown rather than guessing.
 */
export function useReportsWithProject() {
  const reports = useReports();
  const scans = useScans(undefined, 200);
  const projects = useProjects();

  const scanToProject = new Map<string, string>();
  for (const page of scans.data?.pages ?? []) {
    for (const s of page.scans) scanToProject.set(s.id, s.project_id);
  }
  const projectName = new Map<string, string>();
  for (const p of projects.data?.projects ?? []) projectName.set(p.id, p.name);

  const rows: ReportWithProject[] = (reports.data?.reports ?? []).map((r) => {
    const projectId = scanToProject.get(r.scan_id);
    return {
      ...r,
      project_id: projectId,
      project_name: projectId ? projectName.get(projectId) : undefined,
    };
  });

  return {
    rows,
    truncated: reports.data?.truncated ?? false,
    isPending: reports.isPending,
    isError: reports.isError,
    error: reports.error,
    /** True while the project names are still arriving; rows render regardless. */
    joinPending: scans.isPending || projects.isPending,
  };
}

/** Bytes as a short human string. Returns null when the server sent no size. */
export function formatBytes(n: number | undefined): string | null {
  if (n === undefined || n === null) return null;
  if (n < 1024) return `${n} B`;
  const units = ['KB', 'MB', 'GB'];
  let v = n / 1024;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v < 10 ? v.toFixed(1) : Math.round(v)} ${units[i]}`;
}

/** levelLabel is the human label for a report's `level` column. */
export function levelLabel(level: string): string {
  return level === 'top_level' ? 'Top-Level' : level === 'complete' ? 'Complete' : level;
}
