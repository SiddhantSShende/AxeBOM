/**
 * Campaign API types, queries, and the schedule-preset vocabulary.
 *
 * ⚠ THE PRESETS ARE A CONVENIENCE OVER CRON, NOT A REPLACEMENT FOR IT.
 *
 * Most people want "every night" and should not have to learn `30 2 * * *`. But
 * a preset-only UI is a trap: the moment somebody needs "weekdays at 6am" they
 * discover the product cannot express it, and a schedule they cannot read is a
 * schedule they cannot audit. So the wizard shows presets, shows the cron each
 * one produces, and lets the expression be edited directly — the preset list
 * derives FROM cron rather than hiding it.
 */

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { request } from './api';

export interface Campaign {
  id: string;
  name: string;
  project_ids: string[];
  cron_expr: string;
  timezone: string;
  bom_types: string[];
  report_levels: string[];
  standards: string[];
  formats: string[];
  enabled: boolean;
  next_run_at?: string | undefined;
  last_run_at?: string | undefined;
  created_at: string;
  updated_at: string;
}

export interface CampaignRun {
  id: string;
  campaign_id: string;
  scheduled_for: string;
  started_at?: string | undefined;
  finished_at?: string | undefined;
  status: 'pending' | 'running' | 'completed' | 'completed_with_errors' | 'failed' | 'skipped';
  /**
   * ⚠ RENDERED WHEREVER A SKIPPED RUN IS SHOWN. A gap in run history with no
   * explanation is barely better than no row at all; the reason is the whole
   * point of recording a missed occurrence.
   */
  skip_reason?: string | undefined;
  scan_ids: string[];
  error?: string | undefined;
}

export interface CampaignInput {
  name: string;
  project_ids: string[];
  cron_expr: string;
  timezone: string;
  bom_types: string[];
  report_levels: string[];
  standards: string[];
  formats: string[];
  enabled: boolean;
}

// ---------------------------------------------------------------------------
// Presets
// ---------------------------------------------------------------------------

export interface SchedulePreset {
  id: string;
  label: string;
  cron: string;
  /** What it actually does, in words, for the confirmation step. */
  description: string;
}

/**
 * The presets offered in the wizard.
 *
 * ⚠ NONE OF THEM RUN AT MIDNIGHT OR ON THE HOUR. `0 0 * * *` is what everyone
 * reaches for, and it is why every scheduler in the world has a thundering herd
 * at midnight — ours included, since a campaign fires scans against shared
 * infrastructure. Offsetting into the small hours spreads the load and costs
 * the customer nothing.
 */
export const SCHEDULE_PRESETS: SchedulePreset[] = [
  {
    id: 'daily',
    label: 'Every day',
    cron: '30 2 * * *',
    description: 'at 02:30 every day',
  },
  {
    id: 'weekdays',
    label: 'Weekdays',
    cron: '30 2 * * 1-5',
    description: 'at 02:30, Monday to Friday',
  },
  {
    id: 'weekly',
    label: 'Every week',
    cron: '30 3 * * 0',
    description: 'at 03:30 every Sunday',
  },
  {
    id: 'monthly',
    label: 'Every month',
    cron: '30 3 1 * *',
    description: 'at 03:30 on the 1st of each month',
  },
];

/** matchPreset finds the preset a cron expression corresponds to, if any. */
export function matchPreset(cron: string): SchedulePreset | undefined {
  const normalized = cron.trim().replace(/\s+/g, ' ');
  return SCHEDULE_PRESETS.find((p) => p.cron === normalized);
}

/**
 * describeCron renders an expression in words where it can, and says so plainly
 * where it cannot.
 *
 * ⚠ IT NEVER GUESSES. A wrong plain-English rendering of a schedule is worse
 * than none: somebody reads "every day at 2:30am", believes it, and never
 * checks the expression that actually says something else. Unrecognised
 * expressions are shown verbatim with an honest label.
 */
export function describeCron(cron: string): string {
  const preset = matchPreset(cron);
  if (preset) return preset.description;
  return `on the schedule ${cron.trim()}`;
}

/**
 * validateCron is a SHAPE check only, mirroring the server's field count.
 *
 * ⚠ THE SERVER IS THE AUTHORITY. This exists so a typo is caught before a round
 * trip, not so the client can decide what is valid — a client-side validator
 * that disagrees with the server produces either a form that rejects valid
 * input or one that accepts input the server refuses.
 */
export function validateCron(cron: string): string | null {
  const fields = cron.trim().split(/\s+/);
  if (cron.trim() === '') return 'A schedule is required.';
  if (fields.length !== 5) {
    return `A cron expression has 5 fields (minute hour day-of-month month day-of-week); this has ${fields.length}.`;
  }
  return null;
}

/**
 * browserTimezone is the default offered in the wizard.
 *
 * ⚠ AN IANA NAME, NEVER AN OFFSET. An offset is correct for half the year, and
 * which half depends on the zone — a campaign stored as "+05:30" is simply
 * wrong in every zone that observes DST.
 */
export function browserTimezone(): string {
  try {
    return Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC';
  } catch {
    return 'UTC';
  }
}

// ---------------------------------------------------------------------------
// Queries
// ---------------------------------------------------------------------------

export function useCampaigns() {
  return useQuery({
    queryKey: ['campaigns'],
    queryFn: () => request<{ campaigns: Campaign[] }>('/v1/campaigns'),
    select: (d) => d.campaigns,
  });
}

export function useCampaign(id: string) {
  return useQuery({
    queryKey: ['campaigns', id],
    queryFn: () => request<Campaign>(`/v1/campaigns/${id}`),
    enabled: id !== '',
  });
}

export function useCampaignRuns(id: string) {
  return useQuery({
    queryKey: ['campaigns', id, 'runs'],
    queryFn: () => request<{ runs: CampaignRun[] }>(`/v1/campaigns/${id}/runs`),
    select: (d) => d.runs,
    enabled: id !== '',
  });
}

export function useCreateCampaign() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (input: CampaignInput) =>
      request<Campaign>('/v1/campaigns', { method: 'POST', body: input }),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ['campaigns'] }),
  });
}

export function useSetCampaignEnabled() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, enabled }: { id: string; enabled: boolean }) =>
      request<Campaign>(`/v1/campaigns/${id}/enabled`, {
        method: 'POST',
        body: { enabled },
      }),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ['campaigns'] }),
  });
}

export function useDeleteCampaign() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => request<void>(`/v1/campaigns/${id}`, { method: 'DELETE' }),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ['campaigns'] }),
  });
}

export function useRunCampaignNow() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) =>
      request<{ run_id: string; scan_ids: string[] }>(`/v1/campaigns/${id}/run`, {
        method: 'POST',
      }),
    onSuccess: (_data, id) => {
      void qc.invalidateQueries({ queryKey: ['campaigns', id, 'runs'] });
      void qc.invalidateQueries({ queryKey: ['campaigns'] });
    },
  });
}
