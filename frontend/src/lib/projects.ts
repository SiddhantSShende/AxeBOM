/**
 * Project API types and queries.
 *
 * The enums here are FETCHED, not declared. `/v1/projects/options` serves the
 * SDLC stages, BOM depth levels and practice sub-elements straight from the
 * compliance profile, so a CERT-In revision changes the UI without a frontend
 * release — and, more to the point, the frontend cannot drift from the profile
 * by hardcoding a list that was accurate the day it was written.
 */

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { request, upload } from './api';

export interface Owner {
  name?: string | undefined;
  email?: string | undefined;
  github?: string | undefined;
  phone?: string | undefined;
}

export interface Project {
  id: string;
  name: string;
  description?: string | undefined;
  source_type: string;
  sdlc_stage: string;
  validity_start?: string | undefined;
  validity_end?: string | undefined;
  owner: Owner;
  classifications: string[];
  created_at: string;
  updated_at: string;
}

export interface PracticeGap {
  field_id: string;
  name: string;
  reason: string;
}

export interface Practices {
  frequency: string | null;
  depth: string | null;
  known_unknowns: string | null;
  distribution: string | null;
  access_control: string | null;
  errata_policy: string | null;
  compliance: {
    recorded: number;
    total: number;
    complete: boolean;
    gaps: PracticeGap[];
    note: string;
  };
}

export interface ProjectOptions {
  bom_types: Array<{ id: string; requires_import: boolean; is_derived: boolean }>;
  sdlc_stages: string[];
  bom_depths: string[];
  source_types: string[];
  practices: Array<{ id: string; name: string }>;
}

export interface Repo {
  external_id: string;
  full_name: string;
  name: string;
  private: boolean;
  clone_url: string;
  default_branch: string;
  description?: string | undefined;
}

// ---------------------------------------------------------------------------
// Queries
// ---------------------------------------------------------------------------

export function useProjectOptions() {
  return useQuery({
    queryKey: ['project-options'],
    queryFn: ({ signal }) => request<ProjectOptions>('/v1/projects/options', { signal }),
    // The profile changes on a release boundary, not during a session.
    staleTime: 60 * 60 * 1000,
  });
}

export function useProjects() {
  return useQuery({
    queryKey: ['projects'],
    queryFn: ({ signal }) =>
      request<{ projects: Project[]; next_cursor: string }>('/v1/projects', { signal }),
  });
}

export function useProject(id: string | undefined) {
  return useQuery({
    queryKey: ['project', id],
    queryFn: ({ signal }) => request<Project>(`/v1/projects/${id}`, { signal }),
    enabled: Boolean(id),
  });
}

export function usePractices(projectId: string | undefined) {
  return useQuery({
    queryKey: ['practices', projectId],
    queryFn: ({ signal }) => request<Practices>(`/v1/projects/${projectId}/practices`, { signal }),
    enabled: Boolean(projectId),
  });
}

export interface CreateProjectInput {
  name: string;
  description?: string | undefined;
  source_type: string;
  sdlc_stage?: string | undefined;
  validity_start?: string | null | undefined;
  validity_end?: string | null | undefined;
  owner: Owner;
  classifications: string[];
}

export function useCreateProject() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (input: CreateProjectInput) =>
      request<Project>('/v1/projects', { method: 'POST', body: input }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ['projects'] });
    },
  });
}

/**
 * UpdateProjectInput is CreateProjectInput minus `source_type`.
 *
 * ⚠ THE SOURCE IS IMMUTABLE AFTER CREATION, AND THE SERVER IS THE REASON.
 * `projectRequest` still parses `source_type` on a PUT, but
 * `services/project/internal/handler/handler.go` never passes it to
 * `svc.Update` — so sending it looks accepted and changes nothing. Offering
 * the field in a settings form would be a control that silently does nothing,
 * which is worse than not offering it.
 */
export type UpdateProjectInput = Omit<CreateProjectInput, 'source_type'>;

export function useUpdateProject(projectId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (input: UpdateProjectInput) =>
      request<Project>(`/v1/projects/${projectId}`, { method: 'PUT', body: input }),
    onSuccess: (data) => {
      // Seed the detail cache from the response rather than refetching it: the
      // server just told us the new state, and a refetch would show the old
      // one for a frame.
      qc.setQueryData(['project', projectId], data);
      void qc.invalidateQueries({ queryKey: ['projects'] });
    },
  });
}

export interface PracticesInput {
  frequency?: string | undefined;
  depth?: string | undefined;
  known_unknowns?: string | undefined;
  distribution?: string | undefined;
  access_control?: string | undefined;
  errata_policy?: string | undefined;
}

export function useSetPractices(projectId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (input: PracticesInput) =>
      request<Practices>(`/v1/projects/${projectId}/practices`, { method: 'PUT', body: input }),
    onSuccess: (data) => {
      qc.setQueryData(['practices', projectId], data);
    },
  });
}

export interface ConnectInput {
  provider: string;
  repo_url?: string | undefined;
  repo_full_name?: string | undefined;
  repo_external_id: string;
  default_branch?: string | undefined;
  token?: string | undefined;
}

export function useConnectRepo(projectId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (input: ConnectInput) =>
      request(`/v1/projects/${projectId}/connections`, { method: 'POST', body: input }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ['connections', projectId] });
    },
  });
}

export interface WebSourceInput {
  root_url: string;
  max_hosts?: number | undefined;
  discovery_disabled?: boolean | undefined;
}

export function useCreateWebSource(projectId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (input: WebSourceInput) =>
      request(`/v1/projects/${projectId}/web-sources`, { method: 'POST', body: input }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ['web-sources', projectId] });
    },
  });
}

export function useUploadFile(projectId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ file, kind }: { file: File; kind: string }) => {
      const form = new FormData();
      form.append('file', file);
      form.append('kind', kind);
      return upload(`/v1/projects/${projectId}/uploads`, form);
    },
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ['uploads', projectId] });
    },
  });
}

/**
 * useGitHubConnect opens the repo-scoped "connect" popup and resolves with
 * the token GitHubConnectCallback relays back via postMessage.
 *
 * A popup, not a full-page redirect: the wizard's Draft lives only in
 * component state with no persistence, and a full-page OAuth round trip
 * would discard whatever the user had already filled in on the way there.
 *
 * The token this resolves with is handed straight to useRepoSearch and,
 * eventually, useConnectRepo — never stored here, never read back out of
 * this hook after the popup closes.
 */
export function useGitHubConnect() {
  return useMutation({
    mutationFn: () =>
      new Promise<string>((resolve, reject) => {
        const popup = window.open(
          '/api/v1/auth/github/connect/authorize',
          'axebom-github-connect',
          'width=600,height=700',
        );
        if (!popup) {
          reject(
            new Error(
              'The GitHub connect window was blocked. Allow popups for this site and try again.',
            ),
          );
          return;
        }

        let settled = false;
        function cleanup() {
          window.removeEventListener('message', onMessage);
          window.clearInterval(closedCheck);
        }

        function onMessage(event: MessageEvent) {
          // Both directions of the origin check matter: GitHubConnectCallback
          // posts only to this origin, and this listener accepts only from
          // it — an embedded frame on an unrelated page must not be able to
          // hand this tab a token it never asked for.
          if (event.origin !== window.location.origin) return;
          const data = event.data as { type?: unknown; token?: unknown } | null;
          if (data?.type !== 'axebom-github-connect') return;

          settled = true;
          cleanup();
          if (typeof data.token === 'string' && data.token) {
            resolve(data.token);
          } else {
            reject(new Error('GitHub did not return a usable token.'));
          }
        }
        window.addEventListener('message', onMessage);

        // The popup can be closed by hand before it ever calls back — without
        // this the mutation hangs forever with no way to retry.
        const closedCheck = window.setInterval(() => {
          if (popup.closed && !settled) {
            cleanup();
            reject(new Error('The GitHub connect window was closed before finishing.'));
          }
        }, 500);
      }),
  });
}

/**
 * useRepoSearch lists the signed-in user's GitHub repositories.
 *
 * The token travels in a header per request and is never persisted by the
 * frontend — connecting a repository is what stores it, and it goes to Vault.
 */
export function useRepoSearch(token: string, query: string, enabled: boolean) {
  return useQuery({
    queryKey: ['github-repos', query],
    queryFn: ({ signal }) =>
      request<{ repos: Repo[]; next_page?: number }>(
        `/v1/github/repos?q=${encodeURIComponent(query)}`,
        { headers: { 'X-GitHub-Token': token }, signal },
      ),
    enabled: enabled && token.length > 0,
  });
}

// ---------------------------------------------------------------------------
// Display helpers
// ---------------------------------------------------------------------------

/** humanizeEnum turns a profile id like `top_level` into "Top level". */
export function humanizeEnum(value: string): string {
  const spaced = value.replace(/_/g, ' ');
  return spaced.charAt(0).toUpperCase() + spaced.slice(1);
}

/**
 * validityWarning reports whether a validity window needs attention.
 *
 * A BOM whose validity has lapsed is not a minor display concern: it is a
 * compliance document asserting a period that has passed, so the list warns
 * inside 30 days rather than at expiry.
 */
export function validityWarning(end: string | undefined, now = new Date()): string | null {
  if (!end) return null;
  const endDate = new Date(`${end}T00:00:00Z`);
  const days = Math.ceil((endDate.getTime() - now.getTime()) / 86_400_000);
  if (days < 0)
    return `Validity lapsed ${Math.abs(days)} day${Math.abs(days) === 1 ? '' : 's'} ago`;
  if (days <= 30) return `Validity ends in ${days} day${days === 1 ? '' : 's'}`;
  return null;
}
