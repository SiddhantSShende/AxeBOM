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
  bom_types: Array<{
    id: string;
    requires_import: boolean;
    is_derived: boolean;
    /**
     * The project source types this BOM type can actually be registered from.
     *
     * ⚠ NOT EVERY SOURCE WORKS FOR EVERY TYPE, AND THE WIZARD USED TO ACT AS IF
     * IT DID. No AIBOM engine reads a `url` source, so an AIBOM project
     * registered from one produces an empty AIBOM forever — the dev database
     * contains exactly that row. The server now refuses the combination, so a
     * screen that keeps offering it turns a preventable choice into a 422 after
     * the form is filled.
     */
    sources: string[];
    /**
     * BOM types this one is derived from.
     *
     * ⚠ QBOM DERIVES FROM CBOM, AND NOTHING EVER SAID SO AT THE POINT OF THE
     * DECISION. The registration chip read "derived from CBOM", which states
     * the relationship and not the consequence: a project classified QBOM
     * without CBOM produces device metadata and a readiness section with no
     * cryptographic assets in it, permanently.
     */
    depends_on: string[];
    /** What this BOM type still needs once the project exists. */
    requirements: Array<{
      id: string;
      title: string;
      detail: string;
      at_registration: boolean;
      required: boolean;
    }>;
  }>;
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

/** How many pages useProjects will walk before giving up. */
const MAX_PROJECT_PAGES = 20;

/** The server's own clamp, mirrored so the request is explicit. */
const PROJECT_PAGE = 100;

export function useProjects() {
  return useQuery({
    queryKey: ['projects'],
    queryFn: async ({ signal }) => {
      // ⚠ THIS USED TO SEND NO LIMIT AND DISCARD next_cursor, SO IT SILENTLY
      // SHOWED THE FIRST 50 PROJECTS AND NOTHING ELSE.
      //
      // The response type already declared next_cursor; nothing read it. A
      // tenant with 60 projects saw 50, with no page control, no count and no
      // indication that anything was missing — and every BOM-type lens
      // (/sbom, /hbom, …) filters this same list client-side, so a project
      // could be absent from its own lens for no visible reason.
      //
      // Walking the pages rather than exposing a cursor is deliberate: this is
      // a catalogue the whole UI filters in memory, and a partial catalogue is
      // the bug. The bound exists so a runaway cursor cannot spin forever.
      const projects: Project[] = [];
      let cursor = '';

      for (let page = 0; page < MAX_PROJECT_PAGES; page++) {
        const q = new URLSearchParams({ limit: String(PROJECT_PAGE) });
        if (cursor) q.set('cursor', cursor);

        const data = await request<{ projects: Project[]; next_cursor?: string }>(
          `/v1/projects?${q.toString()}`,
          { signal },
        );
        projects.push(...data.projects);

        if (!data.next_cursor) return { projects, next_cursor: '' };
        cursor = data.next_cursor;
      }

      // ⚠ REPORTED, NOT SWALLOWED. Hitting the bound means the list is
      // incomplete, and a caller that cannot tell will render it as if it were
      // everything — the exact failure this whole change is fixing.
      return { projects, next_cursor: cursor };
    },
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

/**
 * useSetPractices takes the project id as part of the MUTATE call, not the
 * hook constructor.
 *
 * ⚠ THIS IS NOT A STYLE CHOICE. The wizard (ProjectWizard.tsx) does not know
 * the project's id until `createProject` resolves, and calls this in the same
 * synchronous continuation — `setState` never updates a value a closure
 * already captured, only what the NEXT render sees. A hook built as
 * `useSetPractices(createdId ?? '')` therefore stays bound to `''` for the
 * entire submit(), sending `PUT /v1/projects//practices` — which the server
 * 307-redirects to `/v1/projects/practices`, a URL that resolves to nothing
 * useful. Taking the id in the call lets the caller pass the just-resolved
 * `project.id` directly, with no render in between to go stale across.
 */
export function useSetPractices() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ projectId, ...input }: PracticesInput & { projectId: string }) =>
      request<Practices>(`/v1/projects/${projectId}/practices`, { method: 'PUT', body: input }),
    onSuccess: (data, variables) => {
      qc.setQueryData(['practices', variables.projectId], data);
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

// useConnectRepo, useCreateWebSource and useUploadFile all take the project
// id in the MUTATE call rather than the hook constructor, for the identical
// reason useSetPractices does — see its own comment. All three are called
// from ProjectWizard.tsx's submit(), in the same synchronous continuation
// right after `createProject` resolves and before any re-render.

export function useConnectRepo() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ projectId, ...input }: ConnectInput & { projectId: string }) =>
      request(`/v1/projects/${projectId}/connections`, { method: 'POST', body: input }),
    onSuccess: (_data, variables) => {
      void qc.invalidateQueries({ queryKey: ['connections', variables.projectId] });
    },
  });
}

export interface WebSourceInput {
  root_url: string;
  max_hosts?: number | undefined;
  discovery_disabled?: boolean | undefined;
}

export function useCreateWebSource() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ projectId, ...input }: WebSourceInput & { projectId: string }) =>
      request(`/v1/projects/${projectId}/web-sources`, { method: 'POST', body: input }),
    onSuccess: (_data, variables) => {
      void qc.invalidateQueries({ queryKey: ['web-sources', variables.projectId] });
    },
  });
}

export function useUploadFile() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ projectId, file, kind }: { projectId: string; file: File; kind: string }) => {
      const form = new FormData();
      form.append('file', file);
      form.append('kind', kind);
      return upload(`/v1/projects/${projectId}/uploads`, form);
    },
    onSuccess: (_data, variables) => {
      void qc.invalidateQueries({ queryKey: ['uploads', variables.projectId] });
    },
  });
}

export interface GitHubConnectionStatus {
  connected: boolean;
  github_login: string;
  connected_at: string;
}

/**
 * useGitHubConnection reports whether this ORGANISATION has connected GitHub.
 *
 * ⚠ TENANT-WIDE, NOT PER PROJECT, WHICH IS THE WHOLE CHANGE. Registration used
 * to run its own OAuth round trip every time: a popup, a token through the
 * browser, and a fresh authorisation for each project. Connecting once means
 * the token lives in Vault and the repo picker opens straight away.
 */
export function useGitHubConnection() {
  return useQuery({
    queryKey: ['github-connection'],
    queryFn: ({ signal }) => request<GitHubConnectionStatus>('/v1/github/connection', { signal }),
  });
}

/**
 * useSaveGitHubConnection stores the token the popup returned, once.
 *
 * PUT, not POST: reconnecting is the normal repair for an expired or revoked
 * authorisation and replaces the single connection an organisation has.
 */
export function useSaveGitHubConnection() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (input: { token: string; github_login?: string }) =>
      request<GitHubConnectionStatus>('/v1/github/connection', { method: 'PUT', body: input }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ['github-connection'] });
    },
  });
}

export function useDisconnectGitHub() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: () => request<void>('/v1/github/connection', { method: 'DELETE' }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ['github-connection'] });
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
        // ⚠ THE HEADER IS OMITTED WHEN THE ORGANISATION IS CONNECTED, and the
        // server reads its stored token instead. Sending a GitHub credential
        // from the browser on every keystroke of a repo search was the cost of
        // having nowhere to keep it; there is somewhere now.
        { ...(token ? { headers: { 'X-GitHub-Token': token } } : {}), signal },
      ),
    enabled,
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
