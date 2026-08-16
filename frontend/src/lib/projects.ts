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
    queryFn: () => request<ProjectOptions>('/v1/projects/options'),
    // The profile changes on a release boundary, not during a session.
    staleTime: 60 * 60 * 1000,
  });
}

export function useProjects() {
  return useQuery({
    queryKey: ['projects'],
    queryFn: () => request<{ projects: Project[]; next_cursor: string }>('/v1/projects'),
  });
}

export function useProject(id: string | undefined) {
  return useQuery({
    queryKey: ['project', id],
    queryFn: () => request<Project>(`/v1/projects/${id}`),
    enabled: Boolean(id),
  });
}

export function usePractices(projectId: string | undefined) {
  return useQuery({
    queryKey: ['practices', projectId],
    queryFn: () => request<Practices>(`/v1/projects/${projectId}/practices`),
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
 * useRepoSearch lists the signed-in user's GitHub repositories.
 *
 * The token travels in a header per request and is never persisted by the
 * frontend — connecting a repository is what stores it, and it goes to Vault.
 */
export function useRepoSearch(token: string, query: string, enabled: boolean) {
  return useQuery({
    queryKey: ['github-repos', query],
    queryFn: () =>
      request<{ repos: Repo[]; next_page?: number }>(
        `/v1/github/repos?q=${encodeURIComponent(query)}`,
        { headers: { 'X-GitHub-Token': token } },
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
