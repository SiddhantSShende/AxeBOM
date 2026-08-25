/**
 * Threaded comments on a report — GET/POST/PUT/DELETE /v1/comments.
 *
 * ⚠ MENTIONS ARE COMPUTED SERVER-SIDE, AT READ TIME, FROM THE BODY TEXT —
 * never stored, never resolved to a real member. See the comment service's
 * ParseMentions doc for why this is scoped down to raw `@handle` tokens.
 *
 * ⚠ A DELETED COMMENT IS NEVER REMOVED FROM THE LIST. Its body becomes the
 * literal string "[deleted]" server-side and `deleted: true` travels with
 * it, so a thread with live replies under a deleted comment never orphans
 * them — see CommentRail.tsx's rendering of `deleted`.
 */

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { api, request } from './api';

export interface Comment {
  id: string;
  report_id: string;
  user_id: string;
  parent_id?: string;
  depth: number;
  body: string;
  mentions: string[];
  edited: boolean;
  edited_at?: string;
  deleted: boolean;
  created_at: string;
}

export function useComments(reportId: string | undefined) {
  return useQuery({
    queryKey: ['comments', reportId],
    queryFn: () => request<{ comments: Comment[] }>(`/v1/comments?report_id=${reportId}`),
    enabled: Boolean(reportId),
    staleTime: 10_000,
  });
}

export function useCreateComment(reportId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ parentId, body }: { parentId?: string; body: string }) =>
      api.post<Comment>('/v1/comments', {
        report_id: reportId,
        parent_id: parentId || undefined,
        body,
      }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ['comments', reportId] });
    },
  });
}

export function useUpdateComment(reportId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, body }: { id: string; body: string }) =>
      api.put<Comment>(`/v1/comments/${id}`, { body }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ['comments', reportId] });
    },
  });
}

export function useDeleteComment(reportId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => api.del(`/v1/comments/${id}`),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ['comments', reportId] });
    },
  });
}
