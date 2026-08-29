/**
 * Notification subscription types and queries.
 *
 * ⚠ THE SECRET IS RETURNED EXACTLY ONCE, ON CREATION, AND IS NEVER STORED HERE.
 *
 * The create response carries it so the UI can show it to the person who just
 * made the subscription. It is deliberately not put in the query cache, not in
 * localStorage and not in the URL: a cached secret survives navigation, appears
 * in a React DevTools dump, and outlives the moment it was needed. The
 * component holds it in local state and loses it on unmount, which is exactly
 * the lifetime it should have.
 */

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { request } from './api';

export interface Subscription {
  id: string;
  kind: 'email' | 'webhook';
  target: string;
  events: string[];
  /** Whether a signing secret is configured. Never the secret itself. */
  has_secret: boolean;
  enabled: boolean;
}

export interface Delivery {
  id: string;
  event_type: string;
  attempt: number;
  status: 'pending' | 'delivered' | 'failed' | 'dead_lettered';
  response_code?: number | undefined;
  error?: string | undefined;
  next_retry_at?: string | undefined;
  created_at: string;
  delivered_at?: string | undefined;
}

export interface CreateSubscriptionInput {
  kind: 'email' | 'webhook';
  target: string;
  /** Empty means "every event". See subscription.Matches on the server. */
  events: string[];
  /** Omit to have one generated. */
  secret?: string | undefined;
}

export interface CreateSubscriptionResult {
  subscription: Subscription;
  /** Present only on the create response, only for webhooks. */
  secret?: string | undefined;
  secret_notice?: string | undefined;
}

export function useSubscriptions() {
  return useQuery({
    queryKey: ['notifications', 'subscriptions'],
    queryFn: ({ signal }) =>
      request<{ subscriptions: Subscription[] }>('/v1/notifications/subscriptions', { signal }),
    select: (d) => d.subscriptions,
  });
}

/**
 * useNotificationEvents fetches the event vocabulary.
 *
 * ⚠ FETCHED, NOT HARDCODED. Adding an event to the product must add it to the
 * settings screen; a list declared here is one that silently omits the newest
 * event until somebody remembers to edit two files.
 */
export function useNotificationEvents() {
  return useQuery({
    queryKey: ['notifications', 'events'],
    queryFn: ({ signal }) => request<{ events: string[] }>('/v1/notifications/events', { signal }),
    select: (d) => d.events,
    staleTime: 60 * 60 * 1000,
  });
}

export function useDeliveries(subscriptionId: string) {
  return useQuery({
    queryKey: ['notifications', 'subscriptions', subscriptionId, 'deliveries'],
    queryFn: ({ signal }) =>
      request<{ deliveries: Delivery[] }>(
        `/v1/notifications/subscriptions/${subscriptionId}/deliveries`,
        { signal },
      ),
    select: (d) => d.deliveries,
    enabled: subscriptionId !== '',
  });
}

export function useCreateSubscription() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (input: CreateSubscriptionInput) =>
      request<CreateSubscriptionResult>('/v1/notifications/subscriptions', {
        method: 'POST',
        body: input,
      }),
    onSuccess: () => {
      // ⚠ ONLY THE LIST IS INVALIDATED. The mutation RESULT — which contains
      // the secret — is never written into the cache, so it cannot be read
      // back by another component or survive this screen.
      void qc.invalidateQueries({ queryKey: ['notifications', 'subscriptions'] });
    },
  });
}

export function useSetSubscriptionEnabled() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, enabled }: { id: string; enabled: boolean }) =>
      request<Subscription>(`/v1/notifications/subscriptions/${id}/enabled`, {
        method: 'POST',
        body: { enabled },
      }),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ['notifications', 'subscriptions'] }),
  });
}

export function useDeleteSubscription() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) =>
      request<void>(`/v1/notifications/subscriptions/${id}`, { method: 'DELETE' }),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ['notifications', 'subscriptions'] }),
  });
}

/**
 * describeEvent renders an event id for a checkbox label.
 *
 * Unknown ids fall through to the raw value rather than being hidden: an event
 * the server emits and this build does not recognise must still be
 * subscribable, or a newer server's events become unreachable from an older UI.
 */
export function describeEvent(id: string): string {
  switch (id) {
    case 'scan.completed':
      return 'Scan completed';
    case 'findings.new_critical':
      return 'New critical findings';
    case 'campaign.failed':
      return 'Scheduled scan failed';
    case 'report.ready':
      return 'Report ready';
    default:
      return id;
  }
}
