/**
 * Notification settings: who gets told what, and whether it arrived.
 *
 * ⚠ THE SIGNING SECRET IS SHOWN EXACTLY ONCE AND LIVES ONLY IN LOCAL STATE.
 *
 * It is not written to the query cache, not to localStorage, not to the URL. A
 * cached secret survives navigation, appears in a DevTools dump, and outlives
 * the moment it was needed; component state loses it on unmount, which is the
 * lifetime it should have. There is no endpoint that reads it back — a customer
 * who loses their copy rotates the subscription, which is safe, rather than
 * revealing it, which is not.
 */

import { useState, type FormEvent } from 'react';
import { EmptyState, ErrorState, SkeletonRows, CopyableCode } from '../../components/States';
import { StatusPill } from '../../components/Chips';
import {
  describeEvent,
  useCreateSubscription,
  useDeleteSubscription,
  useDeliveries,
  useNotificationEvents,
  useSetSubscriptionEnabled,
  useSubscriptions,
  type Subscription,
} from '../../lib/notifications';

export function Notifications() {
  const subs = useSubscriptions();

  return (
    <section>
      <header className="page-header">
        <h1>Notifications</h1>
      </header>

      <p className="field-hint">
        {/*
          ⚠ THE CONFIDENTIALITY RULE IS STATED TO THE CUSTOMER, not just enforced
          in the code. Somebody configuring a webhook into a shared Slack channel
          should know what will and will not appear there before they do it.
        */}
        Notifications carry ids, counts and a link — never a component name, a version or an
        advisory id. Anyone following the link still has to sign in.
      </p>

      <NewSubscription />

      <h2>Delivery targets</h2>
      {subs.isPending && <SkeletonRows rows={3} columns={4} />}
      {subs.error && (
        <ErrorState
          error={subs.error}
          action="load your notification settings"
          onRetry={() => void subs.refetch()}
        />
      )}
      {subs.data?.length === 0 && (
        <EmptyState
          title="Nothing is being notified"
          guidance="Add an email address or a webhook above to be told when scans finish or new critical findings appear."
        />
      )}
      {subs.data && subs.data.length > 0 && (
        <ul className="card-list">
          {subs.data.map((s) => (
            <SubscriptionCard key={s.id} subscription={s} />
          ))}
        </ul>
      )}
    </section>
  );
}

function NewSubscription() {
  const create = useCreateSubscription();
  const events = useNotificationEvents();

  const [kind, setKind] = useState<'email' | 'webhook'>('email');
  const [target, setTarget] = useState('');
  const [selected, setSelected] = useState<string[]>([]);

  // ⚠ LOCAL STATE ONLY. See the file comment.
  const [revealedSecret, setRevealedSecret] = useState<string | null>(null);

  function submit(e: FormEvent) {
    e.preventDefault();
    create.mutate(
      { kind, target: target.trim(), events: selected },
      {
        onSuccess: (res) => {
          setTarget('');
          setSelected([]);
          setRevealedSecret(res.secret ?? null);
        },
      },
    );
  }

  return (
    <form className="panel" onSubmit={submit}>
      <h2>Add a target</h2>

      {create.error && <ErrorState error={create.error} action="add this target" />}

      <div className="field-row">
        <label htmlFor="sub-kind">Channel</label>
        <select
          id="sub-kind"
          value={kind}
          onChange={(e) => setKind(e.target.value as 'email' | 'webhook')}
        >
          <option value="email">Email</option>
          <option value="webhook">Webhook</option>
        </select>
      </div>

      <div className="field-row">
        <label htmlFor="sub-target">{kind === 'email' ? 'Address' : 'URL'}</label>
        <input
          id="sub-target"
          value={target}
          onChange={(e) => setTarget(e.target.value)}
          placeholder={
            kind === 'email' ? 'security@example.com' : 'https://hooks.example.com/axebom'
          }
          type={kind === 'email' ? 'email' : 'url'}
          required
        />
        {kind === 'webhook' && (
          <p className="field-hint">
            Must be <code>https</code>, and must not resolve to a private address. A signing secret
            is generated for you and shown once.
          </p>
        )}
      </div>

      <fieldset>
        <legend>Events</legend>
        {/*
          ⚠ THE EMPTY CASE MEANS "EVERYTHING", AND THE UI SAYS SO. Leaving every
          box unchecked reads as "nothing" to most people; a subscription that
          silently receives no messages is indistinguishable from one where no
          events happened, which is exactly what a notification exists to
          prevent.
        */}
        <p className="field-hint">Leave all unchecked to receive every event.</p>
        {events.isPending && <span className="muted">Loading events…</span>}
        {events.data?.map((id) => (
          <label key={id} className="checkbox">
            <input
              type="checkbox"
              checked={selected.includes(id)}
              onChange={() =>
                setSelected(
                  selected.includes(id) ? selected.filter((e) => e !== id) : [...selected, id],
                )
              }
            />
            {describeEvent(id)}
          </label>
        ))}
      </fieldset>

      <button type="submit" className="btn btn-primary" disabled={create.isPending}>
        {create.isPending ? 'Adding…' : 'Add target'}
      </button>

      {revealedSecret && (
        <div className="callout callout-warn" role="status">
          <h3>Copy this signing secret now</h3>
          <p>
            This is the only time it is shown. It cannot be retrieved — if you lose it, delete this
            webhook and add it again.
          </p>
          <CopyableCode value={revealedSecret} />
          <button type="button" className="btn btn-sm" onClick={() => setRevealedSecret(null)}>
            I have stored it
          </button>
        </div>
      )}
    </form>
  );
}

function SubscriptionCard({ subscription }: { subscription: Subscription }) {
  const setEnabled = useSetSubscriptionEnabled();
  const remove = useDeleteSubscription();
  const [showDeliveries, setShowDeliveries] = useState(false);

  return (
    <li className="card">
      <div className="card-head">
        <div>
          <strong>{subscription.target}</strong>
          <br />
          <small className="muted">
            {subscription.kind}
            {subscription.kind === 'webhook' &&
              (subscription.has_secret ? ' · signed' : ' · UNSIGNED')}
            {' · '}
            {subscription.events.length === 0
              ? 'every event'
              : subscription.events.map(describeEvent).join(', ')}
          </small>
        </div>
        <StatusPill status={subscription.enabled ? 'completed' : 'skipped'} />
      </div>

      <div className="row-actions">
        <button
          type="button"
          className="btn btn-sm"
          onClick={() => setEnabled.mutate({ id: subscription.id, enabled: !subscription.enabled })}
        >
          {subscription.enabled ? 'Pause' : 'Resume'}
        </button>
        <button
          type="button"
          className="btn btn-sm"
          aria-expanded={showDeliveries}
          onClick={() => setShowDeliveries(!showDeliveries)}
        >
          {showDeliveries ? 'Hide deliveries' : 'Deliveries'}
        </button>
        <button type="button" className="btn btn-sm" onClick={() => remove.mutate(subscription.id)}>
          Delete
        </button>
      </div>

      {showDeliveries && <DeliveryLog subscriptionId={subscription.id} />}
    </li>
  );
}

/**
 * DeliveryLog answers "why was I not told?".
 *
 * ⚠ DEAD-LETTERED DELIVERIES ARE SHOWN, NOT HIDDEN. They are the only record
 * that a notification was owed and never arrived. A log that lists only
 * successes tells the customer their webhook works right up until they discover
 * it has not fired for a month.
 */
function DeliveryLog({ subscriptionId }: { subscriptionId: string }) {
  const { data, isPending, error } = useDeliveries(subscriptionId);

  if (isPending) return <SkeletonRows rows={3} columns={3} />;
  if (error) return <ErrorState error={error} action="load the delivery log" />;
  if (!data || data.length === 0) {
    return <p className="muted">Nothing has been sent to this target yet.</p>;
  }

  return (
    <table className="table table-compact">
      <caption className="sr-only">Delivery attempts</caption>
      <thead>
        <tr>
          <th scope="col">When</th>
          <th scope="col">Event</th>
          <th scope="col">Status</th>
          <th scope="col">Detail</th>
        </tr>
      </thead>
      <tbody>
        {data.map((d) => (
          <tr key={d.id}>
            <th scope="row">
              <time dateTime={d.created_at}>
                {new Date(d.created_at).toLocaleString(undefined, {
                  dateStyle: 'short',
                  timeStyle: 'short',
                })}
              </time>
            </th>
            <td>{describeEvent(d.event_type)}</td>
            <td>
              <StatusPill status={d.status === 'dead_lettered' ? 'failed' : d.status} />
              {d.attempt > 1 && <small className="muted"> attempt {d.attempt}</small>}
            </td>
            <td>
              {d.response_code ? <code>{d.response_code}</code> : null}
              {d.error && <p className="muted">{d.error}</p>}
              {d.next_retry_at && (
                <small className="muted">
                  retrying{' '}
                  <time dateTime={d.next_retry_at}>
                    {new Date(d.next_retry_at).toLocaleTimeString()}
                  </time>
                </small>
              )}
              {d.status === 'dead_lettered' && (
                <small className="muted"> — not retried again</small>
              )}
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}
