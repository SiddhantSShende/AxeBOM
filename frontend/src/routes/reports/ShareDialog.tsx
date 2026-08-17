/**
 * The share dialog.
 *
 * ⚠ A SHARE LINK IS AN UNAUTHENTICATED BEARER CREDENTIAL, AND THE DIALOG SAYS
 * SO BEFORE IT MINTS ONE.
 *
 * Anyone holding the URL can download the report. For a `private` report that
 * means an estate's unpatched vulnerabilities, so the warning is not a footnote
 * — it is the first thing in the dialog, and it names what the report contains
 * rather than saying "are you sure".
 *
 * docs/07-FRONTEND-SPEC.md §6, CERT-In §5.3.2.
 */

import { useEffect, useRef, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { api } from '../../lib/api';
import { StatusPill } from '../../components/Chips';
import { CopyableCode, EmptyState, ErrorState, SkeletonRows } from '../../components/States';

interface ShareLink {
  id: string;
  expiresAt: string | null;
  maxDownloads: number | null;
  downloadCount: number;
  revokedAt: string | null;
  state: 'granted' | 'expired' | 'revoked' | 'exhausted';
  createdAt: string;
  /** Present ONLY in the response that created the link. */
  token?: string;
  url?: string;
}

const EXPIRY_PRESETS = [
  { label: '24 hours', hours: 24 },
  { label: '7 days', hours: 24 * 7 },
  { label: '30 days', hours: 24 * 30 },
  { label: 'No expiry', hours: 0 },
];

export function ShareDialog({
  reportId,
  visibility,
  onClose,
}: {
  reportId: string;
  visibility: 'public' | 'private';
  onClose: () => void;
}) {
  const ref = useRef<HTMLDivElement>(null);
  const queryClient = useQueryClient();
  const [expiryHours, setExpiryHours] = useState(24 * 7);
  const [cap, setCap] = useState<number | ''>('');
  const [minted, setMinted] = useState<ShareLink | null>(null);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    document.addEventListener('keydown', onKey);
    ref.current?.focus();
    return () => document.removeEventListener('keydown', onKey);
  }, [onClose]);

  const links = useQuery({
    queryKey: ['shares', reportId],
    queryFn: () => api.get<{ share_links: ShareLink[] }>(`/v1/reports/${reportId}/shares`),
  });

  const create = useMutation({
    mutationFn: () =>
      api.post<ShareLink>(`/v1/reports/${reportId}/shares`, {
        expires_at:
          expiryHours > 0 ? new Date(Date.now() + expiryHours * 3_600_000).toISOString() : null,
        max_downloads: cap === '' ? null : cap,
      }),
    onSuccess: (link) => {
      // ⚠ THE ONLY MOMENT THE TOKEN EXISTS OUTSIDE THE CREATOR'S HANDS. It is
      // never stored and cannot be recovered — a link support can look up is a
      // link an attacker with read access can look up. The dialog says that
      // where the token is shown.
      setMinted(link);
      void queryClient.invalidateQueries({ queryKey: ['shares', reportId] });
    },
  });

  const revoke = useMutation({
    mutationFn: (id: string) => api.del<void>(`/v1/shares/${id}`),
    onSuccess: () => void queryClient.invalidateQueries({ queryKey: ['shares', reportId] }),
  });

  return (
    <div className="drawer-scrim" onClick={onClose}>
      <div
        className="dialog"
        role="dialog"
        aria-modal="true"
        aria-labelledby="share-h"
        tabIndex={-1}
        ref={ref}
        onClick={(e) => e.stopPropagation()}
      >
        <header className="drawer-head">
          <h2 id="share-h">Share this report</h2>
          <button type="button" className="btn btn-quiet" onClick={onClose} aria-label="Close">
            ✕
          </button>
        </header>

        {visibility === 'private' && (
          <div className="callout callout-warn" role="alert">
            <h3>This report is private</h3>
            <p>
              It contains vulnerability detail (CERT-In §5.3.2). A share link is a{' '}
              <strong>bearer credential</strong> — anyone who has the URL can download it, with no
              sign-in and no record of who they are beyond an IP address.
            </p>
            <p>
              Set an expiry and a download cap unless you have a reason not to, and revoke the link
              when the review is over.
            </p>
          </div>
        )}

        {minted ? (
          <MintedLink link={minted} onDone={() => setMinted(null)} />
        ) : (
          <form
            className="share-form"
            onSubmit={(e) => {
              e.preventDefault();
              create.mutate();
            }}
          >
            <label className="filter">
              <span>Expires</span>
              <select value={expiryHours} onChange={(e) => setExpiryHours(Number(e.target.value))}>
                {EXPIRY_PRESETS.map((p) => (
                  <option key={p.label} value={p.hours}>
                    {p.label}
                  </option>
                ))}
              </select>
            </label>

            <label className="filter">
              <span>Download limit</span>
              <input
                type="number"
                min={1}
                value={cap}
                placeholder="unlimited"
                onChange={(e) => setCap(e.target.value === '' ? '' : Number(e.target.value))}
              />
            </label>

            {expiryHours === 0 && (
              <p className="share-warn">
                A link with no expiry lasts until it is revoked. It will outlive the review it was
                created for.
              </p>
            )}

            {create.error != null && <ErrorState error={create.error} action="create the link" />}

            <button type="submit" className="btn btn-primary" disabled={create.isPending}>
              {create.isPending ? 'Creating…' : 'Create link'}
            </button>
          </form>
        )}

        <section>
          <h3>Existing links</h3>
          {links.isPending && <SkeletonRows rows={3} columns={4} />}
          {links.isError && <ErrorState error={links.error} action="load the existing links" />}
          {links.data?.share_links.length === 0 && (
            <EmptyState
              title="No links yet"
              guidance="Nobody outside this tenant can reach this report."
            />
          )}
          {(links.data?.share_links.length ?? 0) > 0 && (
            <table className="table table-compact">
              <thead>
                <tr>
                  <th scope="col">Created</th>
                  <th scope="col">State</th>
                  <th scope="col">Expires</th>
                  <th scope="col">Downloads</th>
                  <th scope="col" />
                </tr>
              </thead>
              <tbody>
                {links.data?.share_links.map((l) => (
                  <tr key={l.id}>
                    <td>{l.createdAt}</td>
                    <td>
                      <StatusPill status={l.state} />
                    </td>
                    <td>{l.expiresAt ?? <span className="not-provided">never</span>}</td>
                    <td>
                      {l.downloadCount}
                      {l.maxDownloads !== null && ` / ${l.maxDownloads}`}
                    </td>
                    <td>
                      {l.revokedAt === null && (
                        <button
                          type="button"
                          className="btn btn-quiet"
                          onClick={() => revoke.mutate(l.id)}
                        >
                          Revoke
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
          <p className="section-note">
            Revocation takes effect immediately — every download re-checks the link, and nothing is
            cached.
          </p>
        </section>
      </div>
    </div>
  );
}

/**
 * MintedLink shows the token once and says that it is once.
 *
 * ⚠ THE "YOU WILL NOT SEE THIS AGAIN" IS NOT BOILERPLATE. Only the hash is
 * stored, so this really is the only opportunity — and a user who dismisses the
 * dialog expecting to find it in the list later has lost it.
 */
function MintedLink({ link, onDone }: { link: ShareLink; onDone: () => void }) {
  const url = link.url ? `${window.location.origin}${link.url}` : '';

  return (
    <div className="callout callout-ok">
      <h3>Link created</h3>
      <p>
        <strong>Copy it now.</strong> Only a hash is stored, so this link cannot be shown again —
        not by you, not by support.
      </p>
      <CopyableCode value={url} />
      <p className="section-note">
        {link.expiresAt ? `Expires ${link.expiresAt}.` : 'No expiry — revoke it when you are done.'}
        {link.maxDownloads !== null && ` Limited to ${link.maxDownloads} downloads.`}
      </p>
      <button type="button" className="btn" onClick={onDone}>
        Done
      </button>
    </div>
  );
}
