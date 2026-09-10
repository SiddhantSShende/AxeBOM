/**
 * The GitHub repository picker.
 *
 * Backed by GET /v1/github/repos, which is used-and-discarded per request
 * (the token travels in a header, never stored server-side) — see
 * useRepoSearch. Selecting a repository here only stages it in the wizard's
 * Draft; nothing is connected until ProjectWizard's submit() calls
 * useConnectRepo after the project itself exists.
 */

import { useState } from 'react';
import { Overlay } from '../../components/Overlay';
import { ErrorState, SkeletonRows } from '../../components/States';
import { ApiError } from '../../lib/api';
import { useRepoSearch, type Repo } from '../../lib/projects';

export function GitHubRepoPicker({
  token,
  onSelect,
  onClose,
  onReconnect,
  reconnecting = false,
}: {
  /**
   * The GitHub token, or '' when the organisation has a stored connection and
   * the server should use that instead. An empty string is not a missing
   * value here — it is the connect-once path.
   */
  token: string;
  onSelect: (repo: Repo) => void;
  onClose: () => void;
  /**
   * Re-runs the OAuth window and replaces the organisation's stored token.
   *
   * ⚠ THIS EXISTS BECAUSE THE ADVICE HAD NOWHERE TO GO. A stored authorisation
   * that GitHub later rejects answers every listing with "reconnect your
   * GitHub account", and there was no reconnect anywhere in the product: the
   * wizard shows "Choose a repository" instead of a connect button whenever
   * the organisation is connected — which it still is, since a rejected token
   * is a token — and the settings screen offers only Disconnect, deliberately.
   * The whole route back was: leave the wizard, find Settings, disconnect,
   * return, start the registration again. Nothing said so.
   */
  onReconnect?: () => void;
  reconnecting?: boolean;
}) {
  const [query, setQuery] = useState('');
  const search = useRepoSearch(token, query, true);

  // Branch on the CODE, never the message (docs/02-CONTRACTS.md §9). The
  // server sends AUTH_TOKEN_INVALID for exactly one thing on this endpoint:
  // GitHub refused the credential we sent it.
  const rejected =
    search.error instanceof ApiError && search.error.code === 'AUTH_TOKEN_INVALID';

  return (
    <Overlay variant="drawer" onClose={onClose} aria-label="Choose a GitHub repository">
      <header className="drawer-head">
        <h2>Choose a repository</h2>
        <button type="button" className="btn btn-quiet" onClick={onClose} aria-label="Close">
          ✕
        </button>
      </header>

      <label className="field">
        <span>Search</span>
        {/* No autoFocus: Overlay already moves focus to the panel itself on
            open (its focus-trap setup), and the two would fight over which
            element actually ends up focused. Tab reaches this field first. */}
        <input
          type="search"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="owner/name"
        />
      </label>

      {search.isLoading && <SkeletonRows rows={6} columns={1} />}
      {search.error != null && (
        <ErrorState
          error={search.error}
          action="list your repositories"
          // A rejected credential does not come back by asking again, so the
          // action offered for one is the repair, not a retry. Every other
          // failure here keeps the plain retry.
          {...(rejected && onReconnect
            ? {
                onRetry: onReconnect,
                retryLabel: reconnecting ? 'Opening GitHub…' : 'Reconnect GitHub',
              }
            : { onRetry: () => void search.refetch() })}
        />
      )}

      {search.data && (
        <ul className="chips" aria-label="Repositories">
          {search.data.repos.length === 0 && <p className="note">No repositories matched.</p>}
          {search.data.repos.map((repo) => (
            <li key={repo.external_id}>
              <button
                type="button"
                className="option"
                onClick={() => {
                  onSelect(repo);
                  onClose();
                }}
              >
                <strong>{repo.full_name}</strong>
                {repo.private && <span className="chip-note">private</span>}
                {repo.description && <small>{repo.description}</small>}
              </button>
            </li>
          ))}
        </ul>
      )}
    </Overlay>
  );
}
