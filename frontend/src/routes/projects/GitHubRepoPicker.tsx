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
import { useRepoSearch, type Repo } from '../../lib/projects';

export function GitHubRepoPicker({
  token,
  onSelect,
  onClose,
}: {
  /**
   * The GitHub token, or '' when the organisation has a stored connection and
   * the server should use that instead. An empty string is not a missing
   * value here — it is the connect-once path.
   */
  token: string;
  onSelect: (repo: Repo) => void;
  onClose: () => void;
}) {
  const [query, setQuery] = useState('');
  const search = useRepoSearch(token, query, true);

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
      {search.error != null && <ErrorState error={search.error} action="list your repositories" />}

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
