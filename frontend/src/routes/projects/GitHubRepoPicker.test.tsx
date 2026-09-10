/**
 * The repo picker's behaviour when GitHub rejects the organisation's stored
 * credential.
 *
 * ⚠ WHAT THIS GUARDS IS A ROUTE OUT, NOT A MESSAGE.
 *
 * A stored authorisation that GitHub later refuses answers every listing with
 * AUTH_TOKEN_INVALID and "reconnect your GitHub account". There was no
 * reconnect anywhere in the product to act on that: the wizard renders
 * "Choose a repository" rather than a connect button whenever the organisation
 * is connected — which it still is, because a rejected token is a token — and
 * the settings screen offers only Disconnect, deliberately. The instruction
 * was correct and unfollowable, which is the worst combination: it reads as
 * the user failing to find a control that does not exist.
 */

import { afterEach, describe, expect, it, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { GitHubRepoPicker } from './GitHubRepoPicker';
import { setAccessToken } from '../../lib/api';

function errorResponse(code: string, message: string, status: number): Response {
  return new Response(
    JSON.stringify({ error: { code, message, request_id: 'req-abc' } }),
    { status, headers: { 'Content-Type': 'application/json' } },
  );
}

function renderPicker(props: Partial<Parameters<typeof GitHubRepoPicker>[0]> = {}) {
  // retry: false — a failure must surface in the assertion rather than in a
  // backoff the test then has to wait out.
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <GitHubRepoPicker token="" onSelect={() => {}} onClose={() => {}} {...props} />
    </QueryClientProvider>,
  );
}

describe('GitHubRepoPicker', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    setAccessToken(null);
  });

  it('offers a reconnect when GitHub has rejected the stored credential', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(
        errorResponse(
          'AUTH_TOKEN_INVALID',
          'GitHub rejected the stored token; reconnect your GitHub account',
          401,
        ),
      ),
    );
    const onReconnect = vi.fn();
    renderPicker({ onReconnect });

    const button = await screen.findByRole('button', { name: /reconnect github/i });
    await userEvent.click(button);
    expect(onReconnect).toHaveBeenCalledOnce();
  });

  // ⚠ THE OTHER HALF OF THE BRANCH. "Try again" is the right offer for a
  // network blip and the wrong one for a credential the provider has refused:
  // pressing it re-sends the same dead token, so the user proves the failure
  // twice before concluding the product is broken. The branch is on the CODE,
  // never the message (docs/02-CONTRACTS.md §9).
  it('offers a plain retry for a failure that is not a rejected credential', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(
        errorResponse('INTERNAL_DEPENDENCY', 'could not reach GitHub', 502),
      ),
    );
    renderPicker({ onReconnect: vi.fn() });

    expect(await screen.findByRole('button', { name: /try again/i })).toBeTruthy();
    expect(screen.queryByRole('button', { name: /reconnect github/i })).toBeNull();
  });
});
