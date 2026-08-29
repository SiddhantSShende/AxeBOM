/**
 * The GitHub "connect" popup's landing page.
 *
 * ⚠ THIS RUNS IN THE POPUP, NOT THE WIZARD TAB.
 *
 * services/auth/internal/handler/github_connect.go redirects here with a
 * repo-scoped access token in the URL FRAGMENT — never a query param, never
 * sent to a server, never logged. This page's only job is to hand that token
 * to the tab that opened it and close itself; nobody is meant to read it.
 *
 * Origin-checked in both directions: the token is posted only to
 * window.location.origin (never a wildcard), and lib/projects.ts's
 * useGitHubConnect discards any message that did not come from that same
 * origin — otherwise an embedded frame on some other page could hand the
 * opener a token it never asked for.
 */

import { useEffect } from 'react';

export function GitHubConnectCallback() {
  useEffect(() => {
    const params = new URLSearchParams(window.location.hash.slice(1));
    const token = params.get('access_token');

    // window.opener is typed as `any` by lib.dom (it can be any browsing
    // context, including one from a different origin this page cannot
    // introspect) — narrowed to Window explicitly rather than trusting that.
    const opener = window.opener as Window | null;
    if (token && opener) {
      opener.postMessage({ type: 'axebom-github-connect', token }, window.location.origin);
    }
    window.close();
  }, []);

  return (
    <div className="page">
      <p>Connecting to GitHub…</p>
    </div>
  );
}
