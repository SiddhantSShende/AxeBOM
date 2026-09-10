/**
 * Empty, loading and error states.
 *
 * Every list has all three, and every one of them tells the user what to do
 * next. "No data" and "Something went wrong" are the two failures this file
 * exists to prevent.
 *
 * docs/07-FRONTEND-SPEC.md §7.
 */

import { useState, type ReactNode } from 'react';
import { ApiError } from '../lib/api';

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

interface ErrorStateProps {
  error: unknown;
  /** What the user was trying to do, e.g. "load your projects". */
  action?: string;
  onRetry?: () => void;
  /**
   * The label for onRetry, when "Try again" is the wrong promise.
   *
   * Some failures are not retryable and are repairable instead: a credential
   * the provider has rejected does not come back by pressing the same button,
   * and offering "Try again" for one invites the user to prove that twice
   * before concluding the product is broken.
   */
  retryLabel?: string;
}

/**
 * ErrorState renders the taxonomy code, the message, and a copyable request id.
 *
 * ⚠ NEVER A BARE "SOMETHING WENT WRONG".
 *
 * Four things have to be here, and each has a reason:
 *
 *   code        stable across rewordings; it is what documentation is keyed on
 *               and what a user can search for
 *   message     the human sentence, from the server, already written for them
 *   request_id  the FIRST thing support asks for, so it is copyable rather
 *               than something to transcribe from a screenshot
 *   what next   a retry, or the specific action that resolves this code
 *
 * A user who can quote a code and a request id gets help in one exchange. A
 * user with a screenshot of "Something went wrong" gets three.
 */
export function ErrorState({ error, action, onRetry, retryLabel }: ErrorStateProps) {
  const api = error instanceof ApiError ? error : null;
  const code = api?.code ?? 'INTERNAL_UNEXPECTED';
  const message =
    api?.message ??
    (error instanceof Error ? error.message : 'The request could not be completed.');

  return (
    <div className="state state-error" role="alert">
      <h3 className="state-title">{action ? `Could not ${action}` : 'That did not work'}</h3>

      <p className="state-message">{message}</p>

      <dl className="state-detail">
        <dt>Code</dt>
        <dd>
          <code>{code}</code>
        </dd>
        {api?.requestId && (
          <>
            <dt>Request</dt>
            <dd>
              <CopyableCode value={api.requestId} />
            </dd>
          </>
        )}
      </dl>

      <p className="state-hint">{hintFor(code)}</p>

      <div className="state-actions">
        {onRetry && (
          <button type="button" className="btn" onClick={onRetry}>
            {retryLabel ?? 'Try again'}
          </button>
        )}
        <a className="btn btn-quiet" href={`/docs/errors#${code.toLowerCase()}`}>
          What does {code} mean?
        </a>
      </div>
    </div>
  );
}

/**
 * hintFor turns a taxonomy code into the next action.
 *
 * ⚠ BRANCHED ON THE CODE, NEVER ON THE MESSAGE TEXT. Messages are for humans
 * and get reworded; a UI that matched on prose would break silently on a copy
 * edit (docs/02-CONTRACTS.md §9).
 */
function hintFor(code: string): string {
  switch (code) {
    case 'PERM_REPORT_PRIVATE':
      return (
        'This report contains vulnerability detail, so it needs the Analyst ' +
        'role or above (CERT-In §5.3.2). Ask an owner to change your role, or ' +
        'request the public version of this report.'
      );
    case 'NOTFOUND_REPORT':
    case 'NOTFOUND_PROJECT':
    case 'NOTFOUND_SCAN':
      return 'It may have been deleted, or the link may be wrong.';
    case 'AUTH_TOKEN_EXPIRED':
      return 'Your session expired. Signing in again will resume where you left off.';
    // ⚠ ONE CODE, TWO SITUATIONS, AND THE GENERIC HINT SUITED NEITHER.
    //
    // AUTH_TOKEN_INVALID covers both "your AxeBOM session is not valid" and
    // "the credential we hold for an external provider was rejected by that
    // provider" — the second being what a GitHub repo listing returns once
    // the stored authorisation stops working. Falling through to "quote the
    // code and request id" answered a question nobody had: this failure is
    // self-service, and the sentence that resolves it is the one naming the
    // authorisation as the thing to replace.
    case 'AUTH_TOKEN_INVALID':
      return (
        'A credential was rejected — either your sign-in, or an authorisation ' +
        'AxeBOM holds for another service. Signing in again fixes the first; ' +
        'reconnecting the account fixes the second, and does not affect ' +
        'projects that are already connected.'
      );
    case 'REPORT_TOO_LARGE_FOR_PDF':
      return (
        'This BOM is too large to render as a PDF. The XLSX and JSON exports ' +
        'have no page limit, or request the Top-Level BOM instead of Complete.'
      );
    case 'REPORT_TOO_LARGE_FOR_XLSX':
      return 'This BOM exceeds a worksheet row limit. The JSON export has no limit.';
    case 'REPORT_SHARE_EXPIRED':
      return 'Ask whoever sent you this link for a new one.';
    case 'REPORT_SHARE_REVOKED':
      return 'This link was deliberately withdrawn. Ask the sender whether that was intended.';
    case 'RATE_LIMIT_EXCEEDED':
      return 'Too many requests. Waiting a moment and retrying will work.';
    case 'SCAN_ALREADY_RUNNING':
      return 'A scan for this project is already in progress. Watch it rather than starting another.';
    default:
      return (
        'If this keeps happening, quote the code and request id above — they ' +
        'are what identifies this exact failure in our logs.'
      );
  }
}

/**
 * CopyableCode is a request id you can click.
 *
 * Transcribing a uuid from a screenshot is where support tickets go wrong, and
 * the person doing the transcribing is already having a bad day.
 */
export function CopyableCode({ value }: { value: string }) {
  const [copied, setCopied] = useState(false);

  return (
    <button
      type="button"
      className="copyable"
      onClick={() => {
        void navigator.clipboard?.writeText(value).then(
          () => {
            setCopied(true);
            window.setTimeout(() => setCopied(false), 1500);
          },
          () => {
            // Clipboard access can be denied. The value is still selectable, so
            // failing silently here is worse than saying so.
            setCopied(false);
          },
        );
      }}
      // The live region announces the copy to a screen reader; a visual-only
      // confirmation is invisible to the users most likely to be typing this
      // into a support form by hand.
      aria-label={`Copy ${value}`}
    >
      <code>{value}</code>
      <span aria-live="polite">{copied ? 'copied' : 'copy'}</span>
    </button>
  );
}

// ---------------------------------------------------------------------------
// Empty
// ---------------------------------------------------------------------------

interface EmptyStateProps {
  title: string;
  /** What to do next. Required — an empty state without one is "no data". */
  guidance: ReactNode;
  action?: ReactNode;
}

/**
 * EmptyState always says what to do next.
 *
 * ⚠ `guidance` IS NOT OPTIONAL. An empty list is the moment a new user decides
 * whether the product works, and "No data" answers the wrong question.
 */
export function EmptyState({ title, guidance, action }: EmptyStateProps) {
  return (
    <div className="state state-empty">
      <h3 className="state-title">{title}</h3>
      <p className="state-message">{guidance}</p>
      {action && <div className="state-actions">{action}</div>}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Loading
// ---------------------------------------------------------------------------

/**
 * Skeleton rows, not a spinner.
 *
 * A spinner says "wait" and nothing else; a skeleton says how much is coming
 * and where it will be, so the layout does not jump when it arrives. On a full
 * page a spinner also destroys any sense of progress on a slow connection —
 * which is the only time it is shown.
 */
export function SkeletonRows({ rows = 8, columns = 4 }: { rows?: number; columns?: number }) {
  return (
    <div className="skeleton" aria-busy="true" aria-live="polite" aria-label="Loading">
      {Array.from({ length: rows }, (_, r) => (
        <div className="skeleton-row" key={r}>
          {Array.from({ length: columns }, (_, c) => (
            <div className="skeleton-cell" key={c} />
          ))}
        </div>
      ))}
    </div>
  );
}
