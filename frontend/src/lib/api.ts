/**
 * The API client.
 *
 * One place that knows how to call the gateway, so error handling, the access
 * token and the canonical error shape are not reimplemented per screen.
 *
 * THE ERROR CONTRACT (docs/02-CONTRACTS.md §9): every failure carries a stable
 * machine code. The UI branches on the CODE, never on the message text —
 * messages are for humans and will be reworded.
 */

export interface ApiErrorBody {
  error: {
    code: string;
    message: string;
    details?: Array<Record<string, unknown>> | undefined;
    request_id?: string | undefined;
  };
}

/** ApiError carries the machine code so callers can branch on it. */
export class ApiError extends Error {
  readonly code: string;
  readonly status: number;
  readonly details: Array<Record<string, unknown>>;
  readonly requestId: string | undefined;

  constructor(status: number, body: ApiErrorBody | null, fallback: string) {
    super(body?.error?.message ?? fallback);
    this.name = 'ApiError';
    this.status = status;
    this.code = body?.error?.code ?? 'INTERNAL_UNEXPECTED';
    this.details = body?.error?.details ?? [];
    this.requestId = body?.error?.request_id;
  }

  /**
   * A 404 for a resource that exists in another tenant is indistinguishable
   * from one that does not exist — deliberately, so the API cannot be used to
   * enumerate ids. The UI says "not found" for both.
   */
  get isNotFound(): boolean {
    return this.status === 404;
  }

  /** The access token expired; the client should refresh and retry once. */
  get isExpired(): boolean {
    return this.code === 'AUTH_TOKEN_EXPIRED';
  }
}

/**
 * The in-memory access token.
 *
 * Memory ONLY. Not localStorage, not a readable cookie: anything JavaScript can
 * read, an XSS can exfiltrate. AuthProvider writes it here on every user change,
 * so a renewal reaches the next request without a re-render.
 *
 * A reload recovers the session from the OIDC library's session storage, which
 * is per tab and discarded when the tab closes.
 */
let accessToken: string | null = null;

export function setAccessToken(token: string | null): void {
  accessToken = token;
}

export function getAccessToken(): string | null {
  return accessToken;
}

/**
 * Which organisation this session is acting in.
 *
 * ⚠ A HINT, NOT A GRANT, AND THE SERVER TREATS IT THAT WAY. The middleware
 * honours the header only when the VERIFIED token already carries a role in the
 * organisation named — a header that could select a tenant on its own would be
 * the entire tenancy boundary, handed to the client.
 *
 * It has to be sent because a person who holds a role in two organisations
 * carries BOTH grants in one token, and the server refuses to guess: naming
 * neither is AUTH_ORG_AMBIGUOUS, because picking one would make the answer
 * depend on map iteration order and show a consultant whichever customer's data
 * came up first.
 */
let orgId: string | null = null;

export function setOrgId(id: string | null): void {
  orgId = id;
}

export function getOrgId(): string | null {
  return orgId;
}

/** The header name, matching oidcauth.HeaderOrg. */
export const ORG_HEADER = 'X-EncoreBOM-Org';

/**
 * How to obtain a fresh access token when one has expired.
 *
 * ⚠ INJECTED, NOT IMPORTED. This module would otherwise pull the whole OIDC
 * library into every unit test that touches an API call, and the api client
 * would know which identity provider is in use — which is the coupling that
 * made replacing local JWTs with ZITADEL a change across every screen instead
 * of one.
 */
type Refresher = () => Promise<string | null>;

let refresher: Refresher | null = null;

export function setTokenRefresher(fn: Refresher | null): void {
  refresher = fn;
}

/**
 * ⚠ ONE RENEWAL AT A TIME, SHARED BY EVERY WAITING REQUEST.
 *
 * A page typically fires several queries at once, and they expire together.
 * Without this, each would start its own renewal: N redirects to the token
 * endpoint, N refresh-token rotations, and — because ZITADEL rotates refresh
 * tokens — all but one of them invalid, which ends the session it was trying
 * to save.
 */
let inFlight: Promise<string | null> | null = null;

function renew(): Promise<string | null> {
  if (!refresher) return Promise.resolve(null);
  inFlight ??= refresher().finally(() => {
    inFlight = null;
  });
  return inFlight;
}

interface RequestOptions {
  method?: string | undefined;
  body?: unknown;
  /** Extra headers, e.g. the GitHub token for the repo picker. */
  headers?: Record<string, string> | undefined;
  signal?: AbortSignal | undefined;
}

/**
 * request performs one API call and normalizes the failure modes.
 *
 * A 401 is retried ONCE after a silent renewal, and only once: a second 401
 * with a token minted seconds earlier is not an expiry, it is a rejection, and
 * retrying it in a loop turns a configuration error into a hammering client.
 */
export async function request<T>(path: string, opts: RequestOptions = {}): Promise<T> {
  try {
    return await send<T>(path, opts);
  } catch (err) {
    if (!(err instanceof ApiError) || err.status !== 401) throw err;
    const fresh = await renew();
    if (!fresh) throw err;
    return await send<T>(path, opts);
  }
}

async function send<T>(path: string, opts: RequestOptions = {}): Promise<T> {
  const headers: Record<string, string> = { ...opts.headers, ...identityHeaders() };
  if (opts.body !== undefined) headers['Content-Type'] = 'application/json';

  // Built incrementally rather than with `body: undefined`: under
  // exactOptionalPropertyTypes an explicit undefined is not the same as an
  // absent property, and RequestInit does not accept one.
  const init: RequestInit = {
    method: opts.method ?? 'GET',
    headers,
    // Same-origin only. There is no session cookie of ours to send — ZITADEL
    // owns sessions now — but the gateway and the identity provider share this
    // origin, and defaulting to omit would break nothing today and something
    // subtle later.
    credentials: 'same-origin',
  };
  if (opts.body !== undefined) init.body = JSON.stringify(opts.body);
  if (opts.signal) init.signal = opts.signal;

  const res = await fetch(`/api${path}`, init);

  if (res.status === 204) return undefined as T;

  if (!res.ok) {
    let body: ApiErrorBody | null = null;
    try {
      body = (await res.json()) as ApiErrorBody;
    } catch {
      // A non-JSON error body means something upstream of the service
      // answered — a proxy, a load balancer. Fall through to the status.
    }
    throw new ApiError(res.status, body, `request failed with ${res.status}`);
  }

  return (await res.json()) as T;
}

/**
 * identityHeaders is who the caller is and who they are acting for.
 *
 * One function so an endpoint can never be reached through a path that forgot
 * one of them — which is how the organisation header ended up being computed by
 * the switcher and sent by nobody.
 */
function identityHeaders(): Record<string, string> {
  const headers: Record<string, string> = {};
  if (accessToken) headers['Authorization'] = `Bearer ${accessToken}`;
  if (orgId) headers[ORG_HEADER] = orgId;
  return headers;
}

/**
 * upload posts multipart form data. Used for manifests and archives.
 *
 * Retried on a 401 exactly like `request`: a hardware import is the longest
 * thing a user does on one screen, so it is the request most likely to be
 * holding a token that expired while they filled the form in.
 */
export async function upload<T>(path: string, form: FormData): Promise<T> {
  try {
    return await sendUpload<T>(path, form);
  } catch (err) {
    if (!(err instanceof ApiError) || err.status !== 401) throw err;
    const fresh = await renew();
    if (!fresh) throw err;
    return await sendUpload<T>(path, form);
  }
}

async function sendUpload<T>(path: string, form: FormData): Promise<T> {
  // Content-Type is deliberately NOT set: the browser must add the multipart
  // boundary, and setting it by hand produces a body the server cannot parse.
  const res = await fetch(`/api${path}`, {
    method: 'POST',
    headers: identityHeaders(),
    body: form,
    credentials: 'same-origin',
  });

  if (!res.ok) {
    let body: ApiErrorBody | null = null;
    try {
      body = (await res.json()) as ApiErrorBody;
    } catch {
      /* see above */
    }
    throw new ApiError(res.status, body, `upload failed with ${res.status}`);
  }
  return (await res.json()) as T;
}

/**
 * A small verb-shaped surface over `request`.
 *
 * Every call site reads `api.get<T>(path)` rather than
 * `request<T>(path, { method: 'GET' })`, which keeps the method next to the
 * path where a reader looks for it — and makes a mutation impossible to write
 * by accident when a query was meant.
 */
export const api = {
  get: <T>(path: string, signal?: AbortSignal) => request<T>(path, signal ? { signal } : {}),
  post: <T>(path: string, body?: unknown) => request<T>(path, { method: 'POST', body }),
  put: <T>(path: string, body?: unknown) => request<T>(path, { method: 'PUT', body }),
  del: <T>(path: string) => request<T>(path, { method: 'DELETE' }),
};

/**
 * A keyset page.
 *
 * ⚠ A CURSOR, NEVER AN OFFSET. `OFFSET 40000` is a table scan of forty
 * thousand rows the database then throws away, and it also SKIPS or REPEATS
 * rows when the underlying set changes between pages — which it does
 * constantly here, because scans keep finishing. The cursor is the last id
 * seen, and ids are UUIDv7, so ordering by id descending is chronological and
 * stable (docs/07-FRONTEND-SPEC.md §8).
 */
export interface Page<T> {
  items: T[];
  /** Null when there is no next page. */
  nextCursor: string | null;
}

/** pageParams builds the query string for a keyset page. */
export function pageParams(limit: number, cursor?: string | null): string {
  const params = new URLSearchParams({ limit: String(limit) });
  if (cursor) params.set('cursor', cursor);
  return params.toString();
}
