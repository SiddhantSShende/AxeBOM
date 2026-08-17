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
 * read, an XSS can exfiltrate. The refresh token lives in an HttpOnly cookie the
 * page cannot see, which is what makes a page reload able to recover a session
 * without the token ever being scriptable.
 */
let accessToken: string | null = null;

export function setAccessToken(token: string | null): void {
  accessToken = token;
}

export function getAccessToken(): string | null {
  return accessToken;
}

interface RequestOptions {
  method?: string | undefined;
  body?: unknown;
  /** Extra headers, e.g. the GitHub token for the repo picker. */
  headers?: Record<string, string> | undefined;
  signal?: AbortSignal | undefined;
}

/** request performs one API call and normalizes the failure modes. */
export async function request<T>(path: string, opts: RequestOptions = {}): Promise<T> {
  const headers: Record<string, string> = { ...opts.headers };
  if (opts.body !== undefined) headers['Content-Type'] = 'application/json';
  if (accessToken) headers['Authorization'] = `Bearer ${accessToken}`;

  // Built incrementally rather than with `body: undefined`: under
  // exactOptionalPropertyTypes an explicit undefined is not the same as an
  // absent property, and RequestInit does not accept one.
  const init: RequestInit = {
    method: opts.method ?? 'GET',
    headers,
    // Send the HttpOnly refresh cookie on same-origin calls.
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

/** upload posts multipart form data. Used for manifests and archives. */
export async function upload<T>(path: string, form: FormData): Promise<T> {
  const headers: Record<string, string> = {};
  if (accessToken) headers['Authorization'] = `Bearer ${accessToken}`;
  // Content-Type is deliberately NOT set: the browser must add the multipart
  // boundary, and setting it by hand produces a body the server cannot parse.

  const res = await fetch(`/api${path}`, {
    method: 'POST',
    headers,
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
