import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  ApiError,
  downloadFile,
  setAccessToken,
  setTokenRefresher,
  triggerSave,
  type DownloadedFile,
} from './api';

function jsonResponse(body: unknown, init: ResponseInit = {}): Response {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
    ...init,
  });
}

function blobResponse(
  bytes: string,
  headers: Record<string, string> = {},
  status = 200,
): Response {
  return new Response(bytes, { status, headers });
}

describe('downloadFile', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    setAccessToken(null);
    setTokenRefresher(null);
  });

  // ⚠ THE REGRESSION THIS GUARDS. A plain `<a href="/api/v1/reports/{id}/
  // download">` cannot authenticate here — the access token lives in memory
  // only, never a cookie — so the request 401s before a single byte returns
  // and the download silently does nothing. downloadFile exists specifically
  // to send the same Authorization header every other authenticated call on
  // this page already sends.
  it('sends the bearer token, unlike a plain anchor navigation', async () => {
    setAccessToken('token-abc');
    const fetchMock = vi.fn().mockResolvedValue(
      blobResponse('%PDF-1.4 fake bytes', {
        'Content-Disposition': 'attachment; filename="report.pdf"',
      }),
    );
    vi.stubGlobal('fetch', fetchMock);

    await downloadFile('/v1/reports/r1/download');

    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe('/api/v1/reports/r1/download');
    expect((init.headers as Record<string, string>)['Authorization']).toBe('Bearer token-abc');
  });

  it('reads the filename the server actually chose, never guessing one', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(
        blobResponse('...', {
          'Content-Disposition': 'attachment; filename="sbom-complete-2026-08-30.cdx.json"',
        }),
      ),
    );

    const file = await downloadFile('/v1/reports/r1/download');
    expect(file.filename).toBe('sbom-complete-2026-08-30.cdx.json');
  });

  it('falls back to a plain name when Content-Disposition is missing, rather than throwing', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(blobResponse('...')));

    const file = await downloadFile('/v1/reports/r1/download');
    expect(file.filename).toBe('download');
  });

  it('surfaces a failure as ApiError, decoding the server error body', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(
        jsonResponse(
          { error: { code: 'REPORT_RENDER_FAILED', message: 'this report is not ready' } },
          { status: 409 },
        ),
      ),
    );

    await expect(downloadFile('/v1/reports/r1/download')).rejects.toMatchObject({
      code: 'REPORT_RENDER_FAILED',
    });
  });

  // Same contract as request()'s own retry: a token that expired between
  // page load and the click gets ONE silent renewal, not a dead button.
  it('retries once after a silent renewal on a 401, then succeeds', async () => {
    let calls = 0;
    vi.stubGlobal(
      'fetch',
      vi.fn().mockImplementation(() => {
        calls += 1;
        if (calls === 1) {
          return Promise.resolve(
            jsonResponse({ error: { code: 'AUTH_TOKEN_EXPIRED', message: 'expired' } }, { status: 401 }),
          );
        }
        return Promise.resolve(blobResponse('bytes', { 'Content-Disposition': 'attachment; filename="r.pdf"' }));
      }),
    );
    setTokenRefresher(() => {
      setAccessToken('renewed');
      return Promise.resolve('renewed');
    });

    const file = await downloadFile('/v1/reports/r1/download');
    expect(file.filename).toBe('r.pdf');
    expect(calls).toBe(2);
  });

  it('does not retry a second 401 forever — a fresh rejection is not an expiry', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(
        jsonResponse({ error: { code: 'AUTH_TOKEN_INVALID', message: 'invalid' } }, { status: 401 }),
      ),
    );
    setTokenRefresher(() => Promise.resolve('renewed'));

    await expect(downloadFile('/v1/reports/r1/download')).rejects.toBeInstanceOf(ApiError);
  });
});

describe('triggerSave', () => {
  it('opens a same-origin blob: URL through a synthetic click, and revokes it after', async () => {
    const createObjectURL = vi.fn().mockReturnValue('blob:fake-url');
    const revokeObjectURL = vi.fn();
    vi.stubGlobal('URL', { ...URL, createObjectURL, revokeObjectURL });

    const clicked = vi.fn();
    const realCreateElement = document.createElement.bind(document);
    const createElementSpy = vi.spyOn(document, 'createElement').mockImplementation((tag) => {
      const el = realCreateElement(tag);
      if (tag === 'a') el.click = clicked;
      return el;
    });

    const file: DownloadedFile = { blob: new Blob(['x']), filename: 'report.pdf' };
    triggerSave(file);

    expect(createObjectURL).toHaveBeenCalledWith(file.blob);
    expect(clicked).toHaveBeenCalledTimes(1);

    // The revoke is scheduled, not immediate — see triggerSave's own doc
    // comment on why revoking in the same task can race the browser.
    expect(revokeObjectURL).not.toHaveBeenCalled();
    await new Promise((r) => setTimeout(r, 0));
    expect(revokeObjectURL).toHaveBeenCalledWith('blob:fake-url');

    createElementSpy.mockRestore();
  });
});
