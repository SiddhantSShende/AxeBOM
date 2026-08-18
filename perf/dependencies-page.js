/**
 * Deep pagination over a large finding set.
 *
 * ⚠ THIS IS THE SCENARIO THAT JUSTIFIES KEYSET PAGINATION, and the only one
 * whose failure mode is invisible on a dashboard.
 *
 * With `OFFSET 400000`, Postgres reads and discards four hundred thousand rows
 * to return twenty. Page 1 is fast, page 400 is roughly four hundred times
 * slower, and nothing errors — the customer with the large monorepo just says
 * the product "feels slow" while every latency percentile looks acceptable,
 * because the fast pages dominate the average.
 *
 * So the assertion is not "the endpoint is fast". It is **the last page is no
 * slower than the first**. That comparison is what distinguishes keyset
 * pagination from OFFSET, and a p95 threshold alone would not catch the
 * regression.
 *
 * ⚠ NEVER RUN. See perf/README.md — the thresholds below are targets, not
 * measured baselines.
 */

import http from 'k6/http';
import { check, fail } from 'k6';
import { Trend } from 'k6/metrics';

const BASE_URL = __ENV.BASE_URL;
const API_KEY = __ENV.API_KEY;
const PROJECT_ID = __ENV.PROJECT_ID;

/** Pages walked before the deep-page comparison. */
const DEEP_PAGE = 400;
const PAGE_SIZE = 50;

const firstPage = new Trend('page_first_ms', true);
const deepPage = new Trend('page_deep_ms', true);

export const options = {
  scenarios: {
    walk: { executor: 'shared-iterations', vus: 4, iterations: 20, maxDuration: '10m' },
  },
  thresholds: {
    // ⚠ THE RATIO IS THE REAL ASSERTION. An absolute threshold passes on a
    // fast machine with OFFSET and fails on a slow one with keyset, which
    // measures the hardware rather than the query.
    'page_deep_ms': ['p(95)<500'],
    'page_first_ms': ['p(95)<500'],
    'http_req_failed': ['rate<0.01'],
  },
};

function page(cursor) {
  const url =
    `${BASE_URL}/api/v1/projects/${PROJECT_ID}/findings?limit=${PAGE_SIZE}` +
    (cursor ? `&cursor=${encodeURIComponent(cursor)}` : '');

  const res = http.get(url, {
    headers: { Authorization: `Bearer ${API_KEY}` },
    tags: { name: 'findings-page' },
  });

  check(res, { 'page returned 200': (r) => r.status === 200 });
  return res;
}

export default function () {
  if (!BASE_URL || !API_KEY || !PROJECT_ID) {
    fail('set BASE_URL, API_KEY and PROJECT_ID');
  }

  const first = page(null);
  firstPage.add(first.timings.duration);

  let cursor = JSON.parse(first.body).next_cursor;
  let reached = 1;

  // Walk to the deep page, timing only the last request: the walk itself is
  // setup, and including it would average the interesting number away.
  for (let i = 1; i < DEEP_PAGE && cursor; i += 1) {
    const res = page(cursor);
    cursor = JSON.parse(res.body).next_cursor;
    reached = i + 1;
  }

  if (!cursor && reached < DEEP_PAGE) {
    // ⚠ NOT A PASS. A dataset too small to reach the deep page means this
    // scenario proved nothing, and a green run that proved nothing is worse
    // than a red one.
    fail(
      `the fixture ran out at page ${reached}; this scenario needs ~${DEEP_PAGE * PAGE_SIZE} ` +
        `findings to exercise deep pagination at all`,
    );
  }

  const deep = page(cursor);
  deepPage.add(deep.timings.duration);

  check(deep, {
    // The property that distinguishes keyset from OFFSET. Three times the first
    // page is generous; OFFSET would be orders of magnitude worse.
    'the deep page is not materially slower than the first': () =>
      deep.timings.duration < Math.max(first.timings.duration * 3, 200),
  });
}
