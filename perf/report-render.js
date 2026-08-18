/**
 * A Complete BOM rendered at the component cap.
 *
 * ⚠ THE FAILURE THIS LOOKS FOR IS MEMORY, NOT TIME.
 *
 * The report writer is a push iterator rather than a slice precisely so a
 * 250k-component workbook is never held in memory twice — once as rows and once
 * as the encoded file. A regression to materialising the rows does not make the
 * render slow; it makes the pod hit its limit and get OOM-killed, and the
 * customer sees a report stuck at `rendering` forever.
 *
 * So this watches for a render that never terminates, not for one that takes a
 * while. A Complete BOM is ALLOWED to take minutes, and a tight latency
 * threshold here would produce a flaky scenario that gets ignored.
 *
 * ⚠ NEVER RUN. See perf/README.md — the thresholds are targets, not baselines.
 */

import http from 'k6/http';
import { check, fail, sleep } from 'k6';
import { Trend } from 'k6/metrics';

const BASE_URL = __ENV.BASE_URL;
const API_KEY = __ENV.API_KEY;
const SCAN_ID = __ENV.SCAN_ID;

const renderSeconds = new Trend('render_seconds');

export const options = {
  scenarios: {
    // Four at once: enough to contend for the render worker without turning
    // this into a queue test, which scan-throughput.js already is.
    render: { executor: 'per-vu-iterations', vus: 4, iterations: 1, maxDuration: '30m' },
  },
  thresholds: {
    render_seconds: ['p(95)<600'],
    http_req_failed: ['rate<0.01'],
  },
};

export default function () {
  if (!BASE_URL || !API_KEY || !SCAN_ID) {
    fail('set BASE_URL, API_KEY and SCAN_ID');
  }

  const queued = http.post(
    `${BASE_URL}/api/v1/reports`,
    JSON.stringify({
      scan_id: SCAN_ID,
      bom_type: 'sbom',
      // ⚠ Complete, not top_level. Top-level is a few hundred components and
      // would exercise none of this.
      level: 'complete',
      standard: 'cyclonedx',
      format: 'xlsx',
    }),
    { headers: { Authorization: `Bearer ${API_KEY}`, 'Content-Type': 'application/json' } },
  );

  // 202: rendering is async precisely because a synchronous request would time
  // out, the client would retry, and the worker would render it twice.
  if (!check(queued, { 'render queued (202)': (r) => r.status === 202 })) return;

  const reportID = JSON.parse(queued.body).id;
  const startedAt = Date.now();
  let report = null;

  for (let i = 0; i < 120; i += 1) {
    sleep(5);
    const res = http.get(`${BASE_URL}/api/v1/reports/${reportID}`, {
      headers: { Authorization: `Bearer ${API_KEY}` },
    });
    report = JSON.parse(res.body);
    if (['ready', 'failed'].includes(report.status)) break;
  }

  if (!report || !['ready', 'failed'].includes(report.status)) {
    // ⚠ THE OOM SIGNATURE. A render that never terminates is what a
    // materialised row set looks like from outside: no error, no failure, just a
    // report stuck at `rendering` while the worker is killed and restarts.
    fail(
      `report ${reportID} never reached a terminal status. A render that hangs ` +
        `rather than failing is the signature of the writer holding the whole ` +
        `report in memory and the pod being OOM-killed mid-stream.`,
    );
    return;
  }

  renderSeconds.add((Date.now() - startedAt) / 1000);

  check(report, {
    'render succeeded': () => report.status === 'ready',
    // Truncation is honest output rather than a failure — but it must be
    // DECLARED, so a reader knows the report is not the whole picture.
    'a truncated report says so': () => !report.truncated || !!report.truncation_note,
  });
}
