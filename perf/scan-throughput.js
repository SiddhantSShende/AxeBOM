/**
 * 100 concurrent scans.
 *
 * ⚠ THIS IS REALLY A TEST OF THE QUEUE AND THE REAPER, NOT OF SCAN SPEED.
 *
 * The orchestrator fans out one job per engine, so a hundred scans across six
 * engines is six hundred jobs contending for workers. What breaks first is not
 * throughput — it is the deadline reaper falling behind, so jobs that finished
 * are marked `timeout`, or jobs that hung are never marked at all.
 *
 * The assertion is therefore about STATUS CORRECTNESS under load, not latency.
 * A fast run that mislabels twenty scans is a worse outcome than a slow one that
 * labels all of them right: a compliance product reporting `timeout` for a scan
 * that succeeded has produced a false negative the customer trusts.
 *
 * ⚠ NEVER RUN. See perf/README.md — the thresholds are targets, not baselines.
 */

import http from 'k6/http';
import { check, fail, sleep } from 'k6';
import { Counter } from 'k6/metrics';

const BASE_URL = __ENV.BASE_URL;
const API_KEY = __ENV.API_KEY;
const PROJECT_ID = __ENV.PROJECT_ID;

const mislabelled = new Counter('scans_mislabelled');
const partial = new Counter('scans_partial');

export const options = {
  scenarios: {
    burst: { executor: 'per-vu-iterations', vus: 100, iterations: 1, maxDuration: '30m' },
  },
  thresholds: {
    // ⚠ ZERO, NOT A RATE. A scan whose reported status does not match its engine
    // runs is a wrong compliance artifact, and one is too many.
    scans_mislabelled: ['count==0'],
    http_req_failed: ['rate<0.01'],
  },
};

export default function () {
  if (!BASE_URL || !API_KEY || !PROJECT_ID) {
    fail('set BASE_URL, API_KEY and PROJECT_ID');
  }

  const started = http.post(
    `${BASE_URL}/api/v1/scans`,
    JSON.stringify({ project_id: PROJECT_ID, bom_types: ['sbom'] }),
    {
      headers: {
        Authorization: `Bearer ${API_KEY}`,
        'Content-Type': 'application/json',
        // Keyed per VU so a retry inside k6 does not create a second scan.
        'Idempotency-Key': `perf-${__VU}-${__ITER}`,
      },
    },
  );
  if (!check(started, { 'scan accepted': (r) => r.status === 202 })) return;

  const scanID = JSON.parse(started.body).id;
  let scan = null;

  // Poll to a terminal state. The interval is deliberately unaggressive:
  // hammering the status endpoint measures our own polling rather than the
  // orchestrator.
  for (let i = 0; i < 120; i += 1) {
    sleep(5);
    const res = http.get(`${BASE_URL}/api/v1/scans/${scanID}`, {
      headers: { Authorization: `Bearer ${API_KEY}` },
    });
    scan = JSON.parse(res.body);
    if (['completed', 'completed_with_errors', 'failed'].includes(scan.status)) break;
  }

  if (!scan) {
    fail('no scan status was ever read');
    return;
  }

  const runs = http.get(`${BASE_URL}/api/v1/scans/${scanID}/engine-runs`, {
    headers: { Authorization: `Bearer ${API_KEY}` },
  });
  const engineRuns = JSON.parse(runs.body).engine_runs ?? [];

  // ⚠ THE STATUS IS DERIVED MECHANICALLY, AND THIS RE-DERIVES IT INDEPENDENTLY.
  //
  //   all succeeded            -> completed
  //   any succeeded + any not  -> completed_with_errors
  //   none succeeded           -> failed
  //
  // A mismatch means the reaper or the aggregator is wrong under load, which is
  // exactly what this scenario exists to find.
  const succeeded = engineRuns.filter((r) => r.status === 'succeeded').length;
  const failed = engineRuns.filter((r) => ['failed', 'timeout'].includes(r.status)).length;

  let expected;
  if (succeeded > 0 && failed === 0) expected = 'completed';
  else if (succeeded > 0) expected = 'completed_with_errors';
  else expected = 'failed';

  if (scan.status !== expected) {
    mislabelled.add(1);
    console.error(
      `scan ${scanID} reports ${scan.status}; ${succeeded} engines succeeded and ` +
        `${failed} did not, which derives ${expected}`,
    );
  }
  if (scan.status === 'completed_with_errors') partial.add(1);

  check(scan, {
    // `partial` is a first-class status, not an error — a scan covering eleven
    // of twelve ecosystems is useful output plus a known gap.
    'scan reached a terminal status': () =>
      ['completed', 'completed_with_errors', 'failed'].includes(scan.status),
  });
}
