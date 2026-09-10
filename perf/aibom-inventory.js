/**
 * The AI inventory endpoint, against a project with a real number of models.
 *
 * ⚠ THIS SCENARIO EXISTS BECAUSE THE ENDPOINT WAS 1 + 3N ROUND TRIPS. Every
 * model cost three more queries — its datasets, its dependencies, the engines
 * that found it — inside one HTTP request, inside one tenant transaction,
 * holding one pooled connection for all of them. Three models cost eleven
 * queries and nothing looks wrong. Two hundred cost six hundred.
 *
 * That is the shape of scaling bug this repository is most exposed to, and the
 * reason is structural rather than careless: a fixture repository has three
 * models, so the per-model loop is invisible in every test and every demo, and
 * becomes visible only to the customer with the largest monorepo — who reports
 * it as "the AI page is slow", not as an error, while every dashboard is green.
 *
 * ⚠ THE ASSERTION IS THE SLOPE, NOT THE LATENCY. An absolute threshold passes on
 * a fast machine with the N+1 still in place and fails on a slow one without it;
 * it measures the hardware, not the query. This measures how much SLOWER the
 * page gets as a project holds more models — which is the property that actually
 * changed. `perf/dependencies-page.js` makes the same argument about OFFSET, and
 * for the same reason.
 *
 * ⚠ NEVER RUN AT SCALE. See perf/README.md. The endpoint was exercised live
 * against a three-model project; nothing has yet fed it two hundred, so the
 * numbers below are targets and the scenario is what turns them into baselines.
 */

import http from "k6/http";
import { check, fail } from "k6";
import { Trend } from "k6/metrics";

const BASE_URL = __ENV.BASE_URL;
const API_KEY = __ENV.API_KEY;

// ⚠ TWO PROJECTS, AND BOTH MUST BE REAL AIBOM SCANS. SMALL_PROJECT_ID has a
// handful of models (the ai-langchain fixture's three); LARGE_PROJECT_ID has as
// many as the fixture corpus can produce. Comparing one project against itself
// would measure caching; comparing a scanned project against an empty one would
// measure an empty state.
const SMALL = __ENV.SMALL_PROJECT_ID;
const LARGE = __ENV.LARGE_PROJECT_ID;

const smallMs = new Trend("inventory_small_ms");
const largeMs = new Trend("inventory_large_ms");

export const options = {
  scenarios: {
    steady: { executor: "constant-vus", vus: 5, duration: "1m" },
  },
  thresholds: {
    inventory_small_ms: ["p(95)<400"],
    // ⚠ NOT 3× THE SMALL PAGE. The endpoint returns more DATA for a bigger
    // project, and serializing it legitimately costs more; what must not grow
    // is the number of round trips. Four times a page with two orders of
    // magnitude more models is generous for serialization and nowhere near
    // enough for 3N queries.
    inventory_large_ms: ["p(95)<1600"],
    http_req_failed: ["rate<0.01"],
  },
};

function inventory(projectId, name) {
  const res = http.get(`${BASE_URL}/api/v1/aibom/${projectId}/models`, {
    headers: { Authorization: `Bearer ${API_KEY}` },
    tags: { name },
  });
  check(res, { [`${name} returned 200`]: (r) => r.status === 200 });
  return res;
}

export default function () {
  if (!BASE_URL || !API_KEY || !SMALL || !LARGE) {
    fail("set BASE_URL, API_KEY, SMALL_PROJECT_ID and LARGE_PROJECT_ID");
  }

  const small = inventory(SMALL, "inventory-small");
  const large = inventory(LARGE, "inventory-large");
  smallMs.add(small.timings.duration);
  largeMs.add(large.timings.duration);

  const smallModels = JSON.parse(small.body).ai_models.length;
  const largeModels = JSON.parse(large.body).ai_models.length;

  // ⚠ NOT A PASS. Two projects with the same number of models prove nothing
  // about how the endpoint scales, and a green run that proved nothing is worse
  // than a red one — it is a baseline somebody will later cite.
  if (largeModels < smallModels * 10) {
    fail(
      `LARGE_PROJECT_ID has ${largeModels} models and SMALL_PROJECT_ID has ${smallModels}; ` +
        `this scenario needs at least a 10x difference to say anything about scaling`,
    );
  }

  check(null, {
    "the large inventory did not scale with the model count": () =>
      large.timings.duration < Math.max(small.timings.duration * 4, 200),
  });
}
