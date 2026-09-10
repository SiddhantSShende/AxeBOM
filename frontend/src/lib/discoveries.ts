/**
 * Live discovery counts — what a scan is finding, as it finds it.
 *
 * ⚠ THESE TURN ENGINE CLAIMS INTO A NUMBER A CUSTOMER READS, which is why they
 * are here and tested rather than inline in the page. `events.ScanEventV1.Metrics`
 * carries one map per engine result; several engines reporting the same thing is
 * the normal case, so folding them is a judgement, not arithmetic.
 *
 * ⚠ COUNTS AND KINDS ONLY. The server holds a metric KEY to the same no-content
 * rule as a message (`events.SanitizeDiscoveries`) — no path, no URL, nothing out
 * of the scanned code, because BOM content is confidential under CERT-In §5.3.
 * Nothing here may reconstruct a name or a location from a key.
 */

/**
 * tallyDiscoveries folds every engine's counts into one figure per kind.
 *
 * ⚠ MAX, NOT SUM, AND THIS IS THE WHOLE REASON THE FUNCTION EXISTS. Several
 * engines finding the SAME thing is the normal case and the point of running
 * them — `ai-bom`, `airom` and `cdxgen-ai` all report the one Llama model in
 * the ai-langchain fixture. Adding their claims would print "3 AI models" for a
 * repository holding one, and a number nobody found is exactly the fabrication
 * this build is not allowed to produce.
 *
 * So it reports the largest single claim: the most any one engine says it saw.
 * That is a real observation by a real engine, and it is honest in the
 * direction that matters — the merged document (which dedups on `model_key`,
 * 03-NORMALIZER-SPEC §1.5) is what the report counts from, and this page says
 * so underneath the chips.
 */
export function tallyDiscoveries(
  byEngine: Record<string, Record<string, number>>,
): Record<string, number> {
  const totals: Record<string, number> = {};
  for (const metrics of Object.values(byEngine)) {
    for (const [key, count] of Object.entries(metrics)) {
      totals[key] = Math.max(totals[key] ?? 0, count);
    }
  }
  return totals;
}

/** sortedCounts orders a metric map largest-first, ties broken by key, so the
 *  chips do not reshuffle on every frame the way Object.entries would. */
export function sortedCounts(metrics: Record<string, number>): [string, number][] {
  return Object.entries(metrics).sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
}

/**
 * metricLabel turns a metric key into English.
 *
 * ⚠ DERIVED FROM THE KEY, NOT LOOKED UP IN A TABLE. A table would silently drop
 * every kind a future engine reports — the live feed would show "3" next to
 * nothing, or nothing at all, for exactly the newest capability. So an unknown
 * key still renders honestly, as itself, made readable: `ai_asset.vector_store`
 * → "vector stores", `components` → "components". The only lookup is which
 * words are acronyms, and a miss there costs a lowercase word, not a lost count.
 */
const ACRONYMS = new Set(['ai', 'rag', 'mcp', 'llm', 'api', 'ml', 'oci', 'sbom', 'cve']);

export function metricLabel(key: string, count: number): string {
  // `ai_asset.vector_store` names a family and a member; the family is already
  // said by the surrounding UI, and "vector stores" is what a person calls it.
  const leaf = key.slice(key.lastIndexOf('.') + 1);
  const words = leaf.split('_').filter(Boolean);
  if (words.length === 0) return key;

  const last = words.length - 1;
  return words
    .map((w, i) => (i === last ? plural(w, count) : w))
    .map((w) => (ACRONYMS.has(w) ? w.toUpperCase() : w))
    .join(' ');
}

/**
 * plural agrees the noun with the count, in both directions.
 *
 * ⚠ IT HAS TO SINGULARIZE TOO, WHICH IS WHY IT IS NOT ONE LINE. Engine authors
 * name a key for the kind, plurally — `ai_models`, `vulnerabilities` — and a
 * count of exactly one is the ORDINARY case on this page: the ai-langchain
 * fixture holds one model. "1 AI models" reads as a broken page next to a
 * number that is in fact correct, which is the worst way to be wrong here.
 *
 * Deliberately the crude rule, and it is allowed to be. Every key is a
 * lowercase ASCII identifier, so an irregular English plural would have to be
 * chosen on purpose; if one ever is, the cost is a misspelled word beside a
 * right number, and reaching for a pluralization dependency to avoid that is
 * not a trade worth making.
 */
function plural(word: string, count: number): string {
  const one = singular(word);
  if (count === 1) return one;
  if (one.endsWith('y') && !/[aeiou]y$/.test(one)) return `${one.slice(0, -1)}ies`;
  return one.endsWith('s') ? one : `${one}s`;
}

/** singular strips the plural an engine author wrote into the key. `ss` is
 *  excluded because "address" is not "addres". */
function singular(word: string): string {
  if (word.endsWith('ies') && word.length > 4) return `${word.slice(0, -3)}y`;
  if (word.endsWith('sses')) return word.slice(0, -2);
  if (word.endsWith('s') && !word.endsWith('ss')) return word.slice(0, -1);
  return word;
}
