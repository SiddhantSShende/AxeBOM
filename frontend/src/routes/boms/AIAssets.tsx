/**
 * The AI asset explorer — prompts, vector stores, RAG pipelines, endpoints,
 * embeddings, agents, tools and MCP servers found in the repository.
 *
 * ⚠ NONE OF THIS IS CERT-In TABLE 10, AND THE SCREEN SAYS SO. Table 10 describes
 * a MODEL; an AI system is mostly the things around the model, and a BOM that
 * lists `gpt-4o` and stops has not described what was built. These rows are
 * scored against `docs/reference/aibom-operational-v1.yaml` into the document's
 * SUPPLEMENTARY coverage and never into `completeness_pct` — a supplementary
 * number rendered as if it were compliance is exactly the false claim invariant 3
 * exists to stop.
 *
 * ⚠ DISCOVERED IN SOURCE. PARSED, NOT EVALUATED. A prompt file listed here was
 * read off disk by an engine; nothing tested it, graded it, or judged whether it
 * is safe. `frontend/src/lib/aibom.claims.test.ts` holds this file to that.
 */

import { useMemo } from 'react';
import { EmptyState } from '../../components/States';
import { NotProvided, ProvenanceChips } from '../../components/Chips';
import type { AIAsset } from '../../lib/aibom';

export function AIAssets({ assets }: { assets: AIAsset[] }) {
  // Grouped by kind, and the KINDS COME FROM THE DATA. A fixed list of headings
  // would silently drop whatever a future engine starts reporting — the one
  // case where a new capability most needs to be visible.
  const groups = useMemo(() => {
    const byType = new Map<string, AIAsset[]>();
    for (const a of assets) {
      const list = byType.get(a.asset_type);
      if (list) list.push(a);
      else byType.set(a.asset_type, [a]);
    }
    return [...byType.entries()].sort(
      (a, b) => b[1].length - a[1].length || a[0].localeCompare(b[0]),
    );
  }, [assets]);

  if (assets.length === 0) {
    return (
      <EmptyState
        title="No AI assets discovered"
        guidance="airom and cdxgen-ai read prompts, vector stores, RAG pipelines and outbound model endpoints out of the source the fetcher materialized. Nothing here means no engine matched one — not that the repository has none."
      />
    );
  }

  return (
    <section className="panel" aria-labelledby="ai-assets-heading">
      <h2 id="ai-assets-heading">AI assets</h2>
      <p className="field-hint">
        Discovered in source, and scored separately. These are AI system components beyond the model
        itself; they count towards this project&apos;s supplementary AI coverage and never towards
        its CERT-In completeness.
      </p>
      {groups.map(([type, items]) => (
        <div key={type} className="asset-group">
          <h3 className="asset-group-title">
            {assetTypeLabel(type)} <span className="asset-group-count">{items.length}</span>
          </h3>
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th scope="col">Name</th>
                  <th scope="col">Provider</th>
                  <th scope="col">Found by</th>
                  <th scope="col">Where</th>
                  <th scope="col">Serves</th>
                  <th scope="col">Reported attributes</th>
                </tr>
              </thead>
              <tbody>
                {items.map((a) => (
                  <tr key={a.asset_key}>
                    <td>
                      <span title={a.asset_key}>{a.name}</span>
                    </td>
                    <td>{a.provider ? a.provider : <NotProvided />}</td>
                    <td>
                      <ProvenanceChips engines={foundBy(a)} />
                    </td>
                    <td>
                      <Evidence lines={a.evidence} />
                    </td>
                    <td>
                      {a.serves_model_key ? (
                        <code className="mono-sm">{a.serves_model_key}</code>
                      ) : (
                        <NotProvided />
                      )}
                    </td>
                    <td>
                      <Attributes attributes={a.attributes} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      ))}
    </section>
  );
}

/**
 * foundBy reads the engines out of the asset's own attributes.
 *
 * ⚠ IT LIVES IN `attributes`, NOT IN A COLUMN, and that is deliberate rather
 * than sloppy: `normalize.ai_assets` has no provenance table the way
 * `ai_models` does, so the merge writes the agreeing engines into the JSON blob
 * it already keeps. Reading it here is the honest thing to do; inventing a
 * chip when it is absent would not be.
 */
function foundBy(asset: AIAsset): string[] {
  const raw = asset.attributes?.found_by;
  if (!Array.isArray(raw)) return [];
  return raw.filter((e): e is string => typeof e === 'string');
}

/** Evidence renders where an engine says it saw the thing — a path, or a
 *  `path:line`. Truncated with the rest on hover: a RAG pipeline referenced
 *  from a dozen files would otherwise set the row height for the table. */
function Evidence({ lines }: { lines: string[] }) {
  if (lines.length === 0) return <NotProvided />;
  const [first, ...rest] = lines;
  return (
    <span title={lines.join('\n')}>
      <code className="mono-sm">{first}</code>
      {rest.length > 0 && <span className="evidence-more"> +{rest.length}</span>}
    </span>
  );
}

/**
 * Attributes renders whatever the engine reported about this asset, as it
 * reported it.
 *
 * ⚠ NOT A FIXED SET OF COLUMNS. Each asset kind carries different attributes —
 * a vector store has a dimension count, an endpoint has a transport, a prompt
 * has the engine's own confidence — and every one of them comes from a
 * different engine's output shape. Rendering the keys the data actually has
 * shows the reader what was found; a fixed set would show blanks for the
 * columns this kind never had and hide the fields it did.
 */
function Attributes({ attributes }: { attributes: Record<string, unknown> | undefined }) {
  const shown = Object.entries(attributes ?? {})
    // `found_by` has its own column; repeating it here is noise.
    .filter(([key]) => key !== 'found_by')
    .map(([key, value]) => [key, scalar(value)] as const)
    .filter((pair): pair is readonly [string, string] => pair[1] !== null)
    .sort((a, b) => a[0].localeCompare(b[0]));

  if (shown.length === 0) return <NotProvided />;
  return (
    <span className="attr-list">
      {shown.map(([key, value]) => (
        <span className="attr" key={key}>
          <span className="attr-key">{key.replace(/_/g, ' ')}</span>
          <span className="attr-value">{value}</span>
        </span>
      ))}
    </span>
  );
}

/** scalar renders a JSON value a table cell can hold, or null for one it
 *  cannot. A nested object flattened into `[object Object]` is worse than
 *  omitted — the detail is in the raw artifact and the export either way. */
function scalar(value: unknown): string | null {
  if (typeof value === 'string') return value || null;
  if (typeof value === 'number' || typeof value === 'boolean') return String(value);
  if (Array.isArray(value)) {
    const parts = value.filter((v) => typeof v === 'string' || typeof v === 'number');
    return parts.length > 0 ? parts.join(', ') : null;
  }
  return null;
}

/** assetTypeLabel makes an asset_type readable without a lookup table — a kind
 *  a future engine invents still gets a heading rather than disappearing. */
function assetTypeLabel(type: string): string {
  const words = type.split('_');
  return words
    .map((w) => (w === 'rag' || w === 'mcp' || w === 'llm' ? w.toUpperCase() : w))
    .join(' ')
    .replace(/^./, (c) => c.toUpperCase());
}
