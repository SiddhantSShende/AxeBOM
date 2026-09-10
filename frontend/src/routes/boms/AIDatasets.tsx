/**
 * Training and evaluation datasets, across every discovered model.
 *
 * ⚠ A DATASET REACHES THIS TABLE ONE WAY: THE MODEL'S OWN CARD SAID SO. Nothing
 * in AxeBOM inspects training data. `workers/aienrich` reads the `datasets` key
 * out of a Hugging Face model card and records what the publisher wrote there —
 * so an empty table means no card named one, which is the common case and is not
 * the same as "this model was trained on nothing".
 *
 * That distinction is the whole reason this screen states its provenance in the
 * caption rather than presenting the rows as findings.
 */

import { EmptyState } from '../../components/States';
import { NotProvided } from '../../components/Chips';
import type { AIDataset, AIModel } from '../../lib/aibom';

interface Row {
  dataset: AIDataset;
  modelName: string;
  modelKey: string;
}

export function AIDatasets({ models }: { models: AIModel[] }) {
  const rows: Row[] = models.flatMap((m) =>
    m.datasets.map((d) => ({ dataset: d, modelName: m.model_name, modelKey: m.model_key })),
  );

  if (rows.length === 0) {
    return (
      <EmptyState
        title="No datasets reported"
        guidance="A dataset appears here when a model's own card names one. No engine inspects training data, so an absent dataset means no card declared it — CERT-In element 05 stays not-provided, and counts as a gap rather than being hidden."
      />
    );
  }

  return (
    <section className="panel" aria-labelledby="ai-datasets-heading">
      <h2 id="ai-datasets-heading">Datasets</h2>
      <div className="table-wrap">
        <table className="table">
          <caption className="table-caption">
            Reported by each model&apos;s own card. Nothing here was read from the data itself.
          </caption>
          <thead>
            <tr>
              <th scope="col">Dataset</th>
              <th scope="col">Used by</th>
              <th scope="col">Version</th>
              <th scope="col">Format</th>
              <th scope="col">License</th>
              <th scope="col">Source</th>
              <th scope="col">Stated limitations</th>
            </tr>
          </thead>
          <tbody>
            {rows.map(({ dataset, modelName, modelKey }) => (
              <tr key={`${modelKey}|${dataset.name}|${dataset.version ?? ''}`}>
                <td>{dataset.name}</td>
                <td title={modelKey}>{modelName}</td>
                <td>{dataset.version ? dataset.version : <NotProvided />}</td>
                <td>{dataset.format ? dataset.format : <NotProvided />}</td>
                <td>{dataset.license ? dataset.license : <NotProvided />}</td>
                <td>
                  {dataset.source ? (
                    <code className="mono-sm">{dataset.source}</code>
                  ) : (
                    <NotProvided />
                  )}
                </td>
                <td>{dataset.limitations ? dataset.limitations : <NotProvided />}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}
