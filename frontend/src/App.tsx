import { useQuery } from '@tanstack/react-query';
import { BOM_TYPES } from './lib/bomTypes';

/**
 * Phase 0 scaffold.
 *
 * Its only job is to prove the toolchain works end to end: React renders,
 * TanStack Query fetches through the Vite proxy, and the gateway answers.
 * Phase 10 replaces this with the real application (docs/07-FRONTEND-SPEC.md).
 */

interface Health {
  status: string;
  service: string;
  version?: string;
}

async function fetchHealth(): Promise<Health> {
  const res = await fetch('/api/healthz');
  if (!res.ok) throw Object.assign(new Error('gateway unhealthy'), { status: res.status });
  return res.json() as Promise<Health>;
}

export function App() {
  const { data, isPending, isError, error } = useQuery({
    queryKey: ['health'],
    queryFn: fetchHealth,
    retry: false,
  });

  return (
    <main className="shell">
      <header>
        <h1>EncoreBOM</h1>
        <p className="tagline">Bill of Materials &amp; Software Composition Analysis</p>
      </header>

      <section aria-labelledby="bom-types-heading">
        <h2 id="bom-types-heading">BOM types</h2>
        {/*
          Every chip carries glyph + label + colour. Colour is reinforcement,
          never the signal — WCAG 1.4.1. See docs/07-FRONTEND-SPEC.md §2.
        */}
        <ul className="chips">
          {BOM_TYPES.map((t) => (
            <li key={t.id} className="chip" data-bom={t.id.toLowerCase()}>
              <span aria-hidden="true">{t.glyph}</span>
              <span>{t.id}</span>
              <span className="chip-note">{t.note}</span>
            </li>
          ))}
        </ul>
      </section>

      <section aria-labelledby="status-heading">
        <h2 id="status-heading">Gateway</h2>
        {isPending && (
          <p className="status" aria-live="polite">
            Checking…
          </p>
        )}
        {isError && (
          <p className="status status-down" role="status">
            Unreachable — start the stack with <code>task dev</code>
            {error instanceof Error ? ` (${error.message})` : null}
          </p>
        )}
        {data && (
          <p className="status status-up" role="status">
            {data.service} is {data.status}
            {data.version ? ` (${data.version})` : null}
          </p>
        )}
      </section>

      <footer>
        <p>
          Phase 0 scaffold. See <code>docs/STATE.md</code> for what exists and{' '}
          <code>docs/phases/</code> for what comes next.
        </p>
      </footer>
    </main>
  );
}
