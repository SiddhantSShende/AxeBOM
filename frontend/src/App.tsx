import { BrowserRouter, Link, Route, Routes } from 'react-router';
import { useQuery } from '@tanstack/react-query';
import { ProjectList } from './routes/projects/ProjectList';
import { ProjectWizard } from './routes/projects/ProjectWizard';
import { ProjectDetail } from './routes/projects/ProjectDetail';

/**
 * Application shell.
 *
 * Phase 4 adds the projects module. Phase 10 replaces this shell with the full
 * application — dashboard, dependency explorer, findings, report viewer
 * (docs/07-FRONTEND-SPEC.md). The routes added here are the ones Phase 4 owns,
 * and they are built against the real API rather than mocked, so Phase 10
 * inherits working screens instead of a scaffold.
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

function GatewayStatus() {
  const { data, isError } = useQuery({
    queryKey: ['health'],
    queryFn: fetchHealth,
    retry: false,
  });

  if (isError) {
    return (
      <span className="status status-down" role="status">
        Gateway unreachable — run <code>task dev</code>
      </span>
    );
  }
  if (!data) return null;
  return (
    <span className="status status-up" role="status">
      {data.service} {data.status}
    </span>
  );
}

export function App() {
  return (
    <BrowserRouter>
      <nav className="topbar">
        <Link to="/projects" className="brand">
          EncoreBOM
        </Link>
        <GatewayStatus />
      </nav>

      <Routes>
        <Route path="/" element={<ProjectList />} />
        <Route path="/projects" element={<ProjectList />} />
        {/* Before /projects/:id, or "new" is read as an id. */}
        <Route path="/projects/new" element={<ProjectWizard />} />
        <Route path="/projects/:id" element={<ProjectDetail />} />
        <Route
          path="*"
          element={
            <main className="shell">
              <h1>Not found</h1>
              <Link to="/projects">Back to projects</Link>
            </main>
          }
        />
      </Routes>
    </BrowserRouter>
  );
}
