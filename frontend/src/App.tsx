/**
 * Application shell.
 *
 * ⚠ ROUTE-LEVEL CODE SPLITTING. The dependency explorer pulls in a virtualizer
 * and the report viewer pulls in the share dialog; neither belongs in the
 * bundle a user downloads to look at a project list. The budget is 250 KB
 * gzipped for the initial load (docs/07-FRONTEND-SPEC.md §8).
 */

import { Suspense, lazy } from 'react';
import { BrowserRouter, Link, NavLink, Route, Routes, useParams } from 'react-router';
import { SkeletonRows } from './components/States';
import { ThemeToggle } from './components/ThemeToggle';
import { ProjectList } from './routes/projects/ProjectList';
import { ProjectWizard } from './routes/projects/ProjectWizard';
import { ProjectDetail } from './routes/projects/ProjectDetail';

const GenerateFlow = lazy(() =>
  import('./routes/generate/GenerateFlow').then((m) => ({ default: m.GenerateFlow })),
);
const ScanProgressRoute = lazy(() =>
  import('./routes/scans/ScanProgress').then((m) => ({ default: m.ScanProgressRoute })),
);
const Dependencies = lazy(() =>
  import('./routes/dependencies/Dependencies').then((m) => ({ default: m.Dependencies })),
);
const Findings = lazy(() =>
  import('./routes/findings/Findings').then((m) => ({ default: m.Findings })),
);
const ReportViewer = lazy(() =>
  import('./routes/reports/ReportViewer').then((m) => ({ default: m.ReportViewer })),
);
const CampaignList = lazy(() =>
  import('./routes/campaigns/CampaignList').then((m) => ({ default: m.CampaignList })),
);
const CampaignWizard = lazy(() =>
  import('./routes/campaigns/CampaignWizard').then((m) => ({ default: m.CampaignWizard })),
);
const CampaignDetail = lazy(() =>
  import('./routes/campaigns/CampaignDetail').then((m) => ({ default: m.CampaignDetail })),
);
const Notifications = lazy(() =>
  import('./routes/settings/Notifications').then((m) => ({ default: m.Notifications })),
);

export function App() {
  return (
    <BrowserRouter>
      <div className="app">
        <Header />
        <main>
          {/*
            The fallback is a skeleton, not a spinner: a chunk arriving over a
            slow link should look like the page filling in, not like a stall.
          */}
          <Suspense fallback={<SkeletonRows rows={8} columns={4} />}>
            <Routes>
              <Route path="/" element={<ProjectList />} />
              <Route path="/projects" element={<ProjectList />} />
              <Route path="/projects/new" element={<ProjectWizard />} />
              <Route path="/projects/:id" element={<ProjectDetail />} />
              <Route
                path="/projects/:id/dependencies"
                element={
                  <ProjectTabs>
                    <Dependencies />
                  </ProjectTabs>
                }
              />
              <Route
                path="/projects/:id/findings"
                element={
                  <ProjectTabs>
                    <Findings />
                  </ProjectTabs>
                }
              />
              <Route path="/generate" element={<GenerateFlow />} />
              <Route path="/scans/:id" element={<ScanProgressRoute />} />
              <Route path="/reports/:id" element={<ReportViewer />} />
              <Route path="/campaigns" element={<CampaignList />} />
              <Route path="/campaigns/new" element={<CampaignWizard />} />
              <Route path="/campaigns/:id" element={<CampaignDetail />} />
              <Route path="/settings/notifications" element={<Notifications />} />
              <Route path="*" element={<NotFound />} />
            </Routes>
          </Suspense>
        </main>
      </div>
    </BrowserRouter>
  );
}

function Header() {
  return (
    <header className="app-header">
      <Link to="/projects" className="brand">
        EncoreBOM
      </Link>
      <nav aria-label="Primary">
        <NavLink to="/projects">Projects</NavLink>
        <NavLink to="/generate">Generate</NavLink>
        <NavLink to="/campaigns">Scheduled</NavLink>
        <NavLink to="/settings/notifications">Notifications</NavLink>
      </nav>
      <ThemeToggle />
    </header>
  );
}

function ProjectTabs({ children }: { children: React.ReactNode }) {
  const { id = '' } = useParams();
  return (
    <>
      <nav className="tabs" aria-label="Project sections">
        <NavLink to={`/projects/${id}`} end>
          Overview
        </NavLink>
        <NavLink to={`/projects/${id}/dependencies`}>Dependencies</NavLink>
        <NavLink to={`/projects/${id}/findings`}>Findings</NavLink>
      </nav>
      {children}
    </>
  );
}

/**
 * NotFound is deliberately indistinguishable from a cross-tenant 404.
 *
 * A resource belonging to another tenant must look exactly like one that does
 * not exist, or the difference becomes an oracle for enumerating ids.
 */
function NotFound() {
  return (
    <div className="state state-empty">
      <h3 className="state-title">Not found</h3>
      <p className="state-message">That page does not exist, or you do not have access to it.</p>
      <div className="state-actions">
        <Link className="btn" to="/projects">
          Back to projects
        </Link>
      </div>
    </div>
  );
}
