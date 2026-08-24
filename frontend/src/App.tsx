/**
 * Application shell.
 *
 * ⚠ ROUTE-LEVEL CODE SPLITTING. The dependency explorer pulls in a virtualizer
 * and the report viewer pulls in the share dialog; neither belongs in the
 * bundle a user downloads to look at a project list. The budget is 250 KB
 * gzipped for the initial load (docs/07-FRONTEND-SPEC.md §8).
 */

import { Suspense, lazy, type ReactNode } from 'react';
import { BrowserRouter, Link, NavLink, Route, Routes, useParams } from 'react-router';
import { SkeletonRows } from './components/States';
import { ThemeToggle } from './components/ThemeToggle';
import { AuthProvider } from './lib/AuthContext';
import { useAuth } from './lib/useAuth';
import { AuthCallback, NoAccess, SignIn, SilentCallback } from './routes/auth/AuthRoutes';
import { OrgSwitcher } from './components/OrgSwitcher';
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
const HardwareImport = lazy(() =>
  import('./routes/hbom/HardwareImport').then((m) => ({ default: m.HardwareImport })),
);
const HardwareTree = lazy(() =>
  import('./routes/hbom/HardwareTree').then((m) => ({ default: m.HardwareTree })),
);

export function App() {
  return (
    <BrowserRouter>
      <AuthProvider>
        <Routes>
          {/*
            ⚠ MOUNTED OUTSIDE THE SHELL AND OUTSIDE RequireAuth.
            The callback routes are how a user BECOMES authenticated; putting
            them behind the gate is a redirect loop, and rendering the header
            around the silent iframe boots a second application inside it.
          */}
          <Route path="/auth/callback" element={<AuthCallback />} />
          <Route path="/auth/silent" element={<SilentCallback />} />
          <Route path="*" element={<Shell />} />
        </Routes>
      </AuthProvider>
    </BrowserRouter>
  );
}

/**
 * RequireAuth gates everything the API backs.
 *
 * ⚠ IT RENDERS NOTHING WHILE THE SESSION IS BEING PROBED. Rendering the
 * children first and correcting afterwards means every screen fires its
 * queries with no token, collects a 401, and shows an error for a session that
 * was about to resume — which is exactly what `no bearer token` on a reload
 * looked like.
 */
function RequireAuth({ children }: { children: ReactNode }) {
  const { loading, user, memberships } = useAuth();
  if (loading) return <SkeletonRows rows={6} columns={4} />;
  if (!user) return <SignIn />;
  // Authenticated, but granted nothing here. Rendering the app anyway would
  // show a full console where every screen fails on its own.
  if (memberships.length === 0) return <NoAccess />;
  return <>{children}</>;
}

function Shell() {
  return (
    <div className="app">
      <Header />
      <main>
        {/*
            The fallback is a skeleton, not a spinner: a chunk arriving over a
            slow link should look like the page filling in, not like a stall.
          */}
        <Suspense fallback={<SkeletonRows rows={8} columns={4} />}>
          <RequireAuth>
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
              <Route
                path="/projects/:id/hardware"
                element={
                  <ProjectTabs>
                    <HardwareTree />
                  </ProjectTabs>
                }
              />
              <Route
                path="/projects/:id/hardware/import"
                element={
                  <ProjectTabs>
                    <HardwareImport />
                  </ProjectTabs>
                }
              />
              <Route path="*" element={<NotFound />} />
            </Routes>
          </RequireAuth>
        </Suspense>
      </main>
    </div>
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
      <div className="header-actions">
        <OrgSwitcher />
        <ThemeToggle />
        <SessionMenu />
      </div>
    </header>
  );
}

/**
 * SessionMenu shows who is signed in and offers the way out.
 *
 * Renders nothing when signed out — a "Sign out" control on the sign-in screen
 * is noise, and the screen itself already says the state.
 */
function SessionMenu() {
  const { user, name, activeOrg, signOut } = useAuth();
  if (!user) return null;

  return (
    <div className="session">
      <span className="session-name" title={activeOrg ? `${name} — ${activeOrg.role}` : name}>
        {name}
      </span>
      <button className="btn btn-quiet" onClick={signOut}>
        Sign out
      </button>
    </div>
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
        {/*
          ⚠ LABELLED "Hardware", NOT "Hardware scan". Nothing here discovers
          anything — the tab leads to an import and a form.
        */}
        <NavLink to={`/projects/${id}/hardware`}>Hardware</NavLink>
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
