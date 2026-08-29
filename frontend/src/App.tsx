/**
 * Application shell.
 *
 * ⚠ ROUTE-LEVEL CODE SPLITTING. The dependency explorer pulls in a virtualizer
 * and the report viewer pulls in the share dialog; neither belongs in the
 * bundle a user downloads to look at a project list. The budget is 250 KB
 * gzipped for the initial load (docs/07-FRONTEND-SPEC.md §8).
 */

import { Suspense, lazy, type ReactNode } from 'react';
import { BrowserRouter, Link, NavLink, Route, Routes, useLocation, useParams } from 'react-router';
import { LazyMotion, MotionConfig, m } from 'motion/react';
import { SkeletonRows } from './components/States';
import { Ambient } from './components/Ambient';
import { Sidebar } from './components/Sidebar';
import { TopBar } from './components/TopBar';
import { AuthProvider } from './lib/AuthContext';
import { useAuth } from './lib/useAuth';
import { AuthCallback, NoAccess, SignIn, SilentCallback } from './routes/auth/AuthRoutes';
import { SignupPage } from './routes/auth/SignupPage';
import { ProjectList } from './routes/projects/ProjectList';
import { ProjectWizard } from './routes/projects/ProjectWizard';
import { ProjectDetail } from './routes/projects/ProjectDetail';

const loadMotionFeatures = () => import('./design/motion-features').then((mod) => mod.default);

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
const ReportList = lazy(() =>
  import('./routes/reports/ReportList').then((m) => ({ default: m.ReportList })),
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
const SettingsIndex = lazy(() =>
  import('./routes/settings/SettingsIndex').then((m) => ({ default: m.SettingsIndex })),
);
const Engines = lazy(() =>
  import('./routes/settings/Engines').then((m) => ({ default: m.Engines })),
);
const BomTypeHome = lazy(() =>
  import('./routes/boms/BomTypeHome').then((m) => ({ default: m.BomTypeHome })),
);
const HardwareImport = lazy(() =>
  import('./routes/hbom/HardwareImport').then((m) => ({ default: m.HardwareImport })),
);
const HardwareTree = lazy(() =>
  import('./routes/hbom/HardwareTree').then((m) => ({ default: m.HardwareTree })),
);
const CryptoInventory = lazy(() =>
  import('./routes/boms/CryptoInventory').then((m) => ({ default: m.CryptoInventory })),
);
const QuantumDevice = lazy(() =>
  import('./routes/boms/QuantumDevice').then((m) => ({ default: m.QuantumDevice })),
);
const AIModelInventory = lazy(() =>
  import('./routes/boms/AIModelInventory').then((m) => ({ default: m.AIModelInventory })),
);
const ProjectScans = lazy(() =>
  import('./routes/projects/ProjectScans').then((m) => ({ default: m.ProjectScans })),
);
const ProjectPractices = lazy(() =>
  import('./routes/projects/ProjectPractices').then((m) => ({ default: m.ProjectPractices })),
);
const ProjectSettings = lazy(() =>
  import('./routes/projects/ProjectSettings').then((m) => ({ default: m.ProjectSettings })),
);

export function App() {
  return (
    /*
     * ⚠ `strict` MAKES `motion.div` THROW, ON PURPOSE.
     *
     * It forces every call site onto `m.*`, which is what keeps the feature
     * bundle lazy. Without it one stray `import { motion }` silently moves
     * ~34 KB into the entry chunk and nothing fails — the bundle just gets
     * bigger, in a repo whose CI does not measure it.
     *
     * `reducedMotion="user"` is the OTHER HALF of the accessibility wiring.
     * The media query in app.css only reaches CSS animations and transitions;
     * `motion` animates through the Web Animations API and ignores it. Neither
     * mechanism covers the other, so both are present.
     */
    <LazyMotion features={loadMotionFeatures} strict>
      <MotionConfig reducedMotion="user">
        <BrowserRouter>
          <AuthProvider>
            <Routes>
              {/*
                ⚠ MOUNTED OUTSIDE SHELL, WHICH IS THE GATE ITSELF NOW.
                The callback routes are how a user BECOMES authenticated; putting
                them behind the gate is a redirect loop, and rendering the header
                around the silent iframe boots a second application inside it.
              */}
              <Route path="/auth/callback" element={<AuthCallback />} />
              <Route path="/auth/silent" element={<SilentCallback />} />
              {/*
                Also outside Shell, for the same reason: a visitor without a
                session yet is exactly who this page is for.
              */}
              <Route path="/signup" element={<SignupPage />} />
              <Route path="*" element={<Shell />} />
            </Routes>
          </AuthProvider>
        </BrowserRouter>
      </MotionConfig>
    </LazyMotion>
  );
}

/**
 * Shell gates everything the API backs, AND the app chrome around it.
 *
 * ⚠ THE SIDEBAR AND TOPBAR ARE PART OF WHAT'S GATED, NOT SCAFFOLDING AROUND
 * THE GATE. A visitor who isn't signed in yet (or has no role anywhere) has
 * nothing behind any of that navigation to go to — showing it anyway reads as
 * "here is the product" for someone who cannot actually open a single link in
 * it. So the loading/sign-in/no-access screens below return on their own,
 * full page, before any of the chrome mounts; only a genuinely usable session
 * reaches the `<div className="app">` that contains it.
 *
 * IT RENDERS NOTHING WHILE THE SESSION IS BEING PROBED, for a second, older
 * reason: rendering the children first and correcting afterwards means every
 * screen fires its queries with no token, collects a 401, and shows an error
 * for a session that was about to resume — which is exactly what `no bearer
 * token` on a reload looked like.
 */
function Shell() {
  const { loading, user, memberships } = useAuth();
  if (loading) return <SkeletonRows rows={6} columns={4} />;
  if (!user) return <SignIn />;
  // Authenticated, but granted nothing here. Rendering the app anyway would
  // show a full console where every screen fails on its own.
  if (memberships.length === 0) return <NoAccess />;

  return (
    <>
      {/* Outside .app: a z-index:-1 child would paint behind its own parent. */}
      <Ambient />
      <a className="skip-link" href="#main">
        Skip to content
      </a>
      <div className="app">
        <Sidebar />
        <TopBar />
        {/*
          ⚠ THE OUTER <main> IS STILL THE ONE PLACE PAGE PADDING AND MAX-WIDTH
          LIVE. Routes must not bring their own; see the note in app.css.
        */}
        <main id="main" tabIndex={-1}>
          {/*
            The fallback is a skeleton, not a spinner: a chunk arriving over a
            slow link should look like the page filling in, not like a stall.
          */}
          <Suspense fallback={<SkeletonRows rows={8} columns={4} />}>
            <RouteTransition>
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
                <Route
                  path="/projects/:id/scans"
                  element={
                    <ProjectTabs>
                      <ProjectScans />
                    </ProjectTabs>
                  }
                />
                <Route
                  path="/projects/:id/practices"
                  element={
                    <ProjectTabs>
                      <ProjectPractices />
                    </ProjectTabs>
                  }
                />
                <Route
                  path="/projects/:id/settings"
                  element={
                    <ProjectTabs>
                      <ProjectSettings />
                    </ProjectTabs>
                  }
                />
                <Route path="/sbom" element={<BomTypeHome family="SBOM" />} />
                <Route path="/cbom" element={<BomTypeHome family="CBOM" />} />
                <Route path="/qbom" element={<BomTypeHome family="QBOM" />} />
                <Route path="/aibom" element={<BomTypeHome family="AIBOM" />} />
                <Route path="/hbom" element={<BomTypeHome family="HBOM" />} />
                <Route path="/generate" element={<GenerateFlow />} />
                <Route path="/scans/:id" element={<ScanProgressRoute />} />
                <Route path="/reports" element={<ReportList />} />
                <Route path="/reports/:id" element={<ReportViewer />} />
                <Route path="/campaigns" element={<CampaignList />} />
                <Route path="/campaigns/new" element={<CampaignWizard />} />
                <Route path="/campaigns/:id" element={<CampaignDetail />} />
                <Route path="/settings" element={<SettingsIndex />} />
                <Route path="/settings/notifications" element={<Notifications />} />
                <Route path="/settings/engines" element={<Engines />} />
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
                <Route
                  path="/projects/:id/crypto"
                  element={
                    <ProjectTabs>
                      <CryptoInventory />
                    </ProjectTabs>
                  }
                />
                <Route
                  path="/projects/:id/quantum"
                  element={
                    <ProjectTabs>
                      <QuantumDevice />
                    </ProjectTabs>
                  }
                />
                <Route
                  path="/projects/:id/ai-models"
                  element={
                    <ProjectTabs>
                      <AIModelInventory />
                    </ProjectTabs>
                  }
                />
                <Route path="*" element={<NotFound />} />
              </Routes>
            </RouteTransition>
          </Suspense>
        </main>
      </div>
    </>
  );
}

/**
 * A short fade-and-rise as each route arrives.
 *
 * ⚠ ENTER ONLY. NO `AnimatePresence`, NO EXIT.
 *
 * Two reasons, and the second is the one that bites. An exit animation around
 * lazily-loaded routes fights `Suspense` — the fallback unmounts and remounts
 * mid-transition. And an exiting screen stays in the DOM and stays clickable,
 * so a fast user (or a test) can click a control on a page that is already
 * leaving. `e2e/generate.spec.ts` clicks Continue and immediately looks for the
 * next step's controls; that is exactly the race.
 *
 * Keyed on pathname, not on the whole location: filters on the dependencies
 * screen are URL state, and re-animating the page on every keystroke would be
 * unbearable.
 */
function RouteTransition({ children }: { children: ReactNode }) {
  const { pathname } = useLocation();
  return (
    <m.div
      key={pathname}
      className="route"
      initial={{ opacity: 0, y: 6 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.18, ease: [0.16, 1, 0.3, 1] }}
    >
      {children}
    </m.div>
  );
}

function ProjectTabs({ children }: { children: ReactNode }) {
  const { id = '' } = useParams();
  return (
    <>
      <nav className="tabs" aria-label="Project sections">
        <NavLink to={`/projects/${id}`} end>
          Overview
        </NavLink>
        <NavLink to={`/projects/${id}/dependencies`}>Dependencies</NavLink>
        <NavLink to={`/projects/${id}/findings`}>Findings</NavLink>
        <NavLink to={`/projects/${id}/scans`}>Scans</NavLink>
        <NavLink to={`/projects/${id}/crypto`}>Crypto</NavLink>
        {/*
          ⚠ LABELLED "Quantum", NOT "Quantum scan". No open-source tool
          discovers quantum hardware — this tab is a derived readiness view
          plus a form, the same honesty QuantumDevice.tsx itself states.
        */}
        <NavLink to={`/projects/${id}/quantum`}>Quantum</NavLink>
        <NavLink to={`/projects/${id}/ai-models`}>AI Models</NavLink>
        {/*
          ⚠ LABELLED "Hardware", NOT "Hardware scan". Nothing here discovers
          anything — the tab leads to an import and a form.
        */}
        <NavLink to={`/projects/${id}/hardware`}>Hardware</NavLink>
        <NavLink to={`/projects/${id}/practices`}>Practices</NavLink>
        <NavLink to={`/projects/${id}/settings`}>Settings</NavLink>
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
