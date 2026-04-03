/**
 * Route map for the REX dashboard.
 *
 * Public:        /login, /setup
 * Auth-gated:    / (redirects to /overview), /overview, /devices, /threats,
 *                /firewall, /knowledge, /scheduler, /plugins, /diagnostics,
 *                /onboarding, /settings/*, /privacy, /change-password
 *
 * First-run:     If no token exists and setup has never been completed,
 *                unauthenticated visitors are redirected to /setup instead
 *                of /login.
 *
 * The ProtectedRoute wrapper checks for auth token and redirects
 * unauthenticated users to /login. Uses the existing AppShell layout
 * for authenticated pages.
 */

import React, { lazy, Suspense } from 'react';
import { Routes, Route, Navigate, useNavigate, useLocation } from 'react-router-dom';
import useAuthStore from '../stores/useAuthStore';
import useSystemStore from '../stores/useSystemStore';
import useUiStore from '../stores/useUiStore';
import LoginPage from '../pages/auth/LoginPage';
import AppShell from '../layouts/AppShell';
import AlphaBanner from '../components/AlphaBanner';

/* Setup wizard + change-password + reset-password (lazy-loaded) */
const SetupWizard = lazy(() => import('../pages/setup/SetupWizard'));
const ChangePasswordPage = lazy(() => import('../pages/auth/ChangePasswordPage'));
const ResetPasswordPage = lazy(() => import('../pages/auth/ResetPasswordPage'));

/* Lazy-load page components for code-splitting */
const DevicesPage = lazy(() => import('../pages/devices/DevicesPage'));
const ThreatsPage = lazy(() => import('../pages/threats/ThreatsPage'));
const AdvancedOverviewPage = lazy(() => import('../pages/overview/AdvancedOverviewPage'));

/* Batch 3 -- operational pages */
const FirewallPage = lazy(() => import('../pages/firewall/FirewallPage'));
const KnowledgeBasePage = lazy(() => import('../pages/knowledge/KnowledgeBasePage'));
const SchedulerPage = lazy(() => import('../pages/scheduler/SchedulerPage'));
const PluginsPage = lazy(() => import('../pages/plugins/PluginsPage'));
const DiagnosticsPage = lazy(() => import('../pages/diagnostics/DiagnosticsPage'));

/* Batch 4 -- settings, notifications, privacy, onboarding, basic mode */
const BasicOverviewPage = lazy(() => import('../pages/overview/BasicOverviewPage'));
const InterviewPage = lazy(() => import('../pages/onboarding/InterviewPage'));
const SettingsPage = lazy(() => import('../pages/settings/SettingsPage'));
const NotificationsPage = lazy(() => import('../pages/settings/NotificationsPage'));
const AboutPage = lazy(() => import('../pages/settings/AboutPage'));
const PrivacyPage = lazy(() => import('../pages/privacy/PrivacyPage'));

/* Batch 5 -- network, investigations, device details, service health */
const NetworkMapPage = lazy(() => import('../pages/network/NetworkMapPage'));
const DeviceDetailsPage = lazy(() => import('../pages/devices/DeviceDetailsPage'));
const ThreatDetailsPage = lazy(() => import('../pages/threats/ThreatDetailsPage'));
const InvestigationsPage = lazy(() => import('../pages/threats/InvestigationsPage'));
const ServiceHealthPage = lazy(() => import('../pages/diagnostics/ServiceHealthPage'));

/* Fallback for legacy basic mode */
const BasicView = lazy(() => import('../views/BasicView'));

/* ---------- loading fallback ---------- */

function PageLoader() {
  return (
    <div className="flex items-center justify-center h-64">
      <div className="flex flex-col items-center gap-3">
        <svg className="w-8 h-8 text-cyan-400 animate-spin" fill="none" viewBox="0 0 24 24">
          <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
          <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
        </svg>
        <span className="text-sm text-rex-muted">Loading...</span>
      </div>
    </div>
  );
}

/* ---------- first-run detection ---------- */

function isFirstRun() {
  return !localStorage.getItem('rex_setup_complete');
}

/* ---------- auth gate ---------- */

function ProtectedRoute({ children }) {
  const isAuthenticated = useAuthStore((s) => s.token);

  if (!isAuthenticated) {
    // First visit with no token -- send to setup wizard instead of login
    if (isFirstRun()) {
      return <Navigate to="/setup" replace />;
    }
    return <Navigate to="/login" replace />;
  }

  return children;
}

/* ---------- route-to-page mapping for AppShell nav ---------- */

const PAGE_ID_FROM_PATH = {
  '/overview':              'overview',
  '/':                      'overview',
  '/network':               'network',
  '/threats':               'threats',
  '/devices':               'devices',
  '/chat':                  'chat',
  '/firewall':              'firewall',
  '/knowledge':             'knowledge',
  '/scheduler':             'scheduler',
  '/plugins':               'plugins',
  '/diagnostics':           'diagnostics',
  '/diagnostics/services':  'diagnostics',
  '/onboarding':            'onboarding',
  '/settings':              'settings',
  '/settings/notifications': 'settings',
  '/settings/about':        'settings',
  '/privacy':               'privacy',
};

/* ---------- shell wrapper that hooks AppShell to routes ---------- */

function AuthenticatedShell() {
  const navigate = useNavigate();
  const location = useLocation();
  const currentPage = PAGE_ID_FROM_PATH[location.pathname] || 'overview';

  const handleNavigate = (id) => {
    const route = {
      overview: '/overview',
      network: '/network',
      threats: '/threats',
      devices: '/devices',
      chat: '/chat',
      firewall: '/firewall',
      knowledge: '/knowledge',
      scheduler: '/scheduler',
      plugins: '/plugins',
      diagnostics: '/diagnostics',
      onboarding: '/onboarding',
      settings: '/settings',
      privacy: '/privacy',
    }[id];
    if (route) navigate(route);
  };

  return (
    <AppShell currentPage={currentPage} onNavigate={handleNavigate}>
      <Suspense fallback={<PageLoader />}>
        <Routes>
          <Route path="/overview" element={<OverviewPage />} />
          <Route path="/devices" element={<DevicesPage />} />
          <Route path="/threats" element={<ThreatsPage />} />
          {/* Batch 3 -- operational pages */}
          <Route path="/firewall" element={<FirewallPage />} />
          <Route path="/knowledge" element={<KnowledgeBasePage />} />
          <Route path="/scheduler" element={<SchedulerPage />} />
          <Route path="/plugins" element={<PluginsPage />} />
          <Route path="/diagnostics" element={<DiagnosticsPage />} />
          {/* Batch 4 -- settings, onboarding, privacy */}
          <Route path="/onboarding" element={<InterviewPage />} />
          <Route path="/settings" element={<SettingsPage />} />
          <Route path="/settings/notifications" element={<NotificationsPage />} />
          <Route path="/settings/about" element={<AboutPage />} />
          <Route path="/privacy" element={<PrivacyPage />} />
          {/* Batch 5 -- network, device details, threat details, investigations, service health */}
          <Route path="/network" element={<NetworkMapPage />} />
          <Route path="/devices/:id" element={<DeviceDetailsPage />} />
          <Route path="/threats/:id" element={<ThreatDetailsPage />} />
          <Route path="/threats/:id/investigate" element={<InvestigationsPage />} />
          <Route path="/diagnostics/services" element={<ServiceHealthPage />} />
          {/* Legacy chat route -- falls back to overview until chat page exists */}
          <Route path="/chat" element={<><AlphaBanner feature="Chat" /><AdvancedOverviewPage /></>} />
          {/* Password change / reset (auth-gated, inside shell) */}
          <Route path="/change-password" element={<ChangePasswordPage />} />
          <Route path="/reset-password" element={<ResetPasswordPage />} />
          {/* Root redirects to overview */}
          <Route path="/" element={<Navigate to="/overview" replace />} />
          {/* Catch-all */}
          <Route path="*" element={<Navigate to="/overview" replace />} />
        </Routes>
      </Suspense>
    </AppShell>
  );
}

/* ---------- Overview page (mode-aware) ---------- */

function OverviewPage() {
  const viewMode = useUiStore((s) => s.viewMode);
  const systemMode = useSystemStore((s) => s.mode);
  const mode = viewMode || systemMode || 'advanced';
  return mode === 'basic' ? <BasicOverviewPage /> : <AdvancedOverviewPage />;
}

/* ---------- exported route tree ---------- */

export default function AppRoutes() {
  return (
    <Suspense fallback={<PageLoader />}>
      <Routes>
        {/* Public */}
        <Route path="/login" element={<LoginPage />} />
        <Route path="/setup" element={<SetupWizard />} />

        {/* All auth-gated routes go through the shell */}
        <Route
          path="/*"
          element={
            <ProtectedRoute>
              <AuthenticatedShell />
            </ProtectedRoute>
          }
        />
      </Routes>
    </Suspense>
  );
}
