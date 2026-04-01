/**
 * Route map for the REX dashboard.
 *
 * Public:        /login
 * Auth-gated:    / (redirects to /overview), /overview, /devices, /threats,
 *                /firewall, /knowledge, /scheduler, /plugins, /diagnostics,
 *                /onboarding, /settings/*, /privacy
 *
 * The ProtectedRoute wrapper checks for auth token and redirects
 * unauthenticated users to /login. Uses the existing AppShell layout
 * for authenticated pages.
 */

import React, { lazy, Suspense } from 'react';
import { Routes, Route, Navigate, useNavigate, useLocation } from 'react-router-dom';
import useAuthStore from '../stores/useAuthStore';
import useSystemStore from '../stores/useSystemStore';
import LoginPage from '../pages/auth/LoginPage';
import AppShell from '../layouts/AppShell';

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

/* ---------- auth gate ---------- */

function ProtectedRoute({ children }) {
  const authToken = useAuthStore((s) => s.token);
  const systemToken = useSystemStore((s) => s.token);
  const isAuthenticated = authToken || systemToken;

  if (!isAuthenticated) {
    return <Navigate to="/login" replace />;
  }

  return children;
}

/* ---------- route-to-page mapping for AppShell nav ---------- */

const PAGE_ID_FROM_PATH = {
  '/overview':              'overview',
  '/':                      'overview',
  '/threats':               'threats',
  '/devices':               'devices',
  '/chat':                  'chat',
  '/firewall':              'firewall',
  '/knowledge':             'knowledge',
  '/scheduler':             'scheduler',
  '/plugins':               'plugins',
  '/diagnostics':           'diagnostics',
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
          {/* Legacy chat route -- falls back to overview until chat page exists */}
          <Route path="/chat" element={<AdvancedOverviewPage />} />
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
  const mode = useSystemStore((s) => s.mode);
  return mode === 'basic' ? <BasicOverviewPage /> : <AdvancedOverviewPage />;
}

/* ---------- exported route tree ---------- */

export default function AppRoutes() {
  return (
    <Routes>
      {/* Public */}
      <Route path="/login" element={<LoginPage />} />

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
  );
}
