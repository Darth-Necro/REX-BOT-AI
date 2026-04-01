/**
 * Route map for the REX dashboard.
 *
 * Public:        /login
 * Auth-gated:    / (redirects to /overview), /overview, /devices, /threats
 *
 * The ProtectedRoute wrapper checks for auth token and redirects
 * unauthenticated users to /login. The AppShell provides the sidebar
 * + top bar layout for all authenticated pages.
 */

import React, { lazy, Suspense } from 'react';
import { Routes, Route, Navigate } from 'react-router-dom';
import useAuthStore from '../stores/useAuthStore';
import useSystemStore from '../stores/useSystemStore';
import LoginPage from '../pages/auth/LoginPage';
import SidebarNav from '../layouts/SidebarNav';
import TopCommandBar from '../layouts/TopCommandBar';

/* Lazy-load page components for code-splitting */
const DevicesPage = lazy(() => import('../pages/devices/DevicesPage'));
const ThreatsPage = lazy(() => import('../pages/threats/ThreatsPage'));

/* Re-use Batch 1 views for Overview (basic/advanced mode) */
const BasicView = lazy(() => import('../views/BasicView'));
const AdvancedView = lazy(() => import('../views/AdvancedView'));

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

/* ---------- app shell (sidebar + topbar + content) ---------- */

function AppShell({ pageLabel, children }) {
  return (
    <div className="flex h-screen bg-rex-bg overflow-hidden">
      <SidebarNav />
      <div className="flex flex-col flex-1 min-w-0">
        <TopCommandBar pageLabel={pageLabel} />
        <main className="flex-1 overflow-hidden">
          <Suspense fallback={<PageLoader />}>
            {children}
          </Suspense>
        </main>
      </div>
    </div>
  );
}

/* ---------- Overview page (mode-aware) ---------- */

function OverviewPage() {
  const mode = useSystemStore((s) => s.mode);
  return mode === 'basic' ? <BasicView /> : <AdvancedView />;
}

/* ---------- exported route tree ---------- */

export default function AppRoutes() {
  return (
    <Routes>
      {/* Public */}
      <Route path="/login" element={<LoginPage />} />

      {/* Auth-gated pages */}
      <Route
        path="/overview"
        element={
          <ProtectedRoute>
            <AppShell pageLabel="Overview">
              <OverviewPage />
            </AppShell>
          </ProtectedRoute>
        }
      />

      <Route
        path="/devices"
        element={
          <ProtectedRoute>
            <AppShell pageLabel="Devices">
              <DevicesPage />
            </AppShell>
          </ProtectedRoute>
        }
      />

      <Route
        path="/threats"
        element={
          <ProtectedRoute>
            <AppShell pageLabel="Threats">
              <ThreatsPage />
            </AppShell>
          </ProtectedRoute>
        }
      />

      {/* Root redirects to overview */}
      <Route path="/" element={<Navigate to="/overview" replace />} />

      {/* Fallback -- redirect unknown paths to overview */}
      <Route path="*" element={<Navigate to="/overview" replace />} />
    </Routes>
  );
}
