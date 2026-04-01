import React, { useState } from 'react';
import { BrowserRouter, Routes, Route, useNavigate } from 'react-router-dom';
import useSystemStore from './stores/useSystemStore';
import useBootstrap from './hooks/useBootstrap';
import AppShell from './layouts/AppShell';
import AdvancedOverviewPage from './pages/overview/AdvancedOverviewPage';
import LoginView from './views/LoginView';

/* ------------------------------------------------------------------ */
/*  Legacy views (keep imports alive for sub-routes)                  */
/* ------------------------------------------------------------------ */
import AdvancedView from './views/AdvancedView';

/* ------------------------------------------------------------------ */
/*  Page ID <-> route mapping                                         */
/* ------------------------------------------------------------------ */

const PAGE_ROUTES = {
  overview: '/',
  threats: '/threats',
  devices: '/devices',
  chat: '/chat',
};

/* ------------------------------------------------------------------ */
/*  Inner shell that owns routing (needs to be inside BrowserRouter)  */
/* ------------------------------------------------------------------ */

function ShellWithRoutes() {
  const navigate = useNavigate();
  const [currentPage, setCurrentPage] = useState('overview');

  const handleNavigate = (id) => {
    setCurrentPage(id);
    const route = PAGE_ROUTES[id];
    if (route) navigate(route);
  };

  return (
    <AppShell currentPage={currentPage} onNavigate={handleNavigate}>
      <Routes>
        <Route path="/" element={<AdvancedOverviewPage />} />
        {/* Legacy routes still work */}
        <Route path="/threats" element={<AdvancedView />} />
        <Route path="/devices" element={<AdvancedView />} />
        <Route path="/chat" element={<AdvancedView />} />
        {/* Catch-all falls back to overview */}
        <Route path="*" element={<AdvancedOverviewPage />} />
      </Routes>
    </AppShell>
  );
}

/* ------------------------------------------------------------------ */
/*  Root App                                                          */
/* ------------------------------------------------------------------ */

export default function App() {
  const token = useSystemStore((s) => s.token);

  // Bootstrap fires hydration + WebSocket setup when token is present
  useBootstrap();

  if (!token) {
    return <LoginView />;
  }

  return (
    <BrowserRouter>
      <ShellWithRoutes />
    </BrowserRouter>
  );
}
