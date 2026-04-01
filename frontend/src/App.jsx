/**
 * App -- root component.
 *
 * Wires:
 *   1. BrowserRouter + AppRoutes (auth gating, /login, /overview, /devices, /threats)
 *   2. useBootstrap   -- API hydration on auth (system status, health)
 *   3. useRealtimeSync -- WebSocket connection + event routing to stores
 *
 * Auth flow:
 *   - useAuthStore holds the in-memory token (Batch 2)
 *   - useSystemStore still holds a localStorage token (Batch 1 compat)
 *   - Both are checked by ProtectedRoute in routes.jsx
 */

import React from 'react';
import { BrowserRouter } from 'react-router-dom';
import AppRoutes from './app/routes';
import useSystemStore from './stores/useSystemStore';
import useAuthStore from './stores/useAuthStore';
import useBootstrap from './hooks/useBootstrap';
import useRealtimeSync from './hooks/useRealtimeSync';

export default function App() {
  const authToken = useAuthStore((s) => s.token);
  const systemToken = useSystemStore((s) => s.token);
  const token = authToken || systemToken;

  // 1. API hydration (system status + health fetch on auth)
  useBootstrap();

  // 2. WebSocket realtime sync (connects after auth, routes events to stores)
  useRealtimeSync(token);

  return (
    <BrowserRouter>
      <AppRoutes />
    </BrowserRouter>
  );
}
