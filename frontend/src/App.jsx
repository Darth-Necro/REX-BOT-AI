/**
 * App -- root component.
 *
 * Wires:
 *   1. BrowserRouter + AppRoutes (auth gating, /login, /overview, /devices, /threats)
 *   2. useBootstrap   -- API hydration on auth (system status, health)
 *   3. useRealtimeSync -- WebSocket connection + event routing to stores
 *
 * Auth flow:
 *   - useAuthStore is the single source of truth for token and session state.
 */

import React from 'react';
import { BrowserRouter } from 'react-router-dom';
import AppRoutes from './app/routes';
import useAuthStore from './stores/useAuthStore';
import useBootstrap from './hooks/useBootstrap';
import useRealtimeSync from './hooks/useRealtimeSync';

export default function App() {
  const token = useAuthStore((s) => s.token);

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
