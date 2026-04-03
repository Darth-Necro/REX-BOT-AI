import { useEffect, useRef } from 'react';
import useAuthStore from '../stores/useAuthStore';
import useSystemStore from '../stores/useSystemStore';
import useDeviceStore from '../stores/useDeviceStore';
import useThreatStore from '../stores/useThreatStore';

/**
 * useBootstrap — called once at app root.
 *
 * Fires hydrateSystem() to fetch /health + /status on mount, then
 * pre-populates the core data stores (devices, threats) in parallel
 * so tab switches are instant.
 *
 * Does NOT open WebSocket — that is owned by useRealtimeSync.
 *
 * Does NOT run if there is no auth token (checked via useAuthStore).
 */
export default function useBootstrap() {
  const token = useAuthStore((s) => s.token);
  const hydrateSystem = useSystemStore((s) => s.hydrateSystem);
  const didRun = useRef(false);

  useEffect(() => {
    if (!token) return;

    // Prevent StrictMode double-fire from triggering duplicate hydration
    if (didRun.current) return;
    didRun.current = true;

    // API hydration only — WS lifecycle is handled by useRealtimeSync
    hydrateSystem().then(() => {
      // Pre-populate the two most-visited stores in parallel so
      // switching to the Devices or Threats tab is instant.
      Promise.all([
        useDeviceStore.getState().fetchDevices(),
        useThreatStore.getState().fetchThreats(),
      ]).catch(() => {
        // Individual stores already set their own error state;
        // swallow here so an unhandled rejection doesn't bubble up.
      });
    });

    return () => {
      didRun.current = false;
    };
  }, [token, hydrateSystem]);
}
