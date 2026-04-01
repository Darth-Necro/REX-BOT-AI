import { useEffect, useRef } from 'react';
import useSystemStore from '../stores/useSystemStore';
import { connect, on, off, disconnect } from '../ws/socket';

/**
 * useBootstrap — called once at app root.
 *
 * 1. Fires hydrateSystem() to fetch /health + /status on mount.
 * 2. Opens the WebSocket and wires real-time event handlers.
 * 3. Cleans up on unmount.
 *
 * Does NOT run if there is no auth token.
 */
export default function useBootstrap() {
  const token = useSystemStore((s) => s.token);
  const hydrateSystem = useSystemStore((s) => s.hydrateSystem);
  const setWsConnection = useSystemStore((s) => s.setWsConnection);
  const setConnected = useSystemStore((s) => s.setConnected);
  const updateFromStatus = useSystemStore((s) => s.updateFromStatus);
  const pushAlert = useSystemStore((s) => s.pushAlert);
  const didRun = useRef(false);

  useEffect(() => {
    if (!token) return;

    // Prevent StrictMode double-fire from triggering duplicate hydration
    if (didRun.current) return;
    didRun.current = true;

    // 1. API hydration
    hydrateSystem();

    // 2. WebSocket
    setWsConnection('connecting');
    connect();

    on('__open', () => {
      setWsConnection('connected');
      setConnected(true);
    });

    on('__close', () => {
      setWsConnection('disconnected');
      setConnected(false);
    });

    on('status.update', (data) => {
      updateFromStatus(data.payload || data);
    });

    on('threat.new', (data) => {
      const payload = data.payload || data;
      pushAlert(payload);
      // Also update the dedicated threat store if it exists
      import('../stores/useThreatStore').then(({ default: store }) => {
        store.getState().addThreat(payload);
      });
    });

    return () => {
      off('__open');
      off('__close');
      off('status.update');
      off('threat.new');
      disconnect();
      didRun.current = false;
    };
  }, [token, hydrateSystem, setWsConnection, setConnected, updateFromStatus, pushAlert]);
}
