/**
 * useRealtimeSync -- connects the WebSocket after authentication
 * and routes all incoming events to the appropriate stores.
 *
 * Usage:  call once in the authenticated shell (AppShell / App).
 *         The hook self-cleans on unmount or when the token changes.
 */

import { useEffect, useRef } from 'react';
import { connect, disconnect, on, off, WS_STATES } from '../ws/socket';
import { routeEvent } from '../ws/eventRouter';
import useSystemStore from '../stores/useSystemStore';

/**
 * @param {string|null} token  The current auth token (null = skip).
 */
export default function useRealtimeSync(token) {
  const setConnected = useSystemStore((s) => s.setConnected);
  const updateFromStatus = useSystemStore((s) => s.updateFromStatus);
  const prevToken = useRef(null);

  useEffect(() => {
    if (!token) {
      // No token -- tear down any existing connection
      disconnect();
      setConnected(false);
      return;
    }

    // Avoid reconnecting when the same token is re-rendered
    if (token === prevToken.current) return;
    prevToken.current = token;

    /* -- wire handlers -- */

    on('__open', () => setConnected(true));
    on('__close', () => setConnected(false));
    on('__state', (state) => {
      // Expose WS state to system store for UI
      useSystemStore.setState({ wsState: state });
    });

    // Wildcard: every message goes through the event router
    on('*', routeEvent);

    // Also keep the legacy status handler for backward compat
    on('status.update', (data) => updateFromStatus(data.payload || data));

    /* -- connect -- */
    connect(token);

    /* -- cleanup on unmount or token change -- */
    return () => {
      off('__open');
      off('__close');
      off('__state');
      off('*');
      off('status.update');
      disconnect();
      setConnected(false);
    };
  }, [token, setConnected, updateFromStatus]);
}
