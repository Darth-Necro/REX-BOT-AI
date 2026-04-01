/**
 * useConnectionStatus -- merged API + WS connection state.
 *
 * Returns a single, human-readable connection state derived from
 * useSystemStore's apiConnection and wsConnection fields.
 *
 * Priority: disconnected > degraded > connecting > connected > unknown.
 */

import useSystemStore from '../stores/useSystemStore';

/**
 * @returns {{
 *   state: 'unknown'|'connecting'|'connected'|'degraded'|'disconnected',
 *   apiState: string,
 *   wsState: string,
 *   label: string,
 *   isOnline: boolean,
 * }}
 */
export default function useConnectionStatus() {
  const apiState = useSystemStore((s) => s.apiConnection);
  const wsState = useSystemStore((s) => s.wsConnection);

  const state = deriveState(apiState, wsState);
  const label = LABELS[state] || 'Unknown';
  const isOnline = state === 'connected';

  return { state, apiState, wsState, label, isOnline };
}

/* ---------- derivation ---------- */

function deriveState(api, ws) {
  // If either is disconnected, the overall state is disconnected
  if (api === 'disconnected' || ws === 'disconnected') return 'disconnected';
  // If either is connecting, show connecting
  if (api === 'connecting' || ws === 'connecting') return 'connecting';
  // If either is degraded, show degraded
  if (api === 'degraded' || ws === 'degraded') return 'degraded';
  // Both connected
  if (api === 'connected' && ws === 'connected') return 'connected';
  // Fallback
  return 'unknown';
}

const LABELS = {
  unknown: 'Unknown',
  connecting: 'Connecting',
  connected: 'Connected',
  degraded: 'Degraded',
  disconnected: 'Disconnected',
};
