import { create } from 'zustand';
import { hydrateSystemState } from '../api/system';
import { normalizeStatus, derivePosture } from '../lib/status';

/**
 * System store — single source of truth for global state.
 *
 * Defaults are HONEST:
 *   - Every enum starts as 'unknown'
 *   - Counts start at 0
 *   - bootstrapState tracks whether we have real data yet
 */
const useSystemStore = create((set, get) => ({
  // --- Bootstrap / connection lifecycle ---
  bootstrapState: 'idle', // 'idle' | 'loading' | 'ready' | 'error'
  apiConnection: 'unknown', // 'unknown' | 'connecting' | 'connected' | 'degraded' | 'disconnected'
  wsConnection: 'unknown', // 'unknown' | 'connecting' | 'connected' | 'disconnected'

  // --- Core system state (all unknown until backend confirms) ---
  status: 'unknown',
  powerState: 'unknown',
  llmStatus: 'unknown',
  threatPosture: 'unknown',
  deviceCount: 0,
  activeThreats: 0,
  threatsBlocked24h: 0,
  uptimeSeconds: 0,
  version: null,

  // Freshness gate — prevents stale HTTP responses from overwriting newer WS data
  _lastStatusTimestamp: 0,

  // --- UI mode ---
  mode: 'advanced',
  toggleMode: () => set((s) => ({ mode: s.mode === 'basic' ? 'advanced' : 'basic' })),

  // --- Derived convenience (kept for backward compat) ---
  connected: false,

  // --- Auth (in-memory only — never persist tokens to localStorage) ---
  token: null,
  setToken: (token) => {
    // Clear any legacy localStorage token on next call
    localStorage.removeItem('rex_token');
    set({ token: token || null });
  },
  logout: () => {
    localStorage.removeItem('rex_token');
    set({ token: null, connected: false, apiConnection: 'disconnected', wsConnection: 'disconnected' });
  },

  // --- Recent alerts (shallow cache for overview) ---
  recentAlerts: [],
  pushAlert: (alert) =>
    set((s) => ({ recentAlerts: [alert, ...s.recentAlerts].slice(0, 20) })),

  // --- Granular setters ---
  setConnected: (connected) => set({ connected }),
  setApiConnection: (apiConnection) => set({ apiConnection }),
  setWsConnection: (wsConnection) => set({ wsConnection }),

  /**
   * Hydrate store from API on bootstrap.
   * Sets bootstrapState through the lifecycle so the UI can show loading / error.
   * Respects _lastStatusTimestamp so a slow HTTP response never overwrites
   * fresher WebSocket data that arrived while the request was in flight.
   */
  hydrateSystem: async () => {
    const { bootstrapState } = get();
    if (bootstrapState === 'loading') return; // prevent double-fire

    set({ bootstrapState: 'loading', apiConnection: 'connecting' });

    try {
      const data = await hydrateSystemState();
      const posture = derivePosture(data);

      const incomingTs = new Date(data._timestamp || 0).getTime() || 0;
      const currentTs = get()._lastStatusTimestamp;

      if (incomingTs && currentTs && incomingTs < currentTs) {
        // HTTP response is older than what WS already applied — keep WS data,
        // but still mark bootstrap as ready and update non-status fields.
        set({
          apiConnection: data.apiConnection,
          health: data.health,
          connected: data.apiConnection === 'connected',
          bootstrapState: 'ready',
        });
      } else {
        set({
          ...data,
          threatPosture: posture,
          connected: data.apiConnection === 'connected',
          bootstrapState: 'ready',
          _lastStatusTimestamp: incomingTs || currentTs,
        });
      }
    } catch {
      set({
        bootstrapState: 'error',
        apiConnection: 'disconnected',
        connected: false,
      });
    }
  },

  /**
   * Incremental update from WebSocket status.update events.
   * Normalises the payload — never trusts raw values blindly.
   * Respects _lastStatusTimestamp so out-of-order messages are discarded.
   */
  updateFromStatus: (raw) => {
    const data = normalizeStatus(raw);
    const posture = derivePosture(data);

    const incomingTs = new Date(data._timestamp || 0).getTime() || 0;
    const currentTs = get()._lastStatusTimestamp;

    // Drop the update if it carries a timestamp older than what we already have
    if (incomingTs && currentTs && incomingTs < currentTs) return;

    // Only spread known status fields to avoid overwriting store internals
    const { status, powerState, llmStatus, deviceCount, activeThreats,
            threatsBlocked24h, uptimeSeconds, version } = data;
    set({
      status, powerState, llmStatus, deviceCount, activeThreats,
      threatsBlocked24h, uptimeSeconds, version,
      threatPosture: posture,
      _lastStatusTimestamp: incomingTs || currentTs,
    });
  },
}));

export default useSystemStore;
