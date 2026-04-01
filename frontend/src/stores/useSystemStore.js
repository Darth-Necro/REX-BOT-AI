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

  // --- UI mode ---
  mode: 'advanced',
  toggleMode: () => set((s) => ({ mode: s.mode === 'basic' ? 'advanced' : 'basic' })),

  // --- Derived convenience (kept for backward compat) ---
  connected: false,

  // --- Auth ---
  token: localStorage.getItem('rex_token') || null,
  setToken: (token) => {
    if (token) localStorage.setItem('rex_token', token);
    else localStorage.removeItem('rex_token');
    set({ token });
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
   */
  hydrateSystem: async () => {
    const { bootstrapState } = get();
    if (bootstrapState === 'loading') return; // prevent double-fire

    set({ bootstrapState: 'loading', apiConnection: 'connecting' });

    try {
      const data = await hydrateSystemState();
      const posture = derivePosture(data);
      set({
        ...data,
        threatPosture: posture,
        connected: data.apiConnection === 'connected',
        bootstrapState: 'ready',
      });
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
   */
  updateFromStatus: (raw) => {
    const data = normalizeStatus(raw);
    const posture = derivePosture(data);
    set({
      ...data,
      threatPosture: posture,
    });
  },
}));

export default useSystemStore;
