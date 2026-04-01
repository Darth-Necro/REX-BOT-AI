import { create } from 'zustand';

const useSystemStore = create((set) => ({
  status: 'operational',
  powerState: 'awake',
  mode: 'basic',
  deviceCount: 0,
  activeThreats: 0,
  threatsBlocked24h: 0,
  llmStatus: 'ready',
  uptimeSeconds: 0,
  version: '1.0.0',
  connected: false,

  // Auth state
  token: localStorage.getItem('rex_token') || null,
  setToken: (token) => {
    if (token) localStorage.setItem('rex_token', token);
    else localStorage.removeItem('rex_token');
    set({ token });
  },
  logout: () => {
    localStorage.removeItem('rex_token');
    set({ token: null, connected: false });
  },

  setStatus: (status) => set({ status }),
  setPowerState: (powerState) => set({ powerState }),
  setMode: (mode) => set({ mode }),
  toggleMode: () => set((s) => ({ mode: s.mode === 'basic' ? 'advanced' : 'basic' })),
  setDeviceCount: (deviceCount) => set({ deviceCount }),
  setActiveThreats: (activeThreats) => set({ activeThreats }),
  setConnected: (connected) => set({ connected }),
  updateFromStatus: (data) => set({
    status: data.status || 'operational',
    powerState: data.power_state || 'awake',
    deviceCount: data.device_count || 0,
    activeThreats: data.active_threats || 0,
    threatsBlocked24h: data.threats_blocked_24h || 0,
    llmStatus: data.llm_status || 'unknown',
    uptimeSeconds: data.uptime_seconds || 0,
  }),
}));

export default useSystemStore;
