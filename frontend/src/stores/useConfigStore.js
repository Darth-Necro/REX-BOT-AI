/**
 * useConfigStore -- system configuration state.
 */
import { create } from 'zustand';
import { getConfig, updateConfig as apiUpdate } from '../api/config';

const useConfigStore = create((set, get) => ({
  config: null,
  loading: false,
  saving: false,
  error: null,
  saveError: null,

  fetchConfig: async () => {
    if (get().loading) return;
    set({ loading: true, error: null });
    try {
      const data = await getConfig();
      set({ config: data, loading: false });
    } catch (err) {
      set({ error: err.message || 'Failed to fetch config', loading: false });
    }
  },

  saveConfig: async (updates) => {
    set({ saving: true, saveError: null });
    try {
      const result = await apiUpdate(updates);
      // Re-fetch to get the canonical state
      await get().fetchConfig();
      set({ saving: false });
      return result;
    } catch (err) {
      set({ saveError: err.message || 'Failed to save config', saving: false });
      return null;
    }
  },
}));

export default useConfigStore;
