/**
 * usePluginStore — installed & available plugins with mutation support.
 *
 * Installed plugins come from /plugins/installed, available from /plugins/available.
 * Both are fetched in parallel on hydration.
 */
import { create } from 'zustand';
import {
  getInstalledPlugins,
  getAvailablePlugins,
  installPlugin as apiInstall,
  removePlugin as apiRemove,
} from '../api/plugins';

const usePluginStore = create((set, get) => ({
  installed: [],
  available: [],
  loading: false,
  actionInProgress: null,   // plugin id currently being installed/removed
  error: null,
  capabilities: {},

  /* ---------- hydration ---------- */

  fetchPlugins: async () => {
    if (get().loading) return;
    set({ loading: true, error: null });
    try {
      const [instRes, availRes] = await Promise.allSettled([
        getInstalledPlugins(),
        getAvailablePlugins(),
      ]);

      const installed =
        instRes.status === 'fulfilled' ? instRes.value.plugins : get().installed;
      const capabilities =
        instRes.status === 'fulfilled' ? instRes.value.capabilities : get().capabilities;
      const available =
        availRes.status === 'fulfilled' ? availRes.value.plugins : get().available;

      set({ installed, available, capabilities, loading: false });
    } catch (err) {
      set({ error: err.message || 'Failed to fetch plugins', loading: false });
    }
  },

  /* ---------- mutations ---------- */

  installPlugin: async (pluginId) => {
    set({ actionInProgress: pluginId, error: null });
    try {
      await apiInstall(pluginId);
      await get().fetchPlugins();
    } catch (err) {
      set({ error: err.message || 'Install failed' });
      throw err;
    } finally {
      set({ actionInProgress: null });
    }
  },

  removePlugin: async (pluginId) => {
    set({ actionInProgress: pluginId, error: null });
    try {
      await apiRemove(pluginId);
      await get().fetchPlugins();
    } catch (err) {
      set({ error: err.message || 'Remove failed' });
      throw err;
    } finally {
      set({ actionInProgress: null });
    }
  },
}));

export default usePluginStore;
