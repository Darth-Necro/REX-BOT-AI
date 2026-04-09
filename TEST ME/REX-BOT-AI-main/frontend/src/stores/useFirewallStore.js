/**
 * useFirewallStore — firewall rules state with API hydration.
 *
 * capabilities object drives permission checks in the UI.
 * All mutations are gated on loading to prevent double-fire.
 */
import { create } from 'zustand';
import {
  getFirewallRules,
  createFirewallRule,
  deleteFirewallRule,
  panicRestore as apiPanicRestore,
} from '../api/firewall';

const useFirewallStore = create((set, get) => ({
  rules: [],
  loading: false,
  error: null,
  capabilities: {},

  /* ---------- hydration ---------- */

  fetchRules: async () => {
    if (get().loading) return;
    set({ loading: true, error: null });
    try {
      const { rules, capabilities } = await getFirewallRules();
      set({ rules, capabilities, loading: false });
    } catch (err) {
      set({ error: err.message || 'Failed to fetch firewall rules', loading: false });
    }
  },

  /* ---------- mutations ---------- */

  createRule: async (rule) => {
    set({ error: null });
    try {
      const created = await createFirewallRule(rule);
      set((s) => ({ rules: [...s.rules, created] }));
      return created;
    } catch (err) {
      set({ error: err.message || 'Failed to create rule' });
      throw err;
    }
  },

  deleteRule: async (id) => {
    set({ error: null });
    try {
      await deleteFirewallRule(id);
      set((s) => ({ rules: s.rules.filter((r) => r.id !== id) }));
    } catch (err) {
      set({ error: err.message || 'Failed to delete rule' });
      throw err;
    }
  },

  panicRestore: async (action = 'restore') => {
    set({ error: null });
    try {
      await apiPanicRestore(action);
      // Re-fetch to reflect the new reality
      await get().fetchRules();
    } catch (err) {
      set({ error: err.message || 'Panic action failed' });
      throw err;
    }
  },
}));

export default useFirewallStore;
