/**
 * useAgentStore -- agent action registry and scope state.
 */
import { create } from 'zustand';
import { getAgentActions, getAgentActionsByDomain, getAgentScope } from '../api/agent';

const useAgentStore = create((set, get) => ({
  actions: [],
  count: 0,
  scope: null,
  loading: false,
  error: null,
  domainFilter: null,

  fetchActions: async () => {
    if (get().loading) return;
    set({ loading: true, error: null });
    try {
      const [actionsData, scopeData] = await Promise.all([
        getAgentActions(),
        getAgentScope().catch(() => null),
      ]);
      set({
        actions: actionsData.actions,
        count: actionsData.count,
        scope: scopeData,
        loading: false,
        domainFilter: null,
      });
    } catch (err) {
      set({ error: err.message || 'Failed to fetch agent actions', loading: false });
    }
  },

  filterByDomain: async (domain) => {
    set({ loading: true, error: null, domainFilter: domain });
    try {
      if (!domain) {
        const data = await getAgentActions();
        set({ actions: data.actions, count: data.count, loading: false });
      } else {
        const data = await getAgentActionsByDomain(domain);
        set({ actions: data.actions, count: data.count, loading: false });
      }
    } catch (err) {
      set({ error: err.message || 'Failed to filter actions', loading: false });
    }
  },
}));

export default useAgentStore;
