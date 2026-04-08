/**
 * useFederationStore -- federation status, peers, and toggle actions.
 */
import { create } from 'zustand';
import {
  getFederationStatus,
  getFederationPeers,
  enableFederation as apiEnable,
  disableFederation as apiDisable,
} from '../api/federation';

const useFederationStore = create((set, get) => ({
  enabled: false,
  peerCount: 0,
  sharedIocCount: 0,
  peers: [],
  loading: false,
  toggling: false,
  error: null,

  fetchStatus: async () => {
    if (get().loading) return;
    set({ loading: true, error: null });
    try {
      const [status, peersData] = await Promise.all([
        getFederationStatus(),
        getFederationPeers().catch(() => ({ peers: [], count: 0 })),
      ]);
      set({
        enabled: status.enabled,
        peerCount: status.peerCount,
        sharedIocCount: status.sharedIocCount,
        peers: peersData.peers,
        loading: false,
      });
    } catch (err) {
      set({ error: err.message || 'Failed to fetch federation status', loading: false });
    }
  },

  enable: async () => {
    set({ toggling: true, error: null });
    try {
      await apiEnable();
      await get().fetchStatus();
    } catch (err) {
      set({ error: err.message || 'Failed to enable federation' });
    } finally {
      set({ toggling: false });
    }
  },

  disable: async () => {
    set({ toggling: true, error: null });
    try {
      await apiDisable();
      await get().fetchStatus();
    } catch (err) {
      set({ error: err.message || 'Failed to disable federation' });
    } finally {
      set({ toggling: false });
    }
  },
}));

export default useFederationStore;
