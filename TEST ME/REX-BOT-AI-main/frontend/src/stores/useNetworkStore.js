/**
 * useNetworkStore -- topology state with API hydration.
 *
 * Fetches device-derived topology via getNetworkTopology().
 * Stores nodes, segments, selectedNode, and degraded state.
 */

import { create } from 'zustand';
import { getNetworkTopology } from '../api/network';

const useNetworkStore = create((set, get) => ({
  nodes: [],
  segments: [],
  gateway: null,
  selectedNode: null,
  loading: false,
  error: null,
  degraded: false,
  fetchedAt: null,

  /* ---------- full hydration from API ---------- */

  fetchTopology: async () => {
    if (get().loading) return;
    set({ loading: true, error: null });
    try {
      const data = await getNetworkTopology();
      set({
        nodes: data.nodes,
        segments: data.segments,
        gateway: data.gateway,
        degraded: data.degraded,
        fetchedAt: data.fetchedAt,
        loading: false,
      });
    } catch (err) {
      set({
        error: err.message || 'Failed to fetch network topology',
        loading: false,
      });
    }
  },

  /* ---------- selection ---------- */

  selectNode: (node) => set({ selectedNode: node }),
  clearSelection: () => set({ selectedNode: null }),

  /* ---------- derived lookups ---------- */

  /**
   * Find a node by its id (mac address).
   * @param {string} id
   * @returns {Object|null}
   */
  findNode: (id) => {
    return get().nodes.find((n) => n.id === id) || null;
  },

  /**
   * Get nodes belonging to a specific segment.
   * @param {string} segment
   * @returns {Array}
   */
  nodesInSegment: (segment) => {
    return get().nodes.filter((n) => n.segment === segment);
  },
}));

export default useNetworkStore;
