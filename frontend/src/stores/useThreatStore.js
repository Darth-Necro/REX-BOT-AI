/**
 * useThreatStore -- threat list state with API hydration and WS delta support.
 *
 * Hydration:  fetchThreats() pulls the full list from the API.
 * Deltas:     applyThreatDelta() merges individual threat events from WS.
 * Selection:  selectedThreat for detail panel navigation.
 */

import { create } from 'zustand';
import { getThreats } from '../api/threats';

const useThreatStore = create((set, get) => ({
  threats: [],
  total: 0,
  selectedThreat: null,
  loading: false,
  error: null,

  /* ---------- full hydration from API ---------- */

  fetchThreats: async (params) => {
    set({ loading: true, error: null });
    try {
      const { threats, total } = await getThreats(params);
      set({ threats, total, loading: false });
    } catch (err) {
      set({ error: err.message || 'Failed to fetch threats', loading: false });
    }
  },

  /* ---------- WS delta handlers ---------- */

  /**
   * Apply a single threat delta from a WebSocket event.
   * @param {'threat_detected'|'threat_resolved'} type
   * @param {Object} payload  Threat data from the event.
   */
  applyThreatDelta: (type, payload) => {
    if (!payload) return;

    set((s) => {
      switch (type) {
        case 'threat_detected':
        case 'threat.new': {
          // Prepend new threat, cap at 200 for memory
          const next = [payload, ...s.threats].slice(0, 200);
          return { threats: next, total: s.total + 1 };
        }

        case 'threat_resolved':
        case 'threat.resolved': {
          const id = payload.id || payload.threat_id;
          return {
            threats: s.threats.map((t) =>
              t.id === id ? { ...t, resolved: true, status: 'resolved' } : t
            ),
            selectedThreat:
              s.selectedThreat?.id === id
                ? { ...s.selectedThreat, resolved: true, status: 'resolved' }
                : s.selectedThreat,
          };
        }

        default:
          return {};
      }
    });
  },

  /* ---------- legacy compat (Batch 1 callers) ---------- */

  addThreat: (threat) =>
    set((s) => ({
      threats: [threat, ...s.threats].slice(0, 200),
      total: s.total + 1,
    })),

  setThreats: (threats, total) => set({ threats, total: total ?? threats.length }),

  resolveThreat: (id) =>
    set((s) => ({
      threats: s.threats.map((t) =>
        t.id === id ? { ...t, resolved: true, status: 'resolved' } : t
      ),
    })),

  /* ---------- selection ---------- */

  selectThreat: (threat) => set({ selectedThreat: threat }),
  clearSelection: () => set({ selectedThreat: null }),
}));

export default useThreatStore;
