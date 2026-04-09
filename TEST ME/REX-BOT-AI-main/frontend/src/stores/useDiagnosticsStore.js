/**
 * useDiagnosticsStore — runtime truth from /health + /status.
 *
 * snapshot is the raw merged payload. serviceHealth is derived
 * into a list of { name, status } entries for the health grid.
 */
import { create } from 'zustand';
import { getDiagnosticsSnapshot } from '../api/diagnostics';

/**
 * Derive a flat array of service health entries from the snapshot.
 */
function deriveServiceHealth(snapshot) {
  if (!snapshot) return [];

  const entries = [];
  const { health, status } = snapshot;

  if (health) {
    entries.push({ name: 'API', status: health.api ?? 'unknown' });
    entries.push({ name: 'WebSocket', status: health.ws ?? 'unknown' });
    entries.push({ name: 'Database', status: health.db ?? 'unknown' });
  }

  if (status) {
    entries.push({ name: 'System', status: status.status ?? 'unknown' });
    entries.push({ name: 'LLM Engine', status: status.llmStatus ?? 'unknown' });
    entries.push({
      name: 'Power State',
      status: status.powerState ?? 'unknown',
      isMeta: true,
    });
  }

  return entries;
}

const useDiagnosticsStore = create((set, get) => ({
  snapshot: null,
  serviceHealth: [],
  loading: false,
  error: null,
  fetchedAt: null,

  fetchDiagnostics: async () => {
    if (get().loading) return;
    set({ loading: true, error: null });
    try {
      const snapshot = await getDiagnosticsSnapshot();
      set({
        snapshot,
        serviceHealth: deriveServiceHealth(snapshot),
        fetchedAt: snapshot.fetchedAt,
        loading: false,
      });
    } catch (err) {
      set({ error: err.message || 'Failed to fetch diagnostics', loading: false });
    }
  },
}));

export default useDiagnosticsStore;
