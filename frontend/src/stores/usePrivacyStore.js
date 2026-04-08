/**
 * usePrivacyStore — privacy summary + audit state.
 *
 * capabilities drives permission checks (deny-by-default).
 * auditResult is null until an audit has been run.
 */
import { create } from 'zustand';
import {
  getPrivacySummary,
  runPrivacyAudit as apiRunAudit,
  getConnections as apiGetConnections,
  getInventory as apiGetInventory,
  getEncryption as apiGetEncryption,
} from '../api/privacy';

const usePrivacyStore = create((set, get) => ({
  signals: [],
  retention: { policy: 'unknown', days: null },
  capabilities: {},
  loading: false,
  error: null,

  auditResult: null, // { findings: Array, score: number|null, ranAt: string } | null
  auditing: false,
  auditError: null,

  /* ---------- hydration ---------- */

  fetchPrivacyState: async () => {
    if (get().loading) return;
    set({ loading: true, error: null });
    try {
      const { signals, retention, capabilities } = await getPrivacySummary();
      set({ signals, retention, capabilities, loading: false });
    } catch (err) {
      set({
        error: err.message || 'Failed to fetch privacy summary',
        loading: false,
      });
    }
  },

  /* ---------- audit ---------- */

  runAudit: async () => {
    if (get().auditing) return;
    set({ auditing: true, auditError: null });
    try {
      const result = await apiRunAudit();
      set({ auditResult: result, auditing: false });
      return result;
    } catch (err) {
      set({
        auditError: err.message || 'Privacy audit failed',
        auditing: false,
      });
      return null;
    }
  },

  /* ---------- sub-endpoint hydration ---------- */

  connections: [],
  inventory: null,
  encryption: null,

  fetchConnections: async () => {
    try {
      const data = await apiGetConnections();
      set({ connections: data.connections });
    } catch (_) { /* non-critical */ }
  },

  fetchInventory: async () => {
    try {
      const data = await apiGetInventory();
      set({ inventory: data });
    } catch (_) { /* non-critical */ }
  },

  fetchEncryption: async () => {
    try {
      const data = await apiGetEncryption();
      set({ encryption: data });
    } catch (_) { /* non-critical */ }
  },

  /* ---------- local setters ---------- */

  clearError: () => set({ error: null, auditError: null }),
}));

export default usePrivacyStore;
