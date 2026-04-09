/**
 * useKnowledgeBaseStore — knowledge base content, version history, capabilities.
 *
 * Content is a raw string (markdown / plain text) that REX uses
 * for context. History tracks revisions so operators can audit + revert.
 */
import { create } from 'zustand';
import {
  getKnowledgeBase,
  getKnowledgeBaseHistory,
  updateKnowledgeBase,
  revertKnowledgeBase,
} from '../api/kb';

const useKnowledgeBaseStore = create((set, get) => ({
  content: '',
  version: 0,
  updatedAt: null,
  history: [],
  loading: false,
  historyLoading: false,
  saving: false,
  error: null,
  capabilities: {},

  /* ---------- hydration ---------- */

  fetchKB: async () => {
    if (get().loading) return;
    set({ loading: true, error: null });
    try {
      const { content, version, updatedAt, capabilities } = await getKnowledgeBase();
      set({ content, version, updatedAt, capabilities, loading: false });
    } catch (err) {
      set({ error: err.message || 'Failed to fetch knowledge base', loading: false });
    }
  },

  fetchHistory: async (params) => {
    set({ historyLoading: true });
    try {
      const { history } = await getKnowledgeBaseHistory(params);
      set({ history, historyLoading: false });
    } catch (err) {
      set({ error: err.message || 'Failed to fetch history', historyLoading: false });
    }
  },

  /* ---------- mutations ---------- */

  saveKB: async (content) => {
    set({ saving: true, error: null });
    try {
      const result = await updateKnowledgeBase(content);
      set({
        content,
        version: result?.version ?? get().version + 1,
        updatedAt: result?.updated_at ?? new Date().toISOString(),
        saving: false,
      });
      return result;
    } catch (err) {
      set({ saving: false, error: err.message || 'Failed to save knowledge base' });
      throw err;
    }
  },

  revertKB: async (version) => {
    set({ saving: true, error: null });
    try {
      await revertKnowledgeBase(version);
      // Re-fetch to get the reverted content
      await get().fetchKB();
      set({ saving: false });
    } catch (err) {
      set({ saving: false, error: err.message || 'Failed to revert' });
      throw err;
    }
  },
}));

export default useKnowledgeBaseStore;
