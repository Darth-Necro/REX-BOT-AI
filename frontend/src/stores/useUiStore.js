/**
 * useUiStore — transient UI state: toasts, mode, etc.
 *
 * Toasts auto-dismiss after a configurable duration.
 * uiMode syncs with useSystemStore.mode but provides local-first control.
 */
import { create } from 'zustand';

let toastIdCounter = 0;

const TOAST_DEFAULTS = {
  success: { duration: 4000, icon: 'check' },
  warning: { duration: 6000, icon: 'warning' },
  error: { duration: 8000, icon: 'error' },
  pending: { duration: 0, icon: 'spinner' }, // 0 = no auto-dismiss
  unsupported: { duration: 6000, icon: 'unsupported' },
};

const useUiStore = create((set, get) => ({
  // --- Toast queue ---
  toasts: [],

  /**
   * Push a toast notification.
   * @param {{ type: 'success'|'warning'|'error'|'pending'|'unsupported', message: string, duration?: number }} toast
   * @returns {number} toast id (can be used to dismiss or replace)
   */
  pushToast: (toast) => {
    const id = ++toastIdCounter;
    const defaults = TOAST_DEFAULTS[toast.type] || TOAST_DEFAULTS.success;
    const duration = toast.duration ?? defaults.duration;

    const entry = {
      id,
      type: toast.type || 'success',
      message: toast.message || '',
      icon: defaults.icon,
      createdAt: Date.now(),
    };

    set((s) => ({ toasts: [...s.toasts, entry] }));

    // Auto-dismiss after duration (0 means manual dismiss only)
    if (duration > 0) {
      setTimeout(() => {
        get().dismissToast(id);
      }, duration);
    }

    return id;
  },

  /**
   * Dismiss a specific toast by id.
   */
  dismissToast: (id) => {
    set((s) => ({ toasts: s.toasts.filter((t) => t.id !== id) }));
  },

  /**
   * Replace the message/type of an existing toast (e.g. pending -> success).
   */
  replaceToast: (id, patch) => {
    set((s) => ({
      toasts: s.toasts.map((t) => {
        if (t.id !== id) return t;
        const newType = patch.type || t.type;
        const defaults = TOAST_DEFAULTS[newType] || TOAST_DEFAULTS.success;
        const updated = {
          ...t,
          ...patch,
          icon: defaults.icon,
        };

        // If the replacement has a duration, schedule auto-dismiss
        const duration = patch.duration ?? defaults.duration;
        if (duration > 0) {
          setTimeout(() => {
            get().dismissToast(id);
          }, duration);
        }

        return updated;
      }),
    }));
  },

  // --- UI mode ---
  uiMode: 'advanced', // 'basic' | 'advanced'

  setUiMode: (mode) => {
    if (mode !== 'basic' && mode !== 'advanced') return;
    set({ uiMode: mode });
  },

  toggleUiMode: () =>
    set((s) => ({ uiMode: s.uiMode === 'basic' ? 'advanced' : 'basic' })),
}));

export default useUiStore;
