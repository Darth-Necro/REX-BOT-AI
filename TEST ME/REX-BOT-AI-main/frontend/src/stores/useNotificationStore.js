/**
 * useNotificationStore — notification settings state with API hydration.
 *
 * capabilities drives permission checks (deny-by-default).
 * testResult stores the last test notification outcome for display.
 */
import { create } from 'zustand';
import {
  getNotificationSettings,
  updateNotificationSettings,
  testNotifications as apiTestNotifications,
} from '../api/notifications';

const useNotificationStore = create((set, get) => ({
  settings: {
    discord_webhook: '',
    telegram_bot_token: '',
    telegram_chat_id: '',
    email_to: '',
    email_smtp_host: '',
    matrix_homeserver: '',
    matrix_room_id: '',
    matrix_token: '',
    enabled_channels: [],
  },
  capabilities: {},
  loading: false,
  saving: false,
  testing: false,
  error: null,
  testResult: null, // { success: boolean, details: Object } | null

  /* ---------- hydration ---------- */

  fetchSettings: async () => {
    if (get().loading) return;
    set({ loading: true, error: null });
    try {
      const { settings, capabilities } = await getNotificationSettings();
      set({ settings, capabilities, loading: false });
    } catch (err) {
      set({
        error: err.message || 'Failed to fetch notification settings',
        loading: false,
      });
    }
  },

  /* ---------- mutations ---------- */

  saveSettings: async (patch) => {
    if (get().saving) return;
    set({ saving: true, error: null });
    try {
      const merged = { ...get().settings, ...patch };
      await updateNotificationSettings(merged);
      set({ settings: merged, saving: false });
      return true;
    } catch (err) {
      set({
        error: err.message || 'Failed to save notification settings',
        saving: false,
      });
      return false;
    }
  },

  testNotifications: async () => {
    if (get().testing) return;
    set({ testing: true, testResult: null, error: null });
    try {
      const result = await apiTestNotifications();
      set({ testResult: { success: true, details: result }, testing: false });
      return true;
    } catch (err) {
      set({
        testResult: { success: false, details: { error: err.message } },
        testing: false,
      });
      return false;
    }
  },

  /* ---------- local setters ---------- */

  updateSettingsLocal: (patch) =>
    set((s) => ({ settings: { ...s.settings, ...patch } })),

  clearError: () => set({ error: null }),
  clearTestResult: () => set({ testResult: null }),
}));

export default useNotificationStore;
