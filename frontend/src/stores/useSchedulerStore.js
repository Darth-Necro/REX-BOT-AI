/**
 * useSchedulerStore — power schedule and job state.
 *
 * powerState reflects the current REX operating mode (awake/sleep/etc).
 * jobs is the list of scheduled tasks with their cadence and status.
 */
import { create } from 'zustand';
import { getSchedule, updateSchedule } from '../api/schedule';

const useSchedulerStore = create((set, get) => ({
  powerState: 'unknown',
  mode: 'unknown',
  jobs: [],
  loading: false,
  saving: false,
  error: null,
  capabilities: {},

  /* ---------- hydration ---------- */

  fetchSchedule: async () => {
    if (get().loading) return;
    set({ loading: true, error: null });
    try {
      const { powerState, mode, jobs, capabilities } = await getSchedule();
      set({ powerState, mode, jobs, capabilities, loading: false });
    } catch (err) {
      set({ error: err.message || 'Failed to fetch schedule', loading: false });
    }
  },

  /* ---------- mutations ---------- */

  saveSchedule: async (schedule) => {
    set({ saving: true, error: null });
    try {
      await updateSchedule(schedule);
      // Re-fetch to reflect backend-confirmed state
      await get().fetchSchedule();
      set({ saving: false });
    } catch (err) {
      set({ saving: false, error: err.message || 'Failed to update schedule' });
      throw err;
    }
  },
}));

export default useSchedulerStore;
