/**
 * useSchedulerStore — power schedule and job state.
 *
 * powerState is OWNED by useSystemStore (single source of truth).
 * This store reads it from schedule responses and syncs it to useSystemStore;
 * the local `powerState` field is kept for backward compat but always mirrors
 * the authoritative value.
 *
 * jobs is the list of scheduled tasks with their cadence and status.
 */
import { create } from 'zustand';
import { getSchedule, updateSchedule } from '../api/schedule';
import useSystemStore from './useSystemStore';

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

      // Sync powerState to the authoritative system store so there is
      // never a disagreement between the two stores.
      if (powerState && powerState !== 'unknown') {
        useSystemStore.setState({ powerState });
      }
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
