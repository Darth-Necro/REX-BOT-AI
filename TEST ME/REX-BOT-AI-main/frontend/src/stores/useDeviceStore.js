/**
 * useDeviceStore -- device list state with API hydration and WS delta support.
 *
 * Hydration:  fetchDevices() pulls the full list from the API.
 * Deltas:     applyDeviceDelta() merges individual device events from WS.
 * Selection:  selectedDevice for detail panel navigation.
 */

import { create } from 'zustand';
import { getDevices } from '../api/devices';

const useDeviceStore = create((set, get) => ({
  devices: [],
  total: 0,
  selectedDevice: null,
  loading: false,
  error: null,

  /* ---------- full hydration from API ---------- */

  fetchDevices: async () => {
    set({ loading: true, error: null });
    try {
      const list = await getDevices();
      set({ devices: list, total: list.length, loading: false });
    } catch (err) {
      set({ error: err.message || 'Failed to fetch devices', loading: false });
    }
  },

  /* ---------- WS delta handlers ---------- */

  /**
   * Apply a single device delta from a WebSocket event.
   * @param {'new_device'|'device_departed'|'device_update'} type
   * @param {Object} payload  Device data from the event.
   */
  applyDeviceDelta: (type, payload) => {
    const mac = payload?.mac_address;
    if (!mac) return;

    set((s) => {
      switch (type) {
        case 'new_device':
        case 'device.new': {
          // Avoid duplicates
          if (s.devices.some((d) => d.mac_address === mac)) {
            return {
              devices: s.devices.map((d) =>
                d.mac_address === mac ? { ...d, ...payload } : d
              ),
            };
          }
          const next = [...s.devices, payload];
          return { devices: next, total: next.length };
        }

        case 'device_departed':
        case 'device.departed': {
          const next = s.devices.filter((d) => d.mac_address !== mac);
          return {
            devices: next,
            total: next.length,
            selectedDevice:
              s.selectedDevice?.mac_address === mac ? null : s.selectedDevice,
          };
        }

        case 'device_update':
        case 'device.update': {
          return {
            devices: s.devices.map((d) =>
              d.mac_address === mac ? { ...d, ...payload } : d
            ),
            selectedDevice:
              s.selectedDevice?.mac_address === mac
                ? { ...s.selectedDevice, ...payload }
                : s.selectedDevice,
          };
        }

        default:
          return {};
      }
    });
  },

  /* ---------- legacy compat (Batch 1 callers) ---------- */

  setDevices: (devices) => set({ devices, total: devices.length }),

  addDevice: (device) =>
    set((s) => ({
      devices: [...s.devices, device],
      total: s.total + 1,
    })),

  updateDevice: (mac, updates) =>
    set((s) => ({
      devices: s.devices.map((d) =>
        d.mac_address === mac ? { ...d, ...updates } : d
      ),
    })),

  /* ---------- selection ---------- */

  selectDevice: (device) => set({ selectedDevice: device }),
  clearSelection: () => set({ selectedDevice: null }),
}));

export default useDeviceStore;
