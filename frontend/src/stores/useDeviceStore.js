import { create } from 'zustand';

const useDeviceStore = create((set) => ({
  devices: [],
  total: 0,

  setDevices: (devices) => set({ devices, total: devices.length }),
  addDevice: (device) => set((s) => ({
    devices: [...s.devices, device],
    total: s.total + 1,
  })),
  updateDevice: (mac, updates) => set((s) => ({
    devices: s.devices.map((d) => d.mac_address === mac ? { ...d, ...updates } : d),
  })),
}));

export default useDeviceStore;
