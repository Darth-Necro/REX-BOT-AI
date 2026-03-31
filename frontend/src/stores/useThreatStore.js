import { create } from 'zustand';

const useThreatStore = create((set) => ({
  threats: [],
  total: 0,

  addThreat: (threat) => set((s) => ({
    threats: [threat, ...s.threats].slice(0, 200),
    total: s.total + 1,
  })),
  setThreats: (threats, total) => set({ threats, total }),
  resolveThreat: (id) => set((s) => ({
    threats: s.threats.map((t) => t.id === id ? { ...t, resolved: true } : t),
  })),
}));

export default useThreatStore;
