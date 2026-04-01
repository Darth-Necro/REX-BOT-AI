import axios from 'axios';
import useSystemStore from '../stores/useSystemStore';
import useAuthStore from '../stores/useAuthStore';

const api = axios.create({
  baseURL: import.meta.env.VITE_API_URL || '/api',
  timeout: 15000,
  headers: { 'Content-Type': 'application/json' },
});

// Attach auth token — check both stores (authStore is authoritative, systemStore is legacy)
api.interceptors.request.use((config) => {
  const token = useAuthStore.getState().token || useSystemStore.getState().token;
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// Handle 401 — clear token in ALL stores so React re-renders to LoginView
api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      useSystemStore.getState().logout();
      useAuthStore.getState().expire();
    }
    return Promise.reject(error);
  }
);

export default api;

export const getStatus = () => api.get('/status');
export const getDevices = () => api.get('/devices/');
export const getThreats = (params) => api.get('/threats/', { params });
export const login = (password) => api.post('/auth/login', { password });
export const triggerScan = () => api.post('/devices/scan');
export const panicButton = () => api.post('/firewall/panic');
