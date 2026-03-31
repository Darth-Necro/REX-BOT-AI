import axios from 'axios';

const api = axios.create({
  baseURL: import.meta.env.VITE_API_URL || '/api',
  timeout: 15000,
  headers: { 'Content-Type': 'application/json' },
});

// Attach auth token
api.interceptors.request.use((config) => {
  const token = localStorage.getItem('rex_token');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// Handle 401
api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      localStorage.removeItem('rex_token');
      window.location.href = '/login';
    }
    return Promise.reject(error);
  }
);

export default api;

export const getStatus = () => api.get('/status');
export const getDevices = () => api.get('/devices/');
export const getThreats = (params) => api.get('/threats/', { params });
export const login = (password) => api.post('/config/auth/login', { password });
export const triggerScan = () => api.post('/devices/scan');
export const panicButton = () => api.post('/firewall/panic');
