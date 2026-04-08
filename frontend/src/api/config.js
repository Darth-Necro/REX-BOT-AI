/**
 * Config API -- system configuration endpoints.
 */
import api from './client';

/**
 * GET /api/config/ -- fetch current system configuration.
 */
export async function getConfig() {
  const res = await api.get('/config/');
  return res.data || {};
}

/**
 * PUT /api/config/ -- update system configuration.
 * @param {Object} payload  Fields to update.
 */
export async function updateConfig(payload) {
  const res = await api.put('/config/', payload);
  return res.data || {};
}
