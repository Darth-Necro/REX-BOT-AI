/**
 * Plugins API module.
 * Wraps /api/plugins endpoints for the REX plugin system.
 */
import api from './client';

/**
 * GET /api/plugins/installed
 * @returns {Promise<{ plugins: Array, capabilities: Object }>}
 */
export async function getInstalledPlugins() {
  const res = await api.get('/plugins/installed');
  const data = res.data ?? {};
  const list = data.plugins ?? data ?? [];
  return {
    plugins: Array.isArray(list) ? list : [],
    capabilities: data.capabilities ?? {},
  };
}

/**
 * GET /api/plugins/available
 * @returns {Promise<{ plugins: Array }>}
 */
export async function getAvailablePlugins() {
  const res = await api.get('/plugins/available');
  const data = res.data ?? {};
  const list = data.plugins ?? data ?? [];
  return { plugins: Array.isArray(list) ? list : [] };
}

/**
 * POST /api/plugins/install/{pluginId}
 * @param {string} pluginId  Plugin identifier.
 * @returns {Promise<Object>}
 */
export async function installPlugin(pluginId) {
  if (!pluginId) throw new Error('Plugin ID is required');
  const res = await api.post(`/plugins/install/${encodeURIComponent(pluginId)}`);
  return res.data;
}

/**
 * DELETE /api/plugins/{pluginId}
 * @param {string} pluginId  Plugin identifier.
 * @returns {Promise<Object>}
 */
export async function removePlugin(pluginId) {
  if (!pluginId) throw new Error('Plugin ID is required');
  const res = await api.delete(`/plugins/${encodeURIComponent(pluginId)}`);
  return res.data;
}
