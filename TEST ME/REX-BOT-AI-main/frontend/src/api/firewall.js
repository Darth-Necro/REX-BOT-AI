/**
 * Firewall API module.
 * Wraps /api/firewall endpoints. Returns normalised data;
 * callers handle errors.
 */
import api from './client';

/**
 * GET /api/firewall/rules
 * @returns {Promise<{ rules: Array, capabilities: Object }>}
 */
export async function getFirewallRules() {
  const res = await api.get('/firewall/rules');
  const data = res.data ?? {};
  const list = data.rules ?? data ?? [];
  return {
    rules: Array.isArray(list) ? list : [],
    capabilities: data.capabilities ?? {},
  };
}

/**
 * POST /api/firewall/rules
 * @param {Object} rule  { action, source, destination, port, protocol, reason }
 * @returns {Promise<Object>} The created rule.
 */
export async function createFirewallRule(rule) {
  if (!rule) throw new Error('Rule payload is required');
  const res = await api.post('/firewall/rules', rule);
  return res.data?.rule ?? res.data;
}

/**
 * DELETE /api/firewall/rules/:id
 * @param {string} id  Rule identifier.
 */
export async function deleteFirewallRule(id) {
  if (!id) throw new Error('Rule ID is required');
  await api.delete(`/firewall/rules/${encodeURIComponent(id)}`);
}

/**
 * POST /api/firewall/panic — activate / restore panic mode.
 * @param {'activate'|'restore'} action  Defaults to 'restore'.
 * @returns {Promise<Object>}
 */
export async function panicRestore(action = 'restore') {
  const endpoint = action === 'activate' ? '/firewall/panic' : '/firewall/panic/restore';
  const res = await api.post(endpoint);
  return res.data;
}
