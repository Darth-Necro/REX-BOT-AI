/**
 * Threat API -- fetch threat list and individual threat details.
 *
 * Response normalization ensures downstream code always gets an array
 * regardless of backend envelope shape.
 */

import api from './client';

/**
 * Fetch threats with optional filters.
 * @param {Object} [params]             Query params.
 * @param {number} [params.limit=100]   Max results.
 * @param {string} [params.severity]    Filter by severity level.
 * @param {string} [params.since]       ISO date for time-range filter.
 * @returns {Promise<{ threats: Array, total: number }>}
 */
export async function getThreats(params = {}) {
  const res = await api.get('/threats/', { params });
  const data = res.data;
  const list = data?.threats || data || [];
  const threats = Array.isArray(list) ? list : [];
  return {
    threats,
    total: data?.total ?? threats.length,
  };
}

/**
 * Fetch a single threat by ID.
 * @param {string} id  Threat identifier.
 * @returns {Promise<Object>}
 */
export async function getThreat(id) {
  if (!id) throw new Error('Threat ID is required');
  const res = await api.get(`/threats/${encodeURIComponent(id)}`);
  return res.data;
}

/**
 * Mark a threat as resolved.
 * @param {string} id  Threat identifier.
 * @returns {Promise<Object>}
 */
export async function resolveThreat(id) {
  if (!id) throw new Error('Threat ID is required');
  const res = await api.put(`/threats/${encodeURIComponent(id)}/resolve`);
  return res.data;
}

/**
 * Mark a threat as a false positive.
 * @param {string} id  Threat identifier.
 * @returns {Promise<Object>}
 */
export async function markFalsePositive(id) {
  if (!id) throw new Error('Threat ID is required');
  const res = await api.put(`/threats/${encodeURIComponent(id)}/false-positive`);
  return res.data;
}
