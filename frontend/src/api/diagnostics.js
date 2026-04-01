/**
 * Diagnostics API module.
 * Merges /api/health + /api/status into a single runtime-truth snapshot.
 * Uses Promise.allSettled so partial failure yields honest degraded state.
 */
import api from './client';
import { normalizeHealth, normalizeStatus } from '../lib/status';

/**
 * Fetch a full diagnostics snapshot by combining health + status.
 * @returns {Promise<{ health: Object, status: Object, fetchedAt: string }>}
 */
export async function getDiagnosticsSnapshot() {
  const [healthRes, statusRes] = await Promise.allSettled([
    api.get('/health'),
    api.get('/status'),
  ]);

  const health =
    healthRes.status === 'fulfilled'
      ? normalizeHealth(healthRes.value.data)
      : { api: 'unknown', ws: 'unknown', db: 'unknown' };

  const status =
    statusRes.status === 'fulfilled'
      ? normalizeStatus(statusRes.value.data)
      : {
          status: 'unknown',
          powerState: 'unknown',
          llmStatus: 'unknown',
          deviceCount: 0,
          activeThreats: 0,
          threatsBlocked24h: 0,
          uptimeSeconds: 0,
          version: null,
        };

  return {
    health,
    status,
    fetchedAt: new Date().toISOString(),
  };
}
