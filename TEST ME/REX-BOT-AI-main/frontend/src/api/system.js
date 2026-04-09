/**
 * System API module — thin wrappers around the axios client.
 * Every function returns the Axios promise so callers handle errors themselves.
 */
import api from './client';
import { normalizeStatus, normalizeHealth } from '../lib/status';

/**
 * GET /api/health — lightweight liveness probe.
 */
export async function getHealth() {
  const res = await api.get('/health');
  return normalizeHealth(res.data);
}

/**
 * GET /api/status — full system snapshot.
 */
export async function getStatus() {
  const res = await api.get('/status');
  return normalizeStatus(res.data);
}

/**
 * Perform initial hydration: fetch health + status in parallel.
 * Returns a merged object the store can spread directly.
 */
export async function hydrateSystemState() {
  const [health, status] = await Promise.allSettled([
    getHealth(),
    getStatus(),
  ]);

  const healthData =
    health.status === 'fulfilled' ? health.value : { api: 'unknown', ws: 'unknown', db: 'unknown' };
  const statusData =
    status.status === 'fulfilled'
      ? status.value
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
    apiConnection: healthData.api === 'healthy' ? 'connected' : healthData.api === 'unknown' ? 'unknown' : 'degraded',
    health: healthData,
    ...statusData,
  };
}
