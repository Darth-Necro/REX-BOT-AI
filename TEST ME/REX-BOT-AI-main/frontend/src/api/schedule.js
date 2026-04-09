/**
 * Schedule API module.
 * Wraps /api/schedule endpoints for REX power schedule & job management.
 */
import api from './client';

/**
 * GET /api/schedule
 * @returns {Promise<{ powerState: string, mode: string, jobs: Array, capabilities: Object }>}
 */
export async function getSchedule() {
  const res = await api.get('/schedule');
  const data = res.data ?? {};
  const jobs = data.jobs ?? data.schedule ?? [];
  return {
    powerState: typeof data.power_state === 'string' ? data.power_state : 'unknown',
    mode: typeof data.mode === 'string' ? data.mode : 'unknown',
    jobs: Array.isArray(jobs) ? jobs : [],
    capabilities: data.capabilities ?? {},
  };
}

/**
 * PUT /api/schedule
 * @param {Object} schedule  { mode, jobs, power_state }
 * @returns {Promise<Object>}
 */
export async function updateSchedule(schedule) {
  if (!schedule || typeof schedule !== 'object') throw new Error('Schedule payload is required');
  const res = await api.put('/schedule', schedule);
  return res.data;
}
