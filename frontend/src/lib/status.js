/**
 * Status normalisation helpers.
 *
 * Ensures every field the stores expect is present with a sane default,
 * regardless of what shape the backend actually returns.
 */

const STATUS_DEFAULTS = {
  status: 'unknown',
  powerState: 'unknown',
  llmStatus: 'unknown',
  deviceCount: 0,
  activeThreats: 0,
  threatsBlocked24h: 0,
  uptimeSeconds: 0,
  version: null,
  _timestamp: null,
};

const HEALTH_DEFAULTS = {
  api: 'unknown',
  ws: 'unknown',
  db: 'unknown',
};

/**
 * Normalise a raw /api/status (or WS status.update) payload.
 * Missing keys are filled with safe defaults; unexpected keys are passed through.
 */
export function normalizeStatus(raw) {
  if (!raw || typeof raw !== 'object') return { ...STATUS_DEFAULTS };

  return {
    ...STATUS_DEFAULTS,
    status: String(raw.status ?? STATUS_DEFAULTS.status),
    powerState: String(raw.power_state ?? raw.powerState ?? STATUS_DEFAULTS.powerState),
    llmStatus: String(raw.llm_status ?? raw.llmStatus ?? STATUS_DEFAULTS.llmStatus),
    deviceCount: Number(raw.device_count ?? raw.deviceCount ?? STATUS_DEFAULTS.deviceCount) || 0,
    activeThreats: Number(raw.active_threats ?? raw.activeThreats ?? STATUS_DEFAULTS.activeThreats) || 0,
    threatsBlocked24h: Number(raw.threats_blocked_24h ?? raw.threatsBlocked24h ?? STATUS_DEFAULTS.threatsBlocked24h) || 0,
    uptimeSeconds: Number(raw.uptime_seconds ?? raw.uptimeSeconds ?? STATUS_DEFAULTS.uptimeSeconds) || 0,
    version: raw.version ?? STATUS_DEFAULTS.version,
    _timestamp: raw._timestamp ?? raw.timestamp ?? null,
  };
}

/**
 * Normalise a raw /api/health response.
 */
export function normalizeHealth(raw) {
  if (!raw || typeof raw !== 'object') return { ...HEALTH_DEFAULTS };

  return {
    ...HEALTH_DEFAULTS,
    api: String(raw.api ?? raw.status ?? HEALTH_DEFAULTS.api),
    ws: String(raw.ws ?? raw.websocket ?? HEALTH_DEFAULTS.ws),
    db: String(raw.db ?? raw.database ?? HEALTH_DEFAULTS.db),
  };
}

/**
 * Derive threat posture from normalised status data.
 *
 * Returns one of: 'critical' | 'elevated' | 'guarded' | 'normal' | 'unknown'.
 */
export function derivePosture(data) {
  if (!data || data.status === 'unknown') return 'unknown';

  const threats = data.activeThreats ?? 0;

  if (threats >= 5) return 'critical';
  if (threats >= 2) return 'elevated';
  if (threats >= 1) return 'guarded';
  return 'normal';
}
