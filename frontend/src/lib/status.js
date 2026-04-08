/**
 * Status normalisation helpers.
 *
 * Ensures every field the stores expect is present with a sane default,
 * regardless of what shape the backend actually returns.
 * Validates enum values and clamps numeric counts to >= 0.
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

const VALID_STATUS = new Set(['operational', 'degraded', 'critical', 'maintenance', 'unknown']);
const VALID_POWER = new Set(['awake', 'alert_sleep', 'deep_sleep', 'off', 'unknown']);
const VALID_LLM = new Set(['ready', 'loading', 'error', 'disabled', 'unknown']);

const HEALTH_DEFAULTS = {
  api: 'unknown',
  ws: 'unknown',
  db: 'unknown',
};

function clampCount(val) {
  const n = Number(val);
  if (!Number.isFinite(n) || n < 0) return 0;
  return n;
}

function validateEnum(val, validSet, fallback) {
  if (typeof val !== 'string') return fallback;
  return validSet.has(val) ? val : fallback;
}

/**
 * Normalise a raw /api/status (or WS status.update) payload.
 * Missing keys are filled with safe defaults; unexpected keys are passed through.
 * Unrecognised enum values become 'unknown'. Negative counts become 0.
 */
export function normalizeStatus(raw) {
  if (!raw || typeof raw !== 'object') return { ...STATUS_DEFAULTS };

  return {
    ...STATUS_DEFAULTS,
    status: validateEnum(raw.status, VALID_STATUS, 'unknown'),
    powerState: validateEnum(raw.power_state ?? raw.powerState, VALID_POWER, 'unknown'),
    llmStatus: validateEnum(raw.llm_status ?? raw.llmStatus, VALID_LLM, 'unknown'),
    deviceCount: clampCount(raw.device_count ?? raw.deviceCount ?? 0),
    activeThreats: clampCount(raw.active_threats ?? raw.activeThreats ?? 0),
    threatsBlocked24h: clampCount(raw.threats_blocked_24h ?? raw.threatsBlocked24h ?? 0),
    uptimeSeconds: clampCount(raw.uptime_seconds ?? raw.uptimeSeconds ?? 0),
    version: typeof raw.version === 'string' ? raw.version : null,
    _timestamp: raw._timestamp ?? raw.timestamp ?? null,
  };
}

/**
 * Normalise a raw /api/health response.
 */
export function normalizeHealth(raw) {
  if (!raw || typeof raw !== 'object') return { ...HEALTH_DEFAULTS };

  // Handle boolean healthy/api fields
  const apiVal = raw.api ?? raw.healthy ?? raw.status ?? HEALTH_DEFAULTS.api;
  const apiStr = apiVal === true ? 'healthy' : apiVal === false ? 'critical' : String(apiVal);

  return {
    ...HEALTH_DEFAULTS,
    api: apiStr,
    ws: String(raw.ws ?? raw.websocket ?? HEALTH_DEFAULTS.ws),
    db: String(raw.db ?? raw.database ?? HEALTH_DEFAULTS.db),
  };
}

/**
 * Derive threat posture from normalised status data.
 *
 * Returns one of: 'critical' | 'elevated' | 'nominal' | 'unknown'.
 */
export function derivePosture(data) {
  if (!data || data.status === 'unknown') return 'unknown';

  const threats = data.activeThreats ?? 0;
  const status = data.status;

  if (status === 'critical' || threats >= 5) return 'critical';
  if (status === 'degraded' || threats >= 1) return 'elevated';
  return 'nominal';
}
