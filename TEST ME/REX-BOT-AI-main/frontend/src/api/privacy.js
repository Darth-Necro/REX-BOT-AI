/**
 * Privacy API module.
 * Thin wrappers for privacy status and audit endpoints.
 * Returns honest defaults when the backend provides nothing.
 */
import api from './client';

/**
 * GET /api/privacy/status — high-level privacy signals.
 * @returns {Promise<{ signals: Array, retention: Object, capabilities: Object }>}
 */
export async function getPrivacySummary() {
  const res = await api.get('/privacy/status');
  const raw = res.data;

  if (!raw || typeof raw !== 'object') {
    return {
      signals: [],
      retention: { policy: 'unknown', days: null },
      capabilities: {},
    };
  }

  return {
    signals: Array.isArray(raw.signals) ? raw.signals : [],
    retention: {
      policy: typeof raw.retention?.policy === 'string' ? raw.retention.policy : 'unknown',
      days: typeof raw.retention?.days === 'number' ? raw.retention.days : null,
    },
    dataLocalOnly: raw.data_local_only ?? true,
    encryptionAtRest: raw.encryption_at_rest ?? false,
    telemetryEnabled: raw.telemetry_enabled ?? false,
    capabilities: raw.capabilities ?? {},
  };
}

/**
 * GET /api/privacy/audit — run a full privacy audit.
 * @returns {Promise<{ findings: Array, score: number|null, ranAt: string }>}
 */
export async function runPrivacyAudit() {
  const res = await api.get('/privacy/audit');
  const raw = res.data;

  if (!raw || typeof raw !== 'object') {
    return { findings: [], score: null, ranAt: new Date().toISOString() };
  }

  return {
    findings: Array.isArray(raw.findings) ? raw.findings : [],
    score: typeof raw.score === 'number' ? raw.score : null,
    ranAt: raw.ran_at ?? raw.ranAt ?? new Date().toISOString(),
  };
}
