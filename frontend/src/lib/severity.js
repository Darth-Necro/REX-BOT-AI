/**
 * Severity normalization and visual tokens for REX-BOT-AI.
 *
 * The backend may report severity as strings in varying casing or as
 * numeric values.  This module normalizes to a fixed enum and provides
 * Tailwind class tokens for each level.
 */

/* ---------- normalization ---------- */

const SEVERITY_MAP = {
  critical: 'critical',
  crit: 'critical',
  high: 'high',
  medium: 'medium',
  med: 'medium',
  low: 'low',
  info: 'info',
  informational: 'info',
  none: 'info',
};

/**
 * Normalize a raw severity value to one of: critical | high | medium | low | info.
 * Returns 'info' for unrecognised or missing values.
 * @param {string|number|null} raw
 * @returns {'critical'|'high'|'medium'|'low'|'info'}
 */
export function normalizeSeverity(raw) {
  if (raw == null) return 'info';
  if (typeof raw === 'number') {
    if (raw >= 9) return 'critical';
    if (raw >= 7) return 'high';
    if (raw >= 4) return 'medium';
    if (raw >= 1) return 'low';
    return 'info';
  }
  const key = String(raw).toLowerCase().trim();
  return SEVERITY_MAP[key] || 'info';
}

/* ---------- visual tokens ---------- */

export const SEVERITY_TOKENS = {
  critical: {
    bg: 'bg-red-500/10',
    text: 'text-red-300',
    border: 'border-red-500/40',
    dot: 'bg-red-400',
    label: 'Critical',
    /** Accessible text description (not just color). */
    srLabel: 'Severity: Critical',
  },
  high: {
    bg: 'bg-orange-500/10',
    text: 'text-orange-300',
    border: 'border-orange-500/40',
    dot: 'bg-orange-400',
    label: 'High',
    srLabel: 'Severity: High',
  },
  medium: {
    bg: 'bg-amber-500/10',
    text: 'text-amber-300',
    border: 'border-amber-500/40',
    dot: 'bg-amber-400',
    label: 'Medium',
    srLabel: 'Severity: Medium',
  },
  low: {
    bg: 'bg-cyan-500/10',
    text: 'text-cyan-300',
    border: 'border-cyan-500/40',
    dot: 'bg-cyan-400',
    label: 'Low',
    srLabel: 'Severity: Low',
  },
  info: {
    bg: 'bg-slate-700/30',
    text: 'text-slate-400',
    border: 'border-slate-600/40',
    dot: 'bg-slate-500',
    label: 'Info',
    srLabel: 'Severity: Informational',
  },
};

/**
 * Get tokens for a severity value (raw or already normalized).
 * @param {string|number|null} raw
 * @returns {typeof SEVERITY_TOKENS.info}
 */
export function severityTokens(raw) {
  return SEVERITY_TOKENS[normalizeSeverity(raw)] || SEVERITY_TOKENS.info;
}

/* ---------- sort order ---------- */

const ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

/**
 * Comparator: sorts higher severity first.
 * @param {string} a  Normalized severity.
 * @param {string} b  Normalized severity.
 * @returns {number}
 */
export function compareSeverity(a, b) {
  return (ORDER[a] ?? 5) - (ORDER[b] ?? 5);
}
