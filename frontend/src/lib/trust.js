/**
 * Trust score helpers for REX-BOT-AI.
 *
 * Trust may arrive from the backend as a string label (e.g. "trusted",
 * "untrusted") or as a numeric score (0-100).  This module normalizes
 * both forms and provides Tailwind class tokens.
 */

/* ---------- normalization ---------- */

const LABEL_TO_SCORE = {
  trusted: 90,
  known: 70,
  new: 50,
  unknown: 30,
  untrusted: 10,
  blocked: 0,
};

/**
 * Normalize a trust value to a 0-100 integer score.
 * @param {string|number|null} raw
 * @returns {number}  0-100 score.  Returns -1 if truly indeterminate.
 */
export function normalizeTrust(raw) {
  if (raw == null) return -1;
  if (typeof raw === 'number') {
    if (!Number.isFinite(raw)) return -1;
    return Math.max(0, Math.min(100, Math.round(raw)));
  }
  const key = String(raw).toLowerCase().trim();
  return LABEL_TO_SCORE[key] ?? -1;
}

/**
 * Convert a numeric trust score to a human-readable tier label.
 * @param {number} score  0-100 or -1 (unknown).
 * @returns {'trusted'|'known'|'new'|'untrusted'|'blocked'|'unknown'}
 */
export function trustTier(score) {
  if (score < 0) return 'unknown';
  if (score >= 80) return 'trusted';
  if (score >= 60) return 'known';
  if (score >= 40) return 'new';
  if (score >= 15) return 'untrusted';
  return 'blocked';
}

/* ---------- visual tokens ---------- */

export const TRUST_TOKENS = {
  trusted: {
    bg: 'bg-emerald-500/10',
    text: 'text-emerald-300',
    border: 'border-emerald-500/30',
    ring: 'ring-emerald-400',
    dot: 'bg-emerald-400',
    label: 'Trusted',
  },
  known: {
    bg: 'bg-cyan-500/10',
    text: 'text-cyan-300',
    border: 'border-cyan-500/30',
    ring: 'ring-cyan-400',
    dot: 'bg-cyan-400',
    label: 'Known',
  },
  new: {
    bg: 'bg-amber-500/10',
    text: 'text-amber-300',
    border: 'border-amber-500/30',
    ring: 'ring-amber-400',
    dot: 'bg-amber-400',
    label: 'New',
  },
  untrusted: {
    bg: 'bg-orange-500/10',
    text: 'text-orange-300',
    border: 'border-orange-500/30',
    ring: 'ring-orange-400',
    dot: 'bg-orange-400',
    label: 'Untrusted',
  },
  blocked: {
    bg: 'bg-red-500/10',
    text: 'text-red-300',
    border: 'border-red-500/40',
    ring: 'ring-red-400',
    dot: 'bg-red-400',
    label: 'Blocked',
  },
  unknown: {
    bg: 'bg-slate-800/60',
    text: 'text-slate-400',
    border: 'border-slate-700',
    ring: 'ring-slate-500',
    dot: 'bg-slate-500',
    label: 'Unknown',
  },
};

/**
 * Get trust visual tokens from a raw trust value.
 * @param {string|number|null} raw
 * @returns {typeof TRUST_TOKENS.unknown}
 */
export function trustTokens(raw) {
  const score = normalizeTrust(raw);
  const tier = trustTier(score);
  return TRUST_TOKENS[tier] || TRUST_TOKENS.unknown;
}

/**
 * Tailwind stroke color class for the TrustRing SVG arc.
 * @param {string} tier  Output of trustTier().
 * @returns {string}
 */
export function trustStrokeColor(tier) {
  const map = {
    trusted: 'stroke-emerald-400',
    known: 'stroke-cyan-400',
    new: 'stroke-amber-400',
    untrusted: 'stroke-orange-400',
    blocked: 'stroke-red-400',
    unknown: 'stroke-slate-500',
  };
  return map[tier] || map.unknown;
}
