/**
 * PrivacySignalCard — displays a single privacy signal with title, value,
 * and verification state.
 *
 * Verification states: 'verified', 'unverified', 'degraded', 'unknown'.
 * Never fakes a green state — unknown renders as neutral grey.
 */
import React from 'react';
import { radius } from '../../theme/tokens';

const VERIFICATION_STYLES = {
  verified: {
    border: 'border-emerald-500/30',
    bg: 'bg-emerald-500/5',
    dot: 'bg-emerald-400',
    text: 'text-emerald-300',
    label: 'Verified',
  },
  unverified: {
    border: 'border-amber-500/30',
    bg: 'bg-amber-500/5',
    dot: 'bg-amber-400',
    text: 'text-amber-300',
    label: 'Unverified',
  },
  degraded: {
    border: 'border-red-500/30',
    bg: 'bg-red-500/5',
    dot: 'bg-red-400',
    text: 'text-red-300',
    label: 'Degraded',
  },
  unknown: {
    border: 'border-slate-700',
    bg: 'bg-slate-800/40',
    dot: 'bg-slate-500',
    text: 'text-slate-400',
    label: 'Unknown',
  },
};

/**
 * @param {{
 *   title: string,
 *   value: string|number|null,
 *   verification: 'verified'|'unverified'|'degraded'|'unknown',
 *   description?: string,
 * }} props
 */
export default function PrivacySignalCard({
  title,
  value,
  verification = 'unknown',
  description = null,
}) {
  const style = VERIFICATION_STYLES[verification] || VERIFICATION_STYLES.unknown;

  return (
    <div
      className={`
        relative overflow-hidden
        ${radius.card} border ${style.border} ${style.bg}
        p-5 flex flex-col gap-2
        transition-shadow duration-300
        hover:shadow-[0_0_24px_rgba(220,38,38,0.04)]
      `}
    >
      {/* Top edge glow */}
      <div className="absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-white/[0.06] to-transparent" />

      {/* Header with verification badge */}
      <div className="flex items-center justify-between">
        <span className="text-xs font-bold tracking-widest uppercase text-slate-400">
          {title}
        </span>
        <span className={`inline-flex items-center gap-1.5 text-[10px] font-medium ${style.text}`}>
          <span className={`w-1.5 h-1.5 rounded-full ${style.dot}`} />
          {style.label}
        </span>
      </div>

      {/* Value */}
      <span className="text-lg font-bold text-slate-100 leading-tight">
        {value ?? '--'}
      </span>

      {/* Description */}
      {description && (
        <p className="text-xs text-slate-500 leading-relaxed">
          {description}
        </p>
      )}
    </div>
  );
}
