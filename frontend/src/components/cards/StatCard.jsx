import React from 'react';
import { radius } from '../../theme/tokens';

/**
 * StatCard
 * Reusable metric card for the overview grid.
 *
 * @param {{ label: string, value: string|number, delta?: string|number|null, icon?: React.ReactNode }} props
 */
export default function StatCard({ label, value, delta = null, icon = null }) {
  // Determine delta direction for colour
  let deltaColor = 'text-slate-400';
  let deltaPrefix = '';
  if (delta != null) {
    const num = Number(delta);
    if (num > 0) {
      deltaColor = 'text-emerald-400';
      deltaPrefix = '+';
    } else if (num < 0) {
      deltaColor = 'text-red-400';
      // negative sign is already in the number
    }
  }

  return (
    <div
      className={`
        relative overflow-hidden
        ${radius.card} border border-white/[0.06]
        bg-gradient-to-br from-[#0a0a0a] to-[#141414]
        p-5 flex flex-col gap-1
        transition-shadow duration-300
        hover:shadow-[0_0_24px_rgba(220,38,38,0.06)]
      `}
    >
      {/* Subtle top-edge glow */}
      <div className="absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-red-500/20 to-transparent" />

      <div className="flex items-center justify-between">
        <span className="text-xs font-medium tracking-wide uppercase text-slate-500">
          {label}
        </span>
        {icon && (
          <span className="text-slate-600 text-lg shrink-0">{icon}</span>
        )}
      </div>

      <span className="text-2xl font-bold text-slate-100 tabular-nums leading-tight">
        {value ?? '--'}
      </span>

      {delta != null && (
        <span className={`text-xs font-medium ${deltaColor}`}>
          {deltaPrefix}{delta}
        </span>
      )}
    </div>
  );
}
