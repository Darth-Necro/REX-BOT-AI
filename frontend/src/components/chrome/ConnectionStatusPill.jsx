import React from 'react';
import { colors } from '../../theme/tokens';

const STATE_MAP = {
  unknown: {
    label: 'Unknown',
    dot: 'bg-slate-500',
    ring: 'border-slate-600',
    text: 'text-slate-400',
    pulse: false,
  },
  connecting: {
    label: 'Connecting',
    dot: 'bg-amber-400',
    ring: 'border-amber-500/30',
    text: 'text-amber-300',
    pulse: true,
  },
  connected: {
    label: 'Connected',
    dot: 'bg-emerald-400',
    ring: 'border-emerald-400/30',
    text: 'text-emerald-300',
    pulse: false,
  },
  degraded: {
    label: 'Degraded',
    dot: 'bg-amber-400',
    ring: 'border-amber-400/30',
    text: 'text-amber-200',
    pulse: true,
  },
  disconnected: {
    label: 'Disconnected',
    dot: 'bg-red-500',
    ring: 'border-red-400/30',
    text: 'text-red-300',
    pulse: true,
  },
};

/**
 * ConnectionStatusPill
 * Compact pill that displays the current connection state.
 *
 * @param {{ state: 'unknown'|'connecting'|'connected'|'degraded'|'disconnected' }} props
 */
export default function ConnectionStatusPill({ state = 'unknown' }) {
  const config = STATE_MAP[state] || STATE_MAP.unknown;

  return (
    <div
      className={`
        inline-flex items-center gap-2 px-3 py-1.5
        rounded-full border backdrop-blur-sm
        bg-slate-900/60 ${config.ring}
        select-none transition-colors duration-300
      `}
      role="status"
      aria-live="polite"
      aria-label={`Connection: ${config.label}`}
    >
      <span className="relative flex h-2 w-2">
        {config.pulse && (
          <span
            className={`absolute inline-flex h-full w-full rounded-full opacity-60 animate-ping ${config.dot}`}
          />
        )}
        <span className={`relative inline-flex h-2 w-2 rounded-full ${config.dot}`} />
      </span>
      <span className={`text-xs font-medium tracking-wide ${config.text}`}>
        {config.label}
      </span>
    </div>
  );
}
