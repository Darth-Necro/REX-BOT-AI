/**
 * REX-BOT-AI Design Tokens
 * Dark red/black tactical theme — all values are source-of-truth for the UI.
 */

export const colors = {
  bg: {
    app: '#050505',
    shell: '#0a0a0a',
    panel: 'rgba(10,10,10,0.85)',
    elevated: '#141414',
  },
  border: {
    subtle: 'rgba(148,163,184,0.10)',
    signal: 'rgba(220,38,38,0.25)',
  },
  text: {
    primary: '#F8FAFC',
    secondary: '#CBD5E1',
    muted: '#64748B',
    signal: '#FCA5A5',
  },
  accent: {
    red: '#DC2626',
    darkRed: '#991B1B',
    crimson: '#B91C1C',
    danger: '#EF4444',
  },
  state: {
    unknown: {
      bg: 'bg-slate-800/60',
      text: 'text-slate-400',
      border: 'border-slate-700',
    },
    degraded: {
      bg: 'bg-amber-500/10',
      text: 'text-amber-200',
      border: 'border-amber-400/30',
    },
    healthy: {
      bg: 'bg-emerald-500/10',
      text: 'text-emerald-200',
      border: 'border-emerald-400/30',
    },
    critical: {
      bg: 'bg-red-500/10',
      text: 'text-red-200',
      border: 'border-red-500/40',
    },
    disconnected: {
      bg: 'bg-red-500/10',
      text: 'text-red-300',
      border: 'border-red-400/30',
    },
  },
};

export const severity = {
  critical: 'red',
  high: 'orange',
  medium: 'amber',
  low: 'emerald',
  info: 'slate',
};

export const radius = {
  card: 'rounded-[26px]',
  panel: 'rounded-[28px]',
  pill: 'rounded-full',
  input: 'rounded-2xl',
};
