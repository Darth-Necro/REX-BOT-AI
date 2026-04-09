/**
 * REX-BOT-AI Design Tokens
 * Dark tactical theme — all values are source-of-truth for the UI.
 */

export const colors = {
  bg: {
    app: '#050816',
    shell: '#0B1020',
    panel: 'rgba(10,15,31,0.78)',
    elevated: '#11192C',
  },
  border: {
    subtle: 'rgba(148,163,184,0.14)',
    signal: 'rgba(34,211,238,0.20)',
  },
  text: {
    primary: '#F8FAFC',
    secondary: '#CBD5E1',
    muted: '#64748B',
    signal: '#A5F3FC',
  },
  accent: {
    cyan: '#22D3EE',
    sky: '#38BDF8',
    fuchsia: '#D946EF',
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
  low: 'cyan',
  info: 'slate',
};

export const radius = {
  card: 'rounded-[26px]',
  panel: 'rounded-[28px]',
  pill: 'rounded-full',
  input: 'rounded-2xl',
};
