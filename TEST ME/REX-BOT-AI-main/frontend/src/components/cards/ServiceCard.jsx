/**
 * ServiceCard — compact card showing a single service's health status.
 * Colour-coded by state: healthy/operational, degraded/loading, critical/error, unknown.
 */
import React from 'react';

const STATUS_STYLES = {
  healthy:     { bg: 'bg-emerald-500/10', text: 'text-emerald-300', border: 'border-emerald-500/30', dot: 'bg-emerald-400' },
  operational: { bg: 'bg-emerald-500/10', text: 'text-emerald-300', border: 'border-emerald-500/30', dot: 'bg-emerald-400' },
  ready:       { bg: 'bg-emerald-500/10', text: 'text-emerald-300', border: 'border-emerald-500/30', dot: 'bg-emerald-400' },
  connected:   { bg: 'bg-emerald-500/10', text: 'text-emerald-300', border: 'border-emerald-500/30', dot: 'bg-emerald-400' },
  awake:       { bg: 'bg-emerald-500/10', text: 'text-emerald-300', border: 'border-emerald-500/30', dot: 'bg-emerald-400' },

  degraded:    { bg: 'bg-amber-500/10',   text: 'text-amber-300',   border: 'border-amber-500/30',   dot: 'bg-amber-400' },
  loading:     { bg: 'bg-amber-500/10',   text: 'text-amber-300',   border: 'border-amber-500/30',   dot: 'bg-amber-400' },
  alert_sleep: { bg: 'bg-amber-500/10',   text: 'text-amber-300',   border: 'border-amber-500/30',   dot: 'bg-amber-400' },

  critical:    { bg: 'bg-red-500/10',     text: 'text-red-300',     border: 'border-red-500/30',     dot: 'bg-red-400' },
  error:       { bg: 'bg-red-500/10',     text: 'text-red-300',     border: 'border-red-500/30',     dot: 'bg-red-400' },
  disconnected:{ bg: 'bg-red-500/10',     text: 'text-red-300',     border: 'border-red-500/30',     dot: 'bg-red-400' },
  disabled:    { bg: 'bg-red-500/10',     text: 'text-red-300',     border: 'border-red-500/30',     dot: 'bg-red-400' },
  off:         { bg: 'bg-red-500/10',     text: 'text-red-300',     border: 'border-red-500/30',     dot: 'bg-red-400' },

  deep_sleep:  { bg: 'bg-slate-800/60',   text: 'text-slate-400',   border: 'border-slate-700',      dot: 'bg-slate-500' },
  unknown:     { bg: 'bg-slate-800/60',   text: 'text-slate-400',   border: 'border-slate-700',      dot: 'bg-slate-500' },
};

export default function ServiceCard({ name, status }) {
  const key = (status || 'unknown').toLowerCase();
  const style = STATUS_STYLES[key] || STATUS_STYLES.unknown;

  return (
    <div className={`${style.bg} ${style.border} border rounded-2xl p-4 flex items-center gap-3 transition-shadow hover:shadow-md`}>
      {/* Status dot */}
      <div className={`w-2.5 h-2.5 rounded-full ${style.dot} shrink-0`} />

      <div className="min-w-0 flex-1">
        <p className="text-sm font-medium text-slate-200 truncate">{name}</p>
        <p className={`text-xs font-medium ${style.text} capitalize`}>
          {status || 'unknown'}
        </p>
      </div>
    </div>
  );
}
