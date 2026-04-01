/**
 * BasicOverviewPage — simplified defense posture for basic mode.
 *
 * Shows the essential metrics from useSystemStore without hiding
 * any degradation. If data is unknown, it says so. No fake green states.
 * Fewer cards than AdvancedOverviewPage but the same honest defaults.
 */
import React from 'react';
import useSystemStore from '../../stores/useSystemStore';

/* ---------- helpers ---------- */

function formatUptime(seconds) {
  if (!seconds || seconds <= 0) return '--';
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  if (h > 0) return `${h}h ${m}m`;
  return `${m}m`;
}

const POSTURE_MAP = {
  nominal: {
    label: 'Nominal',
    color: 'text-emerald-400',
    bg: 'bg-emerald-500/10',
    border: 'border-emerald-500/30',
    dot: 'bg-emerald-400',
  },
  elevated: {
    label: 'Elevated',
    color: 'text-amber-300',
    bg: 'bg-amber-500/10',
    border: 'border-amber-500/30',
    dot: 'bg-amber-400',
  },
  critical: {
    label: 'Critical',
    color: 'text-red-400',
    bg: 'bg-red-500/10',
    border: 'border-red-500/30',
    dot: 'bg-red-500',
  },
  unknown: {
    label: 'Unknown',
    color: 'text-slate-400',
    bg: 'bg-slate-800/60',
    border: 'border-slate-700',
    dot: 'bg-slate-500',
  },
};

/* ---------- sub-components ---------- */

function PostureBanner({ posture, status }) {
  const info = POSTURE_MAP[posture] || POSTURE_MAP.unknown;

  return (
    <div className={`rounded-[26px] border ${info.border} ${info.bg} p-6 flex items-center gap-4`}>
      <div className={`w-4 h-4 rounded-full ${info.dot} ${posture === 'unknown' ? '' : 'animate-pulse'}`} />
      <div>
        <span className={`text-lg font-bold ${info.color}`}>{info.label}</span>
        <p className="text-xs text-slate-500 mt-0.5">
          {posture === 'unknown'
            ? 'Defense posture cannot be determined -- waiting for backend data.'
            : `System is ${status}. Defense posture: ${info.label.toLowerCase()}.`}
        </p>
      </div>
    </div>
  );
}

function SimpleMetric({ label, value, isLoading }) {
  return (
    <div className="rounded-[26px] border border-white/[0.06] bg-gradient-to-br from-[#0B1020] to-[#11192C] p-5 flex flex-col gap-1">
      <span className="text-xs font-medium tracking-wide uppercase text-slate-500">
        {label}
      </span>
      <span className="text-2xl font-bold text-slate-100 tabular-nums leading-tight">
        {isLoading ? '--' : (value ?? '--')}
      </span>
    </div>
  );
}

/* ---------- main page ---------- */

export default function BasicOverviewPage() {
  const {
    bootstrapState,
    status,
    threatPosture,
    connected,
    deviceCount,
    activeThreats,
    threatsBlocked24h,
    uptimeSeconds,
  } = useSystemStore();

  const isLoading = bootstrapState === 'idle' || bootstrapState === 'loading';

  return (
    <div className="p-6 lg:p-8 max-w-3xl mx-auto space-y-6">
      {/* Header */}
      <h1 className="text-xl font-bold text-slate-100 tracking-tight">
        Defense Overview
      </h1>

      {/* Posture banner */}
      <PostureBanner posture={isLoading ? 'unknown' : threatPosture} status={status} />

      {/* Metrics grid */}
      <div className="grid grid-cols-2 gap-4">
        <SimpleMetric label="Devices" value={deviceCount} isLoading={isLoading} />
        <SimpleMetric label="Active Threats" value={activeThreats} isLoading={isLoading} />
        <SimpleMetric label="Blocked (24h)" value={threatsBlocked24h} isLoading={isLoading} />
        <SimpleMetric label="Uptime" value={formatUptime(uptimeSeconds)} isLoading={isLoading} />
      </div>

      {/* Connection warning */}
      {!isLoading && !connected && (
        <div className="rounded-xl border border-amber-500/30 bg-amber-500/5 p-4 text-sm text-amber-200">
          REX is not connected to the backend. Data shown may be stale.
        </div>
      )}

      {/* Bootstrap error */}
      {bootstrapState === 'error' && (
        <div className="rounded-xl border border-red-500/30 bg-red-500/5 p-4 text-sm text-red-300">
          Failed to reach REX backend. All values above may be unavailable.
        </div>
      )}

      {/* Honest disclaimer */}
      <p className="text-[10px] text-slate-700 text-center">
        Basic mode -- showing real system state with no hidden degradation.
      </p>
    </div>
  );
}
