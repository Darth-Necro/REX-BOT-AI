/**
 * BasicOverviewPage -- simplified defense posture for basic mode.
 *
 * Plain language posture messages:
 *   - nominal:  "REX is watching your network"
 *   - elevated: "REX detected issues"
 *   - critical: "REX found serious threats"
 *   - unknown:  "REX is connecting..."
 *
 * Card stack layout on mobile. Recent alerts in plain language.
 * No hidden critical issues. No fake green states.
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

function timeAgo(timestamp) {
  if (!timestamp) return '';
  const diff = Date.now() - new Date(timestamp).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return 'just now';
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  return `${Math.floor(hrs / 24)}d ago`;
}

/* ---------- posture config ---------- */

const POSTURE_CONFIG = {
  nominal: {
    message: 'REX is watching your network',
    detail: 'No threats detected. All systems operating normally.',
    color: 'text-emerald-400',
    bg: 'bg-emerald-500/10',
    border: 'border-emerald-500/30',
    dot: 'bg-emerald-400',
    animate: true,
  },
  elevated: {
    message: 'REX detected issues',
    detail: 'Some threats or degraded services were found. Review the details below.',
    color: 'text-amber-300',
    bg: 'bg-amber-500/10',
    border: 'border-amber-500/30',
    dot: 'bg-amber-400',
    animate: true,
  },
  critical: {
    message: 'REX found serious threats',
    detail: 'Critical issues need your attention. Check threats and take action.',
    color: 'text-red-400',
    bg: 'bg-red-500/10',
    border: 'border-red-500/30',
    dot: 'bg-red-500',
    animate: true,
  },
  unknown: {
    message: 'REX is connecting...',
    detail: 'Waiting for data from the backend. Status cannot be determined yet.',
    color: 'text-slate-400',
    bg: 'bg-slate-800/60',
    border: 'border-slate-700',
    dot: 'bg-slate-500',
    animate: false,
  },
};

/* ---------- sub-components ---------- */

function PostureBanner({ posture }) {
  const config = POSTURE_CONFIG[posture] || POSTURE_CONFIG.unknown;

  return (
    <div
      className={`rounded-2xl sm:rounded-[26px] border ${config.border} ${config.bg} p-5 sm:p-6`}
      role="status"
      aria-label={`Network posture: ${config.message}`}
    >
      <div className="flex items-start gap-4">
        <div className={`w-4 h-4 rounded-full ${config.dot} mt-1 shrink-0 ${config.animate ? 'animate-pulse' : ''}`} />
        <div className="min-w-0">
          <p className={`text-lg sm:text-xl font-bold ${config.color} leading-tight`}>
            {config.message}
          </p>
          <p className="text-xs sm:text-sm text-slate-500 mt-1">
            {config.detail}
          </p>
        </div>
      </div>
    </div>
  );
}

function MetricCard({ label, value, isLoading }) {
  return (
    <div className="rounded-2xl sm:rounded-[26px] border border-white/[0.06] bg-gradient-to-br from-[#0B1020] to-[#11192C] p-4 sm:p-5 flex flex-col gap-1">
      <span className="text-[11px] sm:text-xs font-medium tracking-wide uppercase text-slate-500">
        {label}
      </span>
      <span className="text-xl sm:text-2xl font-bold text-slate-100 tabular-nums leading-tight">
        {isLoading ? '--' : (value ?? '--')}
      </span>
    </div>
  );
}

function RecentAlertItem({ alert }) {
  const severityColors = {
    critical: 'text-red-400',
    high: 'text-orange-400',
    medium: 'text-amber-300',
    low: 'text-cyan-300',
  };
  const color = severityColors[alert.severity] || 'text-slate-400';

  // Plain language description
  const description = alert.description || alert.message || alert.type || 'New alert';

  return (
    <div className="flex items-start gap-3 py-2.5 border-b border-white/[0.04] last:border-0">
      <span className={`w-2 h-2 rounded-full mt-1.5 shrink-0 ${
        alert.severity === 'critical' ? 'bg-red-500' :
        alert.severity === 'high' ? 'bg-orange-400' :
        alert.severity === 'medium' ? 'bg-amber-400' :
        'bg-slate-500'
      }`} />
      <div className="min-w-0 flex-1">
        <p className={`text-sm ${color} truncate`}>{description}</p>
        {alert.timestamp && (
          <p className="text-[10px] text-slate-600 mt-0.5">{timeAgo(alert.timestamp)}</p>
        )}
      </div>
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
    recentAlerts,
  } = useSystemStore();

  const isLoading = bootstrapState === 'idle' || bootstrapState === 'loading';
  const effectivePosture = isLoading ? 'unknown' : threatPosture;

  return (
    <div className="p-4 sm:p-6 lg:p-8 max-w-3xl mx-auto space-y-4 sm:space-y-6">
      {/* Header */}
      <h1 className="text-lg sm:text-xl font-bold text-slate-100 tracking-tight">
        Defense Overview
      </h1>

      {/* Posture banner -- plain language */}
      <PostureBanner posture={effectivePosture} />

      {/* Metrics -- card stack on mobile, 2-col on sm+ */}
      <div className="grid grid-cols-2 gap-3 sm:gap-4">
        <MetricCard label="Devices" value={deviceCount} isLoading={isLoading} />
        <MetricCard label="Active Threats" value={activeThreats} isLoading={isLoading} />
        <MetricCard label="Blocked (24h)" value={threatsBlocked24h} isLoading={isLoading} />
        <MetricCard label="Uptime" value={formatUptime(uptimeSeconds)} isLoading={isLoading} />
      </div>

      {/* Recent alerts in plain language */}
      {recentAlerts.length > 0 && (
        <div className="rounded-2xl sm:rounded-[26px] border border-white/[0.06] bg-gradient-to-br from-[#0B1020] to-[#11192C] p-4 sm:p-5">
          <h2 className="text-xs font-bold tracking-widest uppercase text-slate-500 mb-2">
            Recent Alerts
          </h2>
          <div>
            {recentAlerts.slice(0, 5).map((alert, i) => (
              <RecentAlertItem key={alert.id || i} alert={alert} />
            ))}
          </div>
        </div>
      )}

      {/* Connection warning */}
      {!isLoading && !connected && (
        <div
          className="rounded-xl border border-amber-500/30 bg-amber-500/5 p-4 text-sm text-amber-200"
          role="alert"
        >
          REX is not connected to the backend. Data shown may be stale.
        </div>
      )}

      {/* Bootstrap error */}
      {bootstrapState === 'error' && (
        <div
          className="rounded-xl border border-red-500/30 bg-red-500/5 p-4 text-sm text-red-300"
          role="alert"
        >
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
